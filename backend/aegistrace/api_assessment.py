"""Bounded API checks for an isolated runner; the public API never invokes this worker.

Only reviewed exact operations are sent. Secrets and response content are never
included in results. A supplied transport is a trusted runner boundary, not LLM input.
"""

import hashlib
import http.client
import json
import socket
import ssl
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Literal, Protocol
from urllib.parse import urlsplit

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, SecretStr

from aegistrace.policy import Destination, ExecutionPolicy, PolicyError, authorize, verify_peer


class Operation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    method: Literal["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]
    url: str = Field(max_length=2000)
    security_alternatives: tuple[tuple[str, ...], ...] = ()


class Credential(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, hide_input_in_errors=True)
    kind: Literal["bearer", "api-key"]
    header: str = "Authorization"
    value: SecretStr = Field(repr=False)
    expires_at: AwareDatetime
    origin: str

    def request_header(self, now: datetime, origin: str) -> tuple[str, str]:
        if self.origin != origin:
            raise PolicyError("credential-origin-mismatch")
        if now >= self.expires_at:
            raise PolicyError("credential-expired")
        name = "Authorization" if self.kind == "bearer" else self.header
        if not name.isascii() or not name.replace("-", "").isalnum():
            raise PolicyError("invalid-credential-header")
        if name.lower() in {
            "host",
            "content-length",
            "transfer-encoding",
            "connection",
            "proxy-authorization",
            "cookie",
        }:
            raise PolicyError("prohibited-credential-header")
        value = self.value.get_secret_value()
        if not value or len(value) > 8192 or any(ord(c) < 33 or ord(c) > 126 for c in value):
            raise PolicyError("invalid-credential-value")
        return name, "Bearer " + value if self.kind == "bearer" else value


class Transport(Protocol):
    def __call__(self, target: Destination, method: str, headers: Mapping[str, str]) -> int: ...


def pinned_https(target: Destination, method: str, headers: Mapping[str, str]) -> int:
    """One HTTPS request to an authorized pinned IP, with hostname verification.

    No proxy environment, redirects, response bodies, cookies or secondary DNS
    resolution. The runner must separately enforce kernel egress policy.
    """
    if target.protocol != "https" or not target.pinned_addresses:
        raise PolicyError("https-required")
    raw = socket.create_connection((target.pinned_addresses[0], target.port), timeout=5)
    connection = http.client.HTTPConnection(target.host, target.port, timeout=5)
    try:
        peer = raw.getpeername()
        verify_peer(target, str(peer[0]), int(peer[1]))
        connection.sock = ssl.create_default_context().wrap_socket(raw, server_hostname=target.host)
        connection.request(method, target.path, headers=dict(headers))
        response = connection.getresponse()
        return response.status
    finally:
        connection.close()
        raw.close()


def operation_digest(operations: tuple[Operation, ...]) -> str:
    return hashlib.sha256(
        json.dumps(
            [item.model_dump(mode="json") for item in operations],
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def assess_operations(
    operations: tuple[Operation, ...],
    reviewed_digest: str,
    load_policy: Callable[[], ExecutionPolicy],
    resolve_credentials: Callable[[], Mapping[str, Credential]],
    *,
    explicitly_allowed_operations: frozenset[tuple[str, str]] = frozenset(),
    transport: Transport = pinned_https,
    resolver: Callable[[str, int], tuple[str, ...]] | None = None,
    protected_networks: tuple[str, ...] = ("127.0.0.0/8", "::1/128"),
    cancelled: Callable[[], bool] = lambda: False,
    wait: Callable[[float], None] = time.sleep,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> dict[str, object]:
    """Run sequential checks using a fresh policy/credential snapshot per operation.

    load_policy must validate current scope/approval/revocation in the runner.
    Explicit method/URL consent is required even for GET, since GET can mutate state.
    Header credentials are origin-bound by policy and never sent over plaintext HTTP.
    """
    if not 0 < len(operations) <= 200 or operation_digest(operations) != reviewed_digest:
        raise PolicyError("unreviewed-operation-plan")
    results: list[dict[str, object]] = []
    for operation in operations:
        # URL values may themselves contain tokens: refuse queries/userinfo rather
        # than copying them into the persisted coverage record.
        parts = urlsplit(operation.url)
        if parts.query or parts.fragment or parts.username or parts.password:
            raise PolicyError("credential-bearing-or-ambiguous-url")
        row: dict[str, object] = {
            "method": operation.method,
            "url": operation.url,
            "attempted": False,
            "state": "untested",
            "status_code": None,
            "authentication": "not-attempted",
            "reason": None,
        }
        results.append(row)
        if cancelled():
            row.update(state="untested", reason="cancelled")
            continue
        if "{" in operation.url or "}" in operation.url:
            row.update(state="excluded", reason="unbound-path-parameter")
            continue
        if (operation.method, operation.url) not in explicitly_allowed_operations:
            row.update(state="excluded", reason="operation-not-approved")
            continue
        try:
            policy = load_policy()
            wait(1 / policy.requests_per_second)
            # Recheck after rate-limit wait: revocation/expiry must take effect
            # before dispatch, not merely when the batch starts.
            policy = load_policy()
            if cancelled():
                row.update(reason="cancelled")
                continue
            target = authorize(
                policy,
                operation.url,
                "active-web",
                protected_networks=protected_networks,
                now=clock(),
                **({"resolver": resolver} if resolver else {}),
            )
            if target.protocol != "https":
                raise PolicyError("https-required")
            credentials = resolve_credentials() if operation.security_alternatives else {}
            headers: dict[str, str] = {}
            selected = not operation.security_alternatives
            for alternative in operation.security_alternatives:
                candidate: dict[str, str] = {}
                try:
                    for name in alternative:
                        if name not in credentials:
                            raise PolicyError("credential-unavailable")
                        header, value = credentials[name].request_header(
                            clock(), f"{parts.scheme}://{parts.netloc}"
                        )
                        if header.lower() in {key.lower() for key in candidate}:
                            raise PolicyError("conflicting-credential-headers")
                        candidate[header] = value
                except PolicyError:
                    continue
                headers, selected = candidate, True
                break
            if not selected:
                row.update(
                    state="blocked",
                    authentication="unavailable-or-expired",
                    reason="authentication-unavailable",
                )
                continue
            row["attempted"] = True
            status = transport(target, operation.method, headers)
            if not 100 <= status <= 599:
                raise ValueError("invalid HTTP status")
            auth = "not-required" if not headers else "credentials-sent-unverified"
            if status in {401, 403}:
                auth = "rejected"
            row.update(
                status_code=status,
                authentication=auth,
                state="succeeded" if 200 <= status < 300 else "failed",
                reason="redirect-not-followed" if 300 <= status < 400 else None,
            )
        except PolicyError:
            row.update(state="blocked", reason="scope-or-policy-denied")
        except Exception:
            # Transport/provider exception text can contain credential values.
            row.update(state="failed", reason="request-or-credential-provider-failed")
    attempted = sum(bool(row["attempted"]) for row in results)
    return {
        "schema_version": "1.0",
        "plan_sha256": reviewed_digest,
        "operation_count": len(results),
        "attempted_count": attempted,
        "succeeded_count": sum(row["state"] == "succeeded" for row in results),
        "operations": results,
        "coverage_state": "reviewed-operations-only",
        "limitations": [
            "HTTP success does not prove authenticated identity or security correctness",
            "Unlisted/hidden endpoints are not covered; no response content is retained",
        ],
    }

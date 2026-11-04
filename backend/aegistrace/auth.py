"""Short-lived operator-issued bearer identities; no client-supplied identity headers."""

import base64
import hashlib
import hmac
import json
import time
from typing import Literal

from fastapi import HTTPException, Request, Security
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aegistrace.settings import Settings

bearer = HTTPBearer(auto_error=False)
credentials_dependency = Security(bearer)
Role = Literal["analyst", "reviewer", "admin", "auditor", "scanner", "reporter", "planner"]


class Identity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: str = Field(min_length=1, max_length=200)
    role: Role = "analyst"
    expires: int
    purpose: Literal["identity"] = "identity"
    session_id: str | None = None
    epoch: int = 0
    principal_kind: Literal["human", "service"] = "human"


def seal(secret: str, purpose: str, payload: dict[str, object]) -> str:
    encoded = (
        base64.urlsafe_b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        )
        .decode()
        .rstrip("=")
    )
    signature = hmac.new(
        secret.encode(), f"{purpose}:{encoded}".encode(), hashlib.sha256
    ).hexdigest()
    return encoded + "." + signature


def unseal(secret: str, purpose: str, token: str) -> dict[str, object]:
    try:
        if len(token) > 4096:
            raise ValueError("token too large")
        encoded, signature = token.split(".")
        expected = hmac.new(
            secret.encode(), f"{purpose}:{encoded}".encode(), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise ValueError("invalid signature")
        value = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        if not isinstance(value, dict) or type(value.get("expires")) is not int:
            raise ValueError("invalid claims")
        if value["expires"] <= int(time.time()):
            raise ValueError("expired")
        return value
    except (ValueError, TypeError, UnicodeError) as error:
        raise ValueError("invalid or expired token") from error


def authenticate(
    config: Settings,
    credentials: HTTPAuthorizationCredentials | None,
    request: Request | None = None,
) -> Identity:
    try:
        if credentials is None or credentials.scheme.lower() != "bearer":
            raise ValueError("missing bearer")
        identity = Identity.model_validate(
            unseal(config.app_secret.get_secret_value(), "identity", credentials.credentials)
        )
        if identity.session_id is None:
            if config.environment == "production" or not config.allow_operator_tokens:
                raise ValueError("managed session required")
        else:
            if request is None:
                raise ValueError("session verification context required")
            from aegistrace.identity_service import resolve_session

            parts = request.url.path.split("/")
            from uuid import UUID

            assessment_id = UUID(parts[4]) if len(parts) > 4 and parts[3] == "assessments" else None
            with request.app.state.engine.connect() as connection:
                identity = resolve_session(
                    connection, identity, credentials.credentials, assessment_id
                )
        if request is not None:
            enforce_role(identity, request)
        return identity
    except (ValueError, ValidationError) as error:
        raise HTTPException(
            401, "Authentication required", headers={"WWW-Authenticate": "Bearer"}
        ) from error


def identity_dependency(config: Settings):  # type: ignore[no-untyped-def]
    def identity(
        request: Request,
        credentials: HTTPAuthorizationCredentials | None = credentials_dependency,
    ) -> Identity:
        return authenticate(config, credentials, request)

    return identity


def issue_identity(
    config: Settings,
    subject: str,
    role: Role = "analyst",
    ttl: int = 900,
) -> str:
    if not 1 <= ttl <= 900:
        raise ValueError("identity lifetime must be 1–900 seconds")
    identity = Identity(subject=subject, role=role, expires=int(time.time()) + ttl)
    return seal(config.app_secret.get_secret_value(), "identity", identity.model_dump())


def enforce_role(identity: Identity, request: Request) -> None:
    path = request.url.path
    if (
        (path.startswith("/api/v1/auth/") and identity.principal_kind == "human")
        or path == "/api/v1/auth/logout"
        or (path == "/api/v1/auth/password" and identity.principal_kind == "human")
    ):
        return
    mutation = request.method in {"POST", "PUT", "PATCH", "DELETE"}
    if identity.principal_kind == "service" or identity.role in {"scanner", "reporter", "planner"}:
        # No scanner collector endpoint exists yet; service credentials receive no ambient API power.
        allowed = (
            identity.role == "reporter"
            and request.method == "GET"
            and ("/findings" in path or path.endswith("/reviewed-derivative"))
        )
        allowed |= identity.role == "planner" and (
            (request.method == "GET" and "/findings" in path)
            or (request.method == "POST" and path.endswith("/plans"))
        )
        if not allowed:
            raise HTTPException(403, "Service role cannot perform this action")
    if identity.role == "auditor" and mutation and not path.endswith("/download-ticket"):
        raise HTTPException(403, "Read-only role")

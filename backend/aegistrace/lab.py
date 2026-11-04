"""Offline lab-manifest consistency checks. This module never sends target traffic."""

import hashlib
import ipaddress
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, ValidationError, model_validator

Profile = Literal["discovery", "passive-web", "active-web", "controlled-validation"]


def canonical_host(value: str) -> str:
    candidate = value.strip().lower().removesuffix(".")
    if "%" in candidate:
        raise ValueError("scoped IP literals are not supported")
    if not candidate or any(char in candidate for char in "/:@?#\\* "):
        # IPv6 literal is handled separately; no URL, userinfo or wildcard input.
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            raise ValueError("target must be a plain IP or exact hostname") from None
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        hostname = candidate.encode("idna").decode("ascii")
        label = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
        if (
            len(hostname) > 253
            or not re.fullmatch(rf"{label}(?:\.{label})*", hostname)
            or all(char.isdigit() or char == "." for char in hostname)
        ):
            raise ValueError("invalid or ambiguous hostname") from None
        return hostname


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)


class AuthorizationEvidence(StrictModel):
    source: Literal["organizer"]
    reference: str = Field(min_length=1)
    document_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    reviewed_by: str = Field(min_length=1)


class LabTarget(StrictModel):
    asset_id: str = Field(min_length=1, max_length=80)
    host: str = Field(min_length=1)
    approved_addresses: list[IPvAnyAddress] = Field(min_length=1, max_length=16)


class RateLimits(StrictModel):
    requests_per_second: int = Field(gt=0, strict=True)
    concurrent_jobs: int = Field(gt=0, le=8, strict=True)


class LabManifest(StrictModel):
    schema_version: Literal[1]
    status: Literal["pending", "approved"]
    authorization: AuthorizationEvidence | None
    valid_from: datetime
    valid_until: datetime
    lab_networks: list[str] = Field(min_length=1)
    targets: list[LabTarget] = Field(min_length=1, max_length=32)
    exclusions: list[str]
    allowed_profiles: list[Profile] = Field(min_length=1)
    rate_limits: RateLimits

    @model_validator(mode="after")
    def consistent(self) -> "LabManifest":
        if self.valid_from.tzinfo is None or self.valid_until.tzinfo is None:
            raise ValueError("authorization timestamps must include a timezone")
        if self.valid_until <= self.valid_from:
            raise ValueError("authorization validity interval is invalid")
        networks = [ipaddress.ip_network(net, strict=True) for net in self.lab_networks]
        if any(net.prefixlen == 0 for net in networks):
            raise ValueError("default-route scope is forbidden")
        hosts = [canonical_host(t.host) for t in self.targets]
        if len(set(hosts)) != len(hosts) or len({t.asset_id for t in self.targets}) != len(
            self.targets
        ):
            raise ValueError("target hosts and asset IDs must be unique")
        for target in self.targets:
            try:
                literal = ipaddress.ip_address(canonical_host(target.host))
            except ValueError:
                literal = None
            if literal is not None and literal not in target.approved_addresses:
                raise ValueError("literal target IP must match its approved addresses")
            for address in target.approved_addresses:
                if (
                    "%" in str(address)
                    or address.is_unspecified
                    or address.is_multicast
                    or address.is_link_local
                ):
                    raise ValueError(
                        "unspecified, multicast and link-local destinations are forbidden"
                    )
                if not any(address in network for network in networks):
                    raise ValueError("approved target address falls outside lab networks")
        for item in self.exclusions:
            if "/" in item:
                ipaddress.ip_network(item, strict=True)
            else:
                canonical_host(item)
        return self


class LabDecision(BaseModel):
    ready: bool
    code: str
    detail: str
    tooling: Literal["not-checked"] = "not-checked"
    live_execution_enabled: Literal[False] = False


def check_lab(
    manifest_path: Path,
    authorization_document: Path | None,
    target: str,
    profile: str,
    *,
    now: datetime | None = None,
) -> LabDecision:
    def deny(code: str, detail: str) -> LabDecision:
        return LabDecision(ready=False, code=code, detail=detail)

    if not manifest_path.is_file():
        return deny(
            "missing-manifest",
            "Organizer authorization manifest is required; no target traffic sent.",
        )
    if manifest_path.stat().st_size > 65536:
        return deny("invalid-manifest", "Manifest exceeds the 64 KiB input limit.")
    try:
        with manifest_path.open(encoding="utf-8") as source:
            content = source.read(65537)
        if len(content) > 65536:
            return deny("invalid-manifest", "Manifest exceeds the input limit.")
        for count, token in enumerate(yaml.scan(content)):
            if count >= 4096 or isinstance(
                token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken)
            ):
                return deny(
                    "invalid-manifest", "YAML aliases/anchors or excessive tokens are forbidden."
                )
        manifest = LabManifest.model_validate(yaml.safe_load(content))
    except (ValidationError, ValueError, OSError, RecursionError, yaml.YAMLError):
        return deny(
            "invalid-manifest", "Manifest fields, scope or validity are invalid; no values printed."
        )
    if manifest.status != "approved" or manifest.authorization is None:
        return deny(
            "missing-authorization",
            "Organizer approval and its reviewed source document are required.",
        )
    current = now or datetime.now(UTC)
    if current.tzinfo is None or not manifest.valid_from <= current < manifest.valid_until:
        return deny("expired-or-not-current", "Organizer permission is not currently valid.")
    if authorization_document is None or not authorization_document.is_file():
        return deny(
            "missing-authorization-document",
            "Provide the privately retained reviewed organizer document.",
        )
    if authorization_document.stat().st_size > 10485760:
        return deny(
            "invalid-authorization-document", "Authorization document exceeds the 10 MiB limit."
        )
    if (
        hashlib.sha256(authorization_document.read_bytes()).hexdigest()
        != manifest.authorization.document_sha256
    ):
        return deny(
            "authorization-document-mismatch",
            "Source document hash does not match the reviewed manifest.",
        )
    try:
        host = canonical_host(target)
    except ValueError:
        return deny("invalid-target", "Use an exact plain hostname or IP address.")
    matched = next((t for t in manifest.targets if canonical_host(t.host) == host), None)
    if matched is None:
        return deny("out-of-scope", "Target is not an exact approved target.")
    for excluded in manifest.exclusions:
        if "/" in excluded:
            network = ipaddress.ip_network(excluded)
            if any(address in network for address in matched.approved_addresses):
                return deny(
                    "excluded-target", "An exclusion takes precedence over target inclusion."
                )
        elif canonical_host(excluded) == host or any(
            str(address) == canonical_host(excluded) for address in matched.approved_addresses
        ):
            return deny("excluded-target", "An exclusion takes precedence over target inclusion.")
    if profile not in manifest.allowed_profiles:
        return deny(
            "profile-not-permitted", "Requested profile is not permitted by organizer scope."
        )
    if profile == "controlled-validation":
        return deny(
            "runtime-human-approval-required",
            "Offensive validation additionally requires the unimplemented action-bound runtime approval gate.",
        )
    return LabDecision(
        ready=True,
        code="manifest-consistent",
        detail="Offline manifest checks passed. This does not authenticate organizer identity, verify tooling/network isolation, or enable scans.",
    )

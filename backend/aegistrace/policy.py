"""Deterministic destination policy, reloaded at dispatch; no prompt is authority."""

import hashlib
import ipaddress
import json
import re
import socket
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal, Self
from urllib.parse import unquote, urljoin, urlsplit
from uuid import UUID, uuid4

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import Connection, func, select

from aegistrace.lab import Profile, canonical_host
from aegistrace.policy_schema import policies, usage
from aegistrace.repository import get_record
from aegistrace.schema_v1 import assessments, scope_versions

Resolver = Callable[[str, int], tuple[str, ...]]
FORBIDDEN_NAMES = {
    "localhost",
    "api",
    "postgres",
    "redis",
    "host.docker.internal",
    "metadata.google.internal",
}
METADATA = {"100.100.100.200", "168.63.129.16", "fd00:ec2::254"}


class PolicyError(ValueError):
    pass


def path_value(value: str) -> str:
    if not value.startswith("/") or len(value) > 2000 or any(ord(c) < 33 for c in value):
        raise PolicyError("invalid-path")
    decoded = unquote(value, errors="strict")
    if any(ord(c) < 33 for c in decoded):
        raise PolicyError("encoded-control-character")
    if "\\" in decoded or "//" in decoded or any(p in {".", ".."} for p in decoded.split("/")):
        raise PolicyError("ambiguous-path")
    if any(c in decoded for c in "%?#") or re.search(r"%(?:2f|5c|00)", value, re.I):
        raise PolicyError("ambiguous-encoding")
    return decoded


def address_value(value: str) -> str:
    if "%" in value:
        raise PolicyError("scoped-address-denied")
    address = ipaddress.ip_address(value)
    if (
        getattr(address, "ipv4_mapped", None) is not None
        or address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_multicast
        or str(address) in METADATA
    ):
        raise PolicyError("protected-address")
    return str(address)


class TargetRule(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    host: str
    protocol: Literal["http", "https", "tcp", "udp"]
    port: int = Field(ge=1, le=65535, strict=True)
    path_prefix: str = "/"
    pinned_addresses: tuple[str, ...] = Field(min_length=1, max_length=16)

    @field_validator("host")
    @classmethod
    def host_value(cls, value: str) -> str:
        host = canonical_host(value)
        if host in FORBIDDEN_NAMES or host.startswith("0x") or any(ord(c) < 33 for c in value):
            raise ValueError("protected or ambiguous host")
        return host

    @field_validator("path_prefix")
    @classmethod
    def path(cls, value: str) -> str:
        return path_value(value)

    @field_validator("pinned_addresses")
    @classmethod
    def addresses(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({address_value(value) for value in values}))

    @model_validator(mode="after")
    def literal_matches(self) -> Self:
        try:
            literal = str(ipaddress.ip_address(self.host))
        except ValueError:
            literal = None
        if literal is not None and self.pinned_addresses != (literal,):
            raise ValueError("literal host must match its one pinned address")
        if self.protocol in {"tcp", "udp"} and self.path_prefix != "/":
            raise ValueError("transport targets do not have URL paths")
        return self


class ExecutionPolicy(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1.0"] = "1.0"
    id: UUID = Field(default_factory=uuid4)
    assessment_id: UUID
    scope_id: UUID
    scope_revision: int = Field(ge=1, le=2147483647)
    context: Literal["general", "hackathon"]
    authorization_source: Literal["asset-owner", "organizer"]
    authorization_reference: str = Field(min_length=1, max_length=500)
    authorization_document_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    reviewed_by: str = Field(min_length=1, max_length=200)
    valid_from: AwareDatetime
    valid_until: AwareDatetime
    targets: tuple[TargetRule, ...] = Field(min_length=1, max_length=200)
    allowed_networks: tuple[str, ...] = Field(min_length=1, max_length=100)
    exclusions: tuple[str, ...] = Field(default=(), max_length=200)
    allowed_profiles: tuple[Profile, ...] = Field(min_length=1)
    requests_per_second: int = Field(ge=1, le=100, strict=True)
    concurrent_jobs: int = Field(ge=1, le=8, strict=True)

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if self.valid_until <= self.valid_from:
            raise ValueError("invalid authorization interval")
        if self.context == "hackathon" and self.authorization_source != "organizer":
            raise ValueError("hackathon context requires organizer authority")
        networks = [ipaddress.ip_network(value, strict=True) for value in self.allowed_networks]
        if any(n.prefixlen == 0 for n in networks):
            raise ValueError("default-route authorization is forbidden")
        for target in self.targets:
            if any(
                not any(ipaddress.ip_address(address) in n for n in networks)
                for address in target.pinned_addresses
            ):
                raise ValueError("target pins must be inside explicitly authorized networks")
        for exclusion in self.exclusions:
            if "://" in exclusion:
                destination(exclusion)
            elif "/" in exclusion:
                ipaddress.ip_network(exclusion, strict=True)
            else:
                canonical_host(exclusion)
        return self


class Destination(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    protocol: Literal["http", "https", "tcp", "udp"]
    host: str
    port: int
    path: str
    pinned_addresses: tuple[str, ...] = ()


def destination(url: str) -> Destination:
    if len(url) > 2500 or any(ord(c) < 33 for c in url) or "\\" in url:
        raise PolicyError("invalid-destination")
    parsed = urlsplit(url)
    if (
        parsed.scheme not in {"http", "https", "tcp", "udp"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.query
        or "%" in parsed.netloc
    ):
        raise PolicyError("ambiguous-destination")
    host = TargetRule.host_value(parsed.hostname)
    try:
        port = parsed.port
        if port is None:
            port = {"http": 80, "https": 443}.get(parsed.scheme)
    except ValueError as error:
        raise PolicyError("invalid-port") from error
    if port is None or not 1 <= port <= 65535:
        raise PolicyError("explicit-transport-port-required")
    return Destination.model_validate(
        dict(protocol=parsed.scheme, host=host, port=port, path=path_value(parsed.path or "/"))
    )


def dns_addresses(host: str, port: int) -> tuple[str, ...]:
    try:
        return (str(ipaddress.ip_address(host)),)
    except ValueError:
        return tuple(
            sorted(
                {str(row[4][0]) for row in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)}
            )
        )


def excluded(value: Destination, pins: tuple[str, ...], exclusions: tuple[str, ...]) -> bool:
    for item in exclusions:
        if "://" in item:
            rule = destination(item)
            if (value.host, value.protocol, value.port) == (
                rule.host,
                rule.protocol,
                rule.port,
            ) and (
                value.path == rule.path.rstrip("/")
                or value.path.startswith(rule.path.rstrip("/") + "/")
            ):
                return True
        elif "/" in item:
            network = ipaddress.ip_network(item, strict=True)
            if any(ipaddress.ip_address(pin) in network for pin in pins):
                return True
        elif canonical_host(item) == value.host or canonical_host(item) in pins:
            return True
    return False


def authorize(
    policy: ExecutionPolicy,
    url: str,
    profile: Profile,
    resolver: Resolver = dns_addresses,
    protected_networks: tuple[str, ...] = (),
    now: datetime | None = None,
) -> Destination:
    current = now or datetime.now(UTC)
    if (
        not policy.valid_from <= current < policy.valid_until
        or profile not in policy.allowed_profiles
    ):
        raise PolicyError("expired-or-unpermitted-profile")
    value = destination(url)
    rules = [
        rule
        for rule in policy.targets
        if (rule.host, rule.protocol, rule.port) == (value.host, value.protocol, value.port)
        and (
            value.path == rule.path_prefix.rstrip("/")
            or value.path.startswith(rule.path_prefix.rstrip("/") + "/")
        )
    ]
    if not rules:
        raise PolicyError("out-of-scope-destination")
    pins = tuple(sorted({address_value(pin) for pin in resolver(value.host, value.port)}))
    if not pins or not any(pins == rule.pinned_addresses for rule in rules):
        raise PolicyError("dns-pins-changed")
    if any(
        ipaddress.ip_address(pin) in ipaddress.ip_network(network, strict=True)
        for pin in pins
        for network in protected_networks
    ):
        raise PolicyError("control-plane-destination")
    if excluded(value, pins, policy.exclusions):
        raise PolicyError("excluded-destination")
    return value.model_copy(update={"pinned_addresses": pins})


def authorize_redirect(
    policy: ExecutionPolicy,
    current_url: str,
    location: str,
    profile: Profile,
    resolver: Resolver = dns_addresses,
    protected_networks: tuple[str, ...] = (),
    hop: int = 1,
) -> Destination:
    if not 1 <= hop <= 3:
        raise PolicyError("redirect-limit")
    return authorize(policy, urljoin(current_url, location), profile, resolver, protected_networks)


def verify_peer(authorized: Destination, actual_ip: str, actual_port: int) -> None:
    if (
        address_value(actual_ip) not in authorized.pinned_addresses
        or actual_port != authorized.port
    ):
        raise PolicyError("connected-peer-mismatch")


def policy_digest(policy: ExecutionPolicy) -> str:
    return hashlib.sha256(
        json.dumps(policy.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def load_policy(connection: Connection, assessment_id: UUID, policy_id: UUID) -> ExecutionPolicy:
    connection.execute(
        select(assessments.c.id).where(assessments.c.id == str(assessment_id)).with_for_update()
    ).first()
    payload = connection.execute(
        select(policies.c.payload).where(
            policies.c.id == str(policy_id), policies.c.assessment_id == str(assessment_id)
        )
    ).scalar_one_or_none()
    if payload is None:
        raise PolicyError("reviewed-policy-required")
    policy = ExecutionPolicy.model_validate(payload)
    scope = get_record(connection, "scope_versions", assessment_id, policy.scope_id)
    latest = connection.execute(
        select(func.max(scope_versions.c.revision)).where(
            scope_versions.c.assessment_id == str(assessment_id)
        )
    ).scalar()
    if (
        scope["mode"] != "live-request"
        or latest != policy.scope_revision
        or scope["revision"] != policy.scope_revision
    ):
        raise PolicyError("stale-or-import-only-scope")
    return policy


def reserve_policy(
    connection: Connection, policy: ExecutionPolicy, now: datetime | None = None
) -> None:
    current = (now or datetime.now(UTC)).timestamp()
    connection.execute(
        usage.update().where(usage.c.policy_id == str(policy.id)).values(requests=usage.c.requests)
    )
    row = (
        connection.execute(
            select(usage).where(usage.c.policy_id == str(policy.id)).with_for_update()
        )
        .mappings()
        .one()
    )
    window = row["window_start"]
    requests = row["requests"]
    if current - window >= 1:
        window, requests = current, 0
    if (
        current < window
        or requests >= policy.requests_per_second
        or row["in_flight"] >= policy.concurrent_jobs
    ):
        raise PolicyError("rate-or-concurrency-limit")
    connection.execute(
        usage.update()
        .where(usage.c.policy_id == str(policy.id))
        .values(window_start=window, requests=requests + 1, in_flight=row["in_flight"] + 1)
    )


def release_policy(connection: Connection, policy_id: UUID) -> None:
    result = connection.execute(
        usage.update()
        .where(usage.c.policy_id == str(policy_id), usage.c.in_flight > 0)
        .values(in_flight=usage.c.in_flight - 1)
        .returning(usage.c.policy_id)
    ).first()
    if result is None:
        raise PolicyError("no-reservation-to-release")

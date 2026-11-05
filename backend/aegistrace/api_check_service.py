"""Persisted API-check plans, human consent and encrypted assessment credentials."""

import json
import secrets
import time
from datetime import UTC, datetime
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Connection, select

from aegistrace.api_assessment import Credential, Operation, operation_digest
from aegistrace.api_check_schema import api_checks, api_secrets
from aegistrace.approvals import action_digest, reviewer_current
from aegistrace.auth import Identity
from aegistrace.control import require_running
from aegistrace.normalization_schema import normalizations
from aegistrace.platform_api import record_request
from aegistrace.policy import (
    PolicyError,
    Resolver,
    authorize,
    dns_addresses,
    load_policy,
    policy_digest,
)
from aegistrace.repository import require_access
from aegistrace.schema_v1 import assessments
from aegistrace.settings import Settings


class CheckCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    normalization_id: UUID
    policy_id: UUID
    selected_indices: tuple[int, ...] = Field(min_length=1, max_length=200)
    credential_ids: dict[str, UUID] = Field(default_factory=dict, max_length=20)
    max_runtime_seconds: int = Field(default=60, ge=1, le=300, strict=True)


class CheckDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    decision: Literal["approve", "deny", "cancel"]


def human(actor: Identity, reviewer: bool = False) -> None:
    roles = {"reviewer", "admin"} if reviewer else {"analyst", "reviewer", "admin"}
    if actor.principal_kind != "human" or actor.role not in roles:
        raise PolicyError("human operator required")


def lock_assessment(connection: Connection, assessment_id: UUID) -> None:
    connection.execute(
        assessments.update()
        .where(assessments.c.id == str(assessment_id))
        .values(owner_id=assessments.c.owner_id)
    )


def secret_aad(assessment_id: UUID, secret_id: UUID, origin: str, expires: float) -> bytes:
    return json.dumps(
        [str(assessment_id), str(secret_id), origin, expires], separators=(",", ":")
    ).encode()


def key(config: Settings) -> bytes:
    if config.evidence_key is None:
        raise PolicyError("encrypted secret storage is not configured")
    return bytes.fromhex(config.evidence_key.get_secret_value())


def store_secret(
    connection: Connection, config: Settings, assessment_id: UUID, body: Credential, actor: Identity
) -> dict[str, Any]:
    require_access(connection, assessment_id, actor.subject)
    human(actor)
    parts = urlsplit(body.origin)
    if (
        parts.scheme != "https"
        or not parts.hostname
        or parts.path not in {"", "/"}
        or parts.query
        or parts.fragment
        or parts.username
    ):
        raise PolicyError("exact HTTPS credential origin required")
    body.request_header(datetime.now(UTC), body.origin)
    secret_id = uuid4()
    nonce = secrets.token_bytes(12)
    expires = body.expires_at.timestamp()
    plaintext = body.model_dump(mode="json") | {"value": body.value.get_secret_value()}
    ciphertext = AESGCM(key(config)).encrypt(
        nonce,
        json.dumps(plaintext).encode(),
        secret_aad(assessment_id, secret_id, body.origin, expires),
    )
    connection.execute(
        api_secrets.insert().values(
            id=str(secret_id),
            assessment_id=str(assessment_id),
            origin=body.origin,
            expires_at=expires,
            revoked=False,
            key_id=config.evidence_key_id,
            nonce=nonce,
            ciphertext=ciphertext,
        )
    )
    result = {
        "id": str(secret_id),
        "origin": body.origin,
        "expires_at": body.expires_at.isoformat(),
        "revoked": False,
    }
    record_request(connection, assessment_id, actor, "api-credential.created", secret_id, result)
    return result


def read_secret(
    connection: Connection, config: Settings, assessment_id: UUID, secret_id: UUID
) -> Credential:
    row = (
        connection.execute(
            select(api_secrets).where(
                api_secrets.c.id == str(secret_id),
                api_secrets.c.assessment_id == str(assessment_id),
            )
        )
        .mappings()
        .one_or_none()
    )
    if (
        row is None
        or row["revoked"]
        or row["expires_at"] <= time.time()
        or row["key_id"] != config.evidence_key_id
    ):
        raise PolicyError("credential unavailable")
    raw = AESGCM(key(config)).decrypt(
        row["nonce"],
        row["ciphertext"],
        secret_aad(assessment_id, secret_id, row["origin"], row["expires_at"]),
    )
    return Credential.model_validate_json(raw)


def revoke_secret(
    connection: Connection, assessment_id: UUID, secret_id: UUID, actor: Identity
) -> dict[str, Any]:
    require_access(connection, assessment_id, actor.subject)
    human(actor)
    changed = connection.execute(
        api_secrets.update()
        .where(
            api_secrets.c.id == str(secret_id), api_secrets.c.assessment_id == str(assessment_id)
        )
        .values(revoked=True)
    ).rowcount
    if not changed:
        raise LookupError("credential not found")
    result = {"id": str(secret_id), "revoked": True}
    record_request(connection, assessment_id, actor, "api-credential.revoked", secret_id, result)
    return result


def check_row(connection: Connection, assessment_id: UUID, check_id: UUID) -> dict[str, Any]:
    row = (
        connection.execute(
            select(api_checks).where(
                api_checks.c.id == str(check_id), api_checks.c.assessment_id == str(assessment_id)
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise LookupError("API check not found")
    return dict(row)


def view(row: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": row["id"],
        "assessment_id": row["assessment_id"],
        "state": row["state"],
        "plan": row["payload"],
        "result": row["result"],
    }


def create_check(
    connection: Connection,
    config: Settings,
    assessment_id: UUID,
    body: CheckCreate,
    actor: Identity,
    resolver: Resolver = dns_addresses,
) -> dict[str, Any]:
    require_access(connection, assessment_id, actor.subject)
    human(actor)
    key(config)
    lock_assessment(connection, assessment_id)
    control = require_running(connection, assessment_id)
    policy = load_policy(connection, assessment_id, body.policy_id)
    source = connection.execute(
        select(normalizations.c.payload).where(
            normalizations.c.id == str(body.normalization_id),
            normalizations.c.assessment_id == str(assessment_id),
        )
    ).scalar_one_or_none()
    if (
        source is None
        or source.get("source_kind") != "api-definition"
        or source.get("state") != "normalized"
    ):
        raise PolicyError("normalized API definition required")
    source_operations = source["operations"]
    if len(set(body.selected_indices)) != len(body.selected_indices) or any(
        type(i) is not int or not 0 <= i < len(source_operations) for i in body.selected_indices
    ):
        raise PolicyError("invalid selected operation indices")
    operations = []
    for item in source_operations:
        if "url" not in item or "security_alternatives" not in item:
            raise PolicyError("reimport definition with current parser")
        operations.append(
            Operation(
                method=item["method"],
                url=item["url"],
                security_alternatives=tuple(tuple(alt) for alt in item["security_alternatives"]),
            )
        )
    for index in body.selected_indices:
        op = operations[index]
        authorize(policy, op.url, "active-web", resolver, config.control_plane_networks)
        if urlsplit(op.url).scheme != "https" or "{" in op.url or "}" in op.url:
            raise PolicyError("concrete HTTPS operation required")
    definitions = source.get("security_scheme_definitions", {})
    for name, credential_id in body.credential_ids.items():
        credential = read_secret(connection, config, assessment_id, credential_id)
        scheme = definitions.get(name, {})
        if not (
            credential.kind == "bearer"
            and scheme.get("type") == "http"
            and scheme.get("scheme", "").lower() == "bearer"
            or credential.kind == "api-key"
            and scheme.get("type") == "apiKey"
            and scheme.get("in") == "header"
            and scheme.get("name", "").lower() == credential.header.lower()
        ):
            raise PolicyError("credential does not match a supported definition scheme")
    plan = {
        "source_normalization_id": str(body.normalization_id),
        "source_evidence_id": source["evidence_id"],
        "source_sha256": source["source_sha256"],
        "endpoint_ids": [item["endpoint_id"] for item in source_operations],
        "policy_id": str(body.policy_id),
        "policy_digest": policy_digest(policy),
        "epoch": control["epoch"],
        "operations": [op.model_dump(mode="json") for op in operations],
        "operation_digest": operation_digest(tuple(operations)),
        "selected_indices": list(body.selected_indices),
        "credential_ids": {name: str(value) for name, value in body.credential_ids.items()},
        "max_runtime_seconds": body.max_runtime_seconds,
        "valid_until": min(policy.valid_until.timestamp(), time.time() + 300),
        "created_by": actor.subject,
    }
    plan["digest"] = action_digest(plan)
    check_id = uuid4()
    connection.execute(
        api_checks.insert().values(
            id=str(check_id),
            assessment_id=str(assessment_id),
            state="pending-review",
            payload=plan,
            result=None,
        )
    )
    record_request(
        connection,
        assessment_id,
        actor,
        "api-check.requested",
        check_id,
        {"digest": plan["digest"], "source_normalization_id": str(body.normalization_id)},
    )
    return view(check_row(connection, assessment_id, check_id))


def verify_plan(plan: dict[str, Any]) -> None:
    unsigned = {
        name: value
        for name, value in plan.items()
        if name
        not in {
            "digest",
            "reviewer",
            "reviewer_session",
            "reviewer_epoch",
            "started_at",
            "deadline",
            "worker_id",
            "reservation",
        }
    }
    if action_digest(unsigned) != plan["digest"]:
        raise PolicyError("API check plan changed")


def decide_check(
    connection: Connection,
    config: Settings,
    assessment_id: UUID,
    check_id: UUID,
    body: CheckDecision,
    actor: Identity,
) -> dict[str, Any]:
    require_access(connection, assessment_id, actor.subject)
    human(actor, reviewer=body.decision != "cancel")
    lock_assessment(connection, assessment_id)
    row = check_row(connection, assessment_id, check_id)
    plan = dict(row["payload"])
    verify_plan(plan)
    if body.digest != plan["digest"]:
        raise PolicyError("reviewed digest mismatch")
    if body.decision == "cancel":
        if row["state"] in {"pending-review", "queued", "running"}:
            state = "cancel-requested" if row["state"] == "running" else "cancelled"
        else:
            raise PolicyError("API check is terminal")
    else:
        if row["state"] != "pending-review":
            raise PolicyError("single-use review already decided")
        policy = load_policy(connection, assessment_id, UUID(plan["policy_id"]))
        control = require_running(connection, assessment_id)
        if (
            plan["valid_until"] <= time.time()
            or policy_digest(policy) != plan["policy_digest"]
            or control["epoch"] != plan["epoch"]
        ):
            raise PolicyError("expired or changed authorization")
        state = "queued" if body.decision == "approve" else "denied"
        plan.update(
            reviewer=actor.subject, reviewer_session=actor.session_id, reviewer_epoch=actor.epoch
        )
    connection.execute(
        api_checks.update()
        .where(api_checks.c.id == str(check_id))
        .values(state=state, payload=plan)
    )
    record_request(
        connection, assessment_id, actor, "api-check." + state, check_id, {"digest": body.digest}
    )
    return view(check_row(connection, assessment_id, check_id))


def check_authority(
    connection: Connection, config: Settings, assessment_id: UUID, row: dict[str, Any]
) -> Any:
    plan = row["payload"]
    verify_plan(plan)
    control = require_running(connection, assessment_id)
    if (
        row["state"] not in {"queued", "running"}
        or control["epoch"] != plan["epoch"]
        or plan["valid_until"] <= time.time()
    ):
        raise PolicyError("check revoked or expired")
    if not reviewer_current(connection, {**plan, "assessment_id": str(assessment_id)}, config):
        raise PolicyError("reviewer no longer authorized")
    policy = load_policy(connection, assessment_id, UUID(plan["policy_id"]))
    if policy_digest(policy) != plan["policy_digest"]:
        raise PolicyError("policy changed after review")
    return policy

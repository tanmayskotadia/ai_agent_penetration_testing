"""Persisted human authority, immutable action digests and atomic single-use claims."""

import hashlib
import json
import time
from datetime import UTC, datetime, timedelta
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, StrictInt
from sqlalchemy import Connection, select

from aegistrace.approval_schema import claims, grants
from aegistrace.audit import AuditEvent, append_event, request_context
from aegistrace.auth import Identity
from aegistrace.domain import ToolName
from aegistrace.identity_schema import members, principals, sessions
from aegistrace.lab import Profile
from aegistrace.platform_api import resource
from aegistrace.policy import (
    PolicyError,
    Resolver,
    authorize,
    dns_addresses,
    load_policy,
    policy_digest,
    reserve_policy,
)
from aegistrace.repository import get_record, require_access
from aegistrace.scan_profiles import profile_digest, validate_profile_action
from aegistrace.schema_v1 import assessments
from aegistrace.settings import Settings


class ActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1.0"] = "1.0"
    policy_id: UUID
    plan_id: UUID
    plan_revision: int = Field(ge=1, le=2147483647)
    tool: ToolName
    template: Literal["nmap.connect.v1", "zap.passive.v1", "zap.active.v1", "metasploit.disabled"]
    profile: Profile
    destination_url: str = Field(min_length=1, max_length=2500)
    parameters: dict[Literal["timeout_seconds", "max_redirects"], StrictInt] = Field(
        default_factory=dict, max_length=2
    )
    expected_impact: str = Field(min_length=1, max_length=1000)
    evidence_ids: tuple[UUID, ...] = Field(default=(), max_length=50)
    rollback_instructions: str = Field(min_length=1, max_length=2000)
    max_runtime_seconds: int = Field(ge=1, le=300, strict=True)


class ApprovalView(BaseModel):
    id: UUID
    assessment_id: UUID
    action: ActionRequest
    action_digest: str
    parameter_hash: str
    scope_id: UUID
    scope_revision: int
    policy_digest: str
    profile_digest: str | None = None
    profile_current: bool = False
    valid_until: str
    created_by: str
    created_at: str
    state: Literal["pending-review", "approved", "denied", "revoked", "consumed"]
    reviewer: str | None
    expired: bool
    allowed_decisions: list[Literal["approve", "deny"]]
    execution_enabled: Literal[False] = False


def action_digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def verify_snapshot(row: Any, check_profile: bool = True) -> None:
    snapshot = {
        key: value
        for key, value in row["payload"].items()
        if key not in {"id", "created_by", "created_at"}
    }
    if (
        action_digest(snapshot) != row["action_digest"]
        or action_digest(snapshot["action"]["parameters"]) != snapshot["parameter_hash"]
    ):
        raise PolicyError("reviewed action integrity mismatch")
    if check_profile and row["payload"].get("profile_digest") != profile_digest(
        row["payload"]["action"]["profile"]
    ):
        raise PolicyError("impact profile changed; new human review required")


def audit(
    connection: Connection,
    assessment_id: UUID,
    actor: Identity,
    action: str,
    approval_id: UUID,
    digest: str,
    outcome: Literal["requested", "accepted", "denied", "completed"],
) -> None:
    context = request_context.get() or (uuid4(), uuid4())
    append_event(
        connection,
        AuditEvent(
            assessment_id=assessment_id,
            actor_id=actor.subject,
            actor_kind="human" if actor.principal_kind == "human" else "service",
            request_id=context[0],
            correlation_id=context[1],
            action=action,
            resource_id=approval_id,
            action_digest=digest,
            outcome=outcome,
        ),
    )


def validate_action(
    connection: Connection,
    assessment_id: UUID,
    body: ActionRequest,
    resolver: Resolver = dns_addresses,
) -> dict[str, Any]:
    policy = load_policy(connection, assessment_id, body.policy_id)
    plan = resource(connection, assessment_id, "plans", body.plan_id)
    if (
        plan["revision"] != body.plan_revision
        or plan["request"]["scope_id"] != str(policy.scope_id)
        or plan["request"]["scope_revision"] != policy.scope_revision
    ):
        raise PolicyError("stale plan/scope")
    validate_profile_action(
        body.template,
        body.tool,
        body.profile,
        {str(k): v for k, v in body.parameters.items()},
        body.max_runtime_seconds,
    )
    authorize(policy, body.destination_url, body.profile, resolver)
    for evidence_id in body.evidence_ids:
        get_record(connection, "evidence_references", assessment_id, evidence_id)
    return {
        "action": body.model_dump(mode="json"),
        "assessment_id": str(assessment_id),
        "scope_id": str(policy.scope_id),
        "scope_revision": policy.scope_revision,
        "policy_digest": policy_digest(policy),
        "profile_digest": profile_digest(body.profile),
        "parameter_hash": action_digest(
            {str(key): value for key, value in body.parameters.items()}
        ),
        "valid_until": min(
            policy.valid_until, datetime.now(UTC) + timedelta(minutes=5)
        ).isoformat(),
    }


def request_approval(
    connection: Connection,
    assessment_id: UUID,
    body: ActionRequest,
    actor: Identity,
    resolver: Resolver = dns_addresses,
) -> dict[str, Any]:
    from aegistrace.control import require_running

    require_running(connection, assessment_id)
    require_access(connection, assessment_id, actor.subject)
    if actor.principal_kind != "human" or actor.role not in {"analyst", "reviewer", "admin"}:
        raise PolicyError("human action request required")
    value = validate_action(connection, assessment_id, body, resolver)
    require_running(connection, assessment_id)
    approval_id = uuid4()
    digest = action_digest(value)
    payload = value | {
        "id": str(approval_id),
        "created_by": actor.subject,
        "created_at": datetime.now(UTC).isoformat(),
    }
    connection.execute(
        grants.insert().values(
            id=str(approval_id),
            assessment_id=str(assessment_id),
            policy_id=str(body.policy_id),
            state="pending-review",
            action_digest=digest,
            payload=payload,
        )
    )
    audit(connection, assessment_id, actor, "approval.requested", approval_id, digest, "requested")
    return view_approval(connection, assessment_id, approval_id, actor)


def view_approval(
    connection: Connection, assessment_id: UUID, approval_id: UUID, actor: Identity
) -> dict[str, Any]:
    require_access(connection, assessment_id, actor.subject)
    row = (
        connection.execute(
            select(grants).where(
                grants.c.id == str(approval_id), grants.c.assessment_id == str(assessment_id)
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise LookupError("approval not found")
    expired = datetime.fromisoformat(row["payload"]["valid_until"]) <= datetime.now(UTC)
    profile_current = row["payload"].get("profile_digest") == profile_digest(
        row["payload"]["action"]["profile"]
    )
    allowed = (
        (["approve", "deny"] if profile_current else ["deny"])
        if not expired
        and row["state"] == "pending-review"
        and actor.principal_kind == "human"
        and actor.role in {"reviewer", "admin"}
        else []
    )
    return dict(row["payload"]) | {
        "state": row["state"],
        "action_digest": row["action_digest"],
        "reviewer": row["reviewer"],
        "expired": expired,
        "allowed_decisions": allowed,
        "execution_enabled": False,
        "profile_current": profile_current,
    }


def decide(
    connection: Connection,
    assessment_id: UUID,
    approval_id: UUID,
    decision: Literal["approve", "deny", "revoke"],
    expected_digest: str,
    actor: Identity,
    resolver: Resolver = dns_addresses,
) -> dict[str, Any]:
    connection.execute(
        assessments.update()
        .where(assessments.c.id == str(assessment_id))
        .values(owner_id=assessments.c.owner_id)
    )
    require_access(connection, assessment_id, actor.subject)
    if actor.principal_kind != "human" or actor.role not in {"reviewer", "admin"}:
        raise PolicyError("human reviewer role required")
    connection.execute(
        grants.update()
        .where(grants.c.id == str(approval_id), grants.c.assessment_id == str(assessment_id))
        .values(state=grants.c.state)
    )
    row = (
        connection.execute(
            select(grants)
            .where(grants.c.id == str(approval_id), grants.c.assessment_id == str(assessment_id))
            .with_for_update()
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise LookupError("approval not found")
    verify_snapshot(row, check_profile=decision == "approve")
    if row["action_digest"] != expected_digest:
        raise PolicyError("reviewed action changed")
    allowed = {
        "approve": {"pending-review"},
        "deny": {"pending-review"},
        "revoke": {"pending-review", "approved"},
    }
    if row["state"] not in allowed[decision]:
        raise PolicyError("approval is no longer reviewable")
    if decision == "approve":
        from aegistrace.control import require_running

        require_running(connection, assessment_id)
        if datetime.fromisoformat(row["payload"]["valid_until"]) <= datetime.now(UTC):
            raise PolicyError("approval expired")
        body = ActionRequest.model_validate(row["payload"]["action"])
        checked = validate_action(connection, assessment_id, body, resolver)
        if (
            checked["policy_digest"] != row["payload"]["policy_digest"]
            or body.template == "metasploit.disabled"
        ):
            raise PolicyError("changed policy or unsupported validation module")
    state = {"approve": "approved", "deny": "denied", "revoke": "revoked"}[decision]
    connection.execute(
        grants.update()
        .where(grants.c.id == str(approval_id))
        .values(
            state=state,
            reviewer=actor.subject,
            reviewer_epoch=actor.epoch,
            reviewer_session=actor.session_id,
        )
    )
    audit(
        connection,
        assessment_id,
        actor,
        "approval." + state,
        approval_id,
        expected_digest,
        "denied" if decision != "approve" else "accepted",
    )
    return view_approval(connection, assessment_id, approval_id, actor)


def reviewer_current(connection: Connection, row: Any, config: Settings) -> bool:
    principal = (
        connection.execute(select(principals).where(principals.c.id == row["reviewer"]))
        .mappings()
        .one_or_none()
    )
    if principal is None:
        return (
            config.environment != "production"
            and config.allow_operator_tokens
            and row["reviewer_session"] is None
        )
    membership = (
        connection.execute(
            select(members).where(
                members.c.subject == row["reviewer"],
                members.c.assessment_id == row["assessment_id"],
                members.c.active.is_(True),
            )
        )
        .mappings()
        .one_or_none()
    )
    session = (
        connection.execute(select(sessions).where(sessions.c.id == row["reviewer_session"]))
        .mappings()
        .one_or_none()
    )
    return bool(
        principal["active"]
        and principal["kind"] == "human"
        and principal["epoch"] == row["reviewer_epoch"]
        and membership
        and membership["role"] in {"reviewer", "admin"}
        and session
        and not session["revoked"]
        and session["expires"] > time.time()
    )


def consume(
    connection: Connection,
    config: Settings,
    assessment_id: UUID,
    approval_id: UUID,
    expected_digest: str,
    resolver: Resolver = dns_addresses,
) -> dict[str, Any]:
    from aegistrace.control import require_running

    require_running(connection, assessment_id)
    connection.execute(
        assessments.update()
        .where(assessments.c.id == str(assessment_id))
        .values(owner_id=assessments.c.owner_id)
    )
    # No public endpoint. Control dispatch reloads this persisted human decision.
    require_running(connection, assessment_id)
    connection.execute(
        grants.update()
        .where(grants.c.id == str(approval_id), grants.c.assessment_id == str(assessment_id))
        .values(state=grants.c.state)
    )
    row = (
        connection.execute(
            select(grants)
            .where(grants.c.id == str(approval_id), grants.c.assessment_id == str(assessment_id))
            .with_for_update()
        )
        .mappings()
        .one_or_none()
    )
    if (
        row is None
        or row["state"] != "approved"
        or row["action_digest"] != expected_digest
        or not reviewer_current(connection, row, config)
    ):
        raise PolicyError("approval denied, revoked, consumed or reviewer invalid")
    payload = row["payload"]
    verify_snapshot(row)
    if datetime.fromisoformat(payload["valid_until"]) <= datetime.now(UTC):
        raise PolicyError("approval expired")
    body = ActionRequest.model_validate(payload["action"])
    checked = validate_action(connection, assessment_id, body, resolver)
    if (
        checked["policy_digest"] != payload["policy_digest"]
        or body.template == "metasploit.disabled"
    ):
        raise PolicyError("stale policy or disabled module")
    policy = load_policy(connection, assessment_id, body.policy_id)
    pinned = authorize(
        policy, body.destination_url, body.profile, resolver, config.control_plane_networks
    )
    reserve_policy(connection, policy)
    claim = {
        "id": str(uuid4()),
        "approval_id": str(approval_id),
        "assessment_id": str(assessment_id),
        "action_digest": expected_digest,
        "action": body.model_dump(mode="json"),
        "destination": pinned.model_dump(),
        "state": "claimed-not-executed",
        "deadline": min(
            datetime.now(UTC) + timedelta(seconds=body.max_runtime_seconds),
            policy.valid_until,
            datetime.fromisoformat(payload["valid_until"]),
        ).isoformat(),
        "reviewer": row["reviewer"],
    }
    connection.execute(
        grants.update().where(grants.c.id == str(approval_id)).values(state="consumed")
    )
    connection.execute(
        claims.insert().values(
            id=claim["id"],
            approval_id=str(approval_id),
            assessment_id=str(assessment_id),
            payload=claim,
        )
    )
    audit(
        connection,
        assessment_id,
        Identity(
            subject="control-dispatch",
            role="scanner",
            principal_kind="service",
            expires=int(time.time()) + 1,
        ),
        "approval.consumed",
        approval_id,
        expected_digest,
        "completed",
    )
    return claim

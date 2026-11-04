"""Persistent stop/cancel state; unconfirmed remote termination is always unknown."""

import time
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from sqlalchemy import Connection, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from aegistrace.approval_schema import claims, grants
from aegistrace.auth import Identity
from aegistrace.control_schema import controls, executions
from aegistrace.platform_api import record_request
from aegistrace.policy import PolicyError, release_policy
from aegistrace.repository import require_access
from aegistrace.schema_v1 import assessments
from aegistrace.settings import Settings


def control_state(connection: Connection, assessment_id: UUID) -> dict[str, Any]:
    insert = pg_insert if connection.dialect.name == "postgresql" else sqlite_insert
    connection.execute(
        insert(controls)
        .values(assessment_id=str(assessment_id), stopped=False, epoch=0)
        .on_conflict_do_nothing()
    )
    return dict(
        connection.execute(select(controls).where(controls.c.assessment_id == str(assessment_id)))
        .mappings()
        .one()
    )


def require_running(connection: Connection, assessment_id: UUID) -> dict[str, Any]:
    state = control_state(connection, assessment_id)
    if state["stopped"]:
        raise PolicyError("assessment-stopped")
    return state


def emergency_stop(connection: Connection, assessment_id: UUID, actor: Identity) -> dict[str, Any]:
    require_access(connection, assessment_id, actor.subject)
    if actor.principal_kind != "human" or actor.role not in {"analyst", "reviewer", "admin"}:
        raise PolicyError("human control role required")
    connection.execute(
        assessments.update()
        .where(assessments.c.id == str(assessment_id))
        .values(owner_id=assessments.c.owner_id)
    )
    state = control_state(connection, assessment_id)
    connection.execute(
        controls.update()
        .where(controls.c.assessment_id == str(assessment_id))
        .values(stopped=True, epoch=state["epoch"] + 1)
    )
    connection.execute(
        grants.update()
        .where(
            grants.c.assessment_id == str(assessment_id),
            grants.c.state.in_(["pending-review", "approved"]),
        )
        .values(state="revoked")
    )
    queued = (
        connection.execute(select(claims).where(claims.c.assessment_id == str(assessment_id)))
        .mappings()
        .all()
    )
    not_started = 0
    for claim in queued:
        value = dict(claim["payload"])
        if value["state"] == "claimed-not-executed":
            value["state"] = "cancelled-before-start"
            connection.execute(
                claims.update().where(claims.c.id == claim["id"]).values(payload=value)
            )
            release_policy(connection, UUID(value["action"]["policy_id"]))
            not_started += 1
    rows = (
        connection.execute(
            select(executions).where(
                executions.c.assessment_id == str(assessment_id),
                executions.c.state.in_(["running", "cancel-requested", "unknown"]),
            )
        )
        .mappings()
        .all()
    )
    for row in rows:
        state_name = (
            "unknown"
            if row["state"] == "unknown" or row["lease_until"] <= time.time()
            else "cancel-requested"
        )
        connection.execute(
            executions.update()
            .where(executions.c.claim_id == row["claim_id"])
            .values(state=state_name)
        )
    result = {
        "stopped": True,
        "epoch": state["epoch"] + 1,
        "cancelled_before_start": not_started,
        "running_cancel_requests": sum(
            row["state"] != "unknown" and row["lease_until"] > time.time() for row in rows
        ),
        "unknown_disconnected": sum(
            row["state"] == "unknown" or row["lease_until"] <= time.time() for row in rows
        ),
        "termination_confirmed": False if rows else True,
    }
    record_request(connection, assessment_id, actor, "assessment.stopped", assessment_id, result)
    return result


def resume(connection: Connection, assessment_id: UUID, actor: Identity) -> dict[str, Any]:
    connection.execute(
        assessments.update()
        .where(assessments.c.id == str(assessment_id))
        .values(owner_id=assessments.c.owner_id)
    )
    require_access(connection, assessment_id, actor.subject)
    if actor.principal_kind != "human" or actor.role not in {"reviewer", "admin"}:
        raise PolicyError("human reviewer required to resume")
    if connection.execute(
        select(executions.c.claim_id).where(
            executions.c.assessment_id == str(assessment_id),
            executions.c.state.in_(["running", "cancel-requested", "unknown", "reset-required"]),
        )
    ).first():
        raise PolicyError("unreconciled or reset-required work blocks resume")
    state = control_state(connection, assessment_id)
    connection.execute(
        controls.update()
        .where(controls.c.assessment_id == str(assessment_id))
        .values(stopped=False, epoch=state["epoch"] + 1)
    )
    result = {"stopped": False, "epoch": state["epoch"] + 1, "old_approvals_restored": False}
    record_request(connection, assessment_id, actor, "assessment.resumed", assessment_id, result)
    return result


def begin_execution(
    connection: Connection,
    claim_id: UUID,
    worker_id: UUID,
    kind: Literal["scanner", "report"],
    config: Settings,
) -> dict[str, Any]:
    claim = connection.execute(select(claims).where(claims.c.id == str(claim_id))).mappings().one()
    assessment_id = UUID(claim["assessment_id"])
    connection.execute(
        assessments.update()
        .where(assessments.c.id == str(assessment_id))
        .values(owner_id=assessments.c.owner_id)
    )
    state = require_running(connection, assessment_id)
    # Re-read after lock; stop may have changed the queued claim.
    payload = dict(
        connection.execute(
            select(claims.c.payload).where(claims.c.id == str(claim_id))
        ).scalar_one()
    )
    deadline = datetime.fromisoformat(payload["deadline"]).timestamp()
    if payload["state"] != "claimed-not-executed" or deadline <= time.time():
        raise PolicyError("claim cancelled, already started or expired")
    from aegistrace.approvals import (
        ActionRequest,
        reviewer_current,
        validate_action,
        verify_snapshot,
    )
    from aegistrace.policy import authorize, load_policy

    approval = (
        connection.execute(select(grants).where(grants.c.id == claim["approval_id"]))
        .mappings()
        .one()
    )
    verify_snapshot(approval)
    if (
        approval["state"] != "consumed"
        or not reviewer_current(connection, approval, config)
        or approval["action_digest"] != payload["action_digest"]
        or approval["payload"]["action"] != payload["action"]
    ):
        raise PolicyError("claimed authority changed or reviewer revoked")
    action = ActionRequest.model_validate(payload["action"])
    validate_action(connection, assessment_id, action)
    policy = load_policy(connection, assessment_id, action.policy_id)
    authorize(
        policy,
        action.destination_url,
        action.profile,
        protected_networks=config.control_plane_networks,
    )
    payload["state"] = "running"
    connection.execute(claims.update().where(claims.c.id == str(claim_id)).values(payload=payload))
    value = {
        "claim_id": str(claim_id),
        "assessment_id": str(assessment_id),
        "worker_id": str(worker_id),
        "epoch": state["epoch"],
        "lease_until": min(time.time() + 5, deadline),
        "deadline": deadline,
        "started_at": time.time(),
        "state": "running",
        "kind": kind,
        "reset_required": payload["action"]["profile"] in {"active-web", "controlled-validation"},
        "reset_evidence_id": None,
        "termination_evidence_id": None,
    }
    connection.execute(executions.insert().values(**value))
    return value


def heartbeat(connection: Connection, claim_id: UUID, worker_id: UUID, epoch: int) -> bool:
    row = (
        connection.execute(select(executions).where(executions.c.claim_id == str(claim_id)))
        .mappings()
        .one()
    )
    if (
        row["worker_id"] != str(worker_id)
        or row["epoch"] != epoch
        or row["lease_until"] <= time.time()
    ):
        raise PolicyError("expired or mismatched worker fence")
    stopped = control_state(connection, UUID(row["assessment_id"]))["stopped"]
    cancel = stopped or row["state"] != "running" or row["deadline"] <= time.time()
    if not cancel:
        connection.execute(
            executions.update()
            .where(executions.c.claim_id == str(claim_id))
            .values(lease_until=min(time.time() + 5, row["deadline"]))
        )
    return bool(cancel)


def finish_execution(
    connection: Connection, claim_id: UUID, worker_id: UUID, epoch: int, termination_confirmed: bool
) -> str:
    row = (
        connection.execute(select(executions).where(executions.c.claim_id == str(claim_id)))
        .mappings()
        .one()
    )
    if (
        row["worker_id"] != str(worker_id)
        or row["epoch"] != epoch
        or row["lease_until"] <= time.time()
        or row["state"] not in {"running", "cancel-requested"}
    ):
        raise PolicyError("worker fence no longer valid")
    state = (
        "unknown"
        if not termination_confirmed
        else ("reset-required" if row["reset_required"] else "terminated")
    )
    connection.execute(
        executions.update().where(executions.c.claim_id == str(claim_id)).values(state=state)
    )
    claim_payload = dict(
        connection.execute(
            select(claims.c.payload).where(claims.c.id == str(claim_id))
        ).scalar_one()
    )
    claim_payload["state"] = state
    connection.execute(
        claims.update().where(claims.c.id == str(claim_id)).values(payload=claim_payload)
    )
    if termination_confirmed and not row["reset_required"]:
        payload = connection.execute(
            select(claims.c.payload).where(claims.c.id == str(claim_id))
        ).scalar_one()
        release_policy(connection, UUID(payload["action"]["policy_id"]))
    return state


def cancel_job(
    connection: Connection, assessment_id: UUID, claim_id: UUID, actor: Identity
) -> dict[str, Any]:
    require_access(connection, assessment_id, actor.subject)
    if actor.principal_kind != "human" or actor.role not in {"analyst", "reviewer", "admin"}:
        raise PolicyError("human control role required")
    connection.execute(
        assessments.update()
        .where(assessments.c.id == str(assessment_id))
        .values(owner_id=assessments.c.owner_id)
    )
    claim = (
        connection.execute(
            select(claims).where(
                claims.c.id == str(claim_id), claims.c.assessment_id == str(assessment_id)
            )
        )
        .mappings()
        .one_or_none()
    )
    if claim is None:
        raise LookupError("claim not found")
    payload = dict(claim["payload"])
    if payload["state"] == "claimed-not-executed":
        payload["state"] = "cancelled-before-start"
        connection.execute(
            claims.update().where(claims.c.id == str(claim_id)).values(payload=payload)
        )
        release_policy(connection, UUID(payload["action"]["policy_id"]))
        result = {"state": "cancelled-before-start", "termination_confirmed": True}
    else:
        row = (
            connection.execute(select(executions).where(executions.c.claim_id == str(claim_id)))
            .mappings()
            .one_or_none()
        )
        state = (
            "unknown" if row is None or row["lease_until"] <= time.time() else "cancel-requested"
        )
        if row is not None and row["state"] in {"running", "cancel-requested", "unknown"}:
            connection.execute(
                executions.update()
                .where(executions.c.claim_id == str(claim_id))
                .values(state=state)
            )
        result = {
            "state": row["state"]
            if row and row["state"] not in {"running", "cancel-requested", "unknown"}
            else state,
            "termination_confirmed": False,
        }
    record_request(connection, assessment_id, actor, "job.cancel-requested", claim_id, result)
    return result

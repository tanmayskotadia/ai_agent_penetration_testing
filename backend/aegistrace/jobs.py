"""At-least-once delivery with single-use claims; uncertain external work never retries."""

import hashlib
import re
import secrets
import time
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import Connection, Engine, func, select

from aegistrace.approval_schema import claims, grants
from aegistrace.approvals import consume
from aegistrace.auth import Identity
from aegistrace.control import begin_execution, finish_execution, heartbeat
from aegistrace.control_schema import executions
from aegistrace.job_schema import chunks, jobs, outbox
from aegistrace.platform_api import record_request
from aegistrace.policy import PolicyError, release_policy
from aegistrace.repository import require_access
from aegistrace.scheduler_schema import admissions
from aegistrace.schema_v1 import assessments
from aegistrace.settings import Settings


def lock_job(connection: Connection, job_id: UUID) -> Mapping[str, Any]:
    assessment_id = connection.execute(
        select(jobs.c.assessment_id).where(jobs.c.id == str(job_id))
    ).scalar_one_or_none()
    if assessment_id is None:
        raise LookupError("job not found")
    connection.execute(
        assessments.update()
        .where(assessments.c.id == assessment_id)
        .values(owner_id=assessments.c.owner_id)
    )
    return dict(
        connection.execute(select(jobs).where(jobs.c.id == str(job_id)).with_for_update())
        .mappings()
        .one()
    )


def job_event(
    connection: Connection, row: Mapping[str, Any], action: str, payload: dict[str, Any]
) -> None:
    record_request(
        connection,
        UUID(row["assessment_id"]),
        Identity(
            subject="durable-job-coordinator",
            role="scanner",
            principal_kind="service",
            expires=int(time.time()) + 1,
        ),
        "job." + action,
        UUID(row["id"]),
        payload,
    )


def enqueue(
    connection: Connection,
    config: Settings,
    assessment_id: UUID,
    approval_id: UUID,
    digest: str,
    actor: Identity,
    priority: int = 0,
) -> dict[str, Any]:
    require_access(connection, assessment_id, actor.subject)
    if actor.principal_kind != "human" or actor.role not in {"analyst", "reviewer", "admin"}:
        raise PolicyError("human operator required")
    if config.evidence_key is None:
        raise PolicyError("encrypted output storage must be configured before queueing")
    from aegistrace.approvals import ActionRequest, reviewer_current, verify_snapshot
    from aegistrace.scheduler import reserve_admission

    if type(priority) is not int or not 0 <= priority <= 10:
        raise PolicyError("bounded human priority required")
    connection.execute(
        assessments.update()
        .where(assessments.c.id == str(assessment_id))
        .values(owner_id=assessments.c.owner_id)
    )
    approval = (
        connection.execute(
            select(grants).where(
                grants.c.id == str(approval_id), grants.c.assessment_id == str(assessment_id)
            )
        )
        .mappings()
        .one_or_none()
    )
    if (
        approval is None
        or approval["state"] != "approved"
        or approval["action_digest"] != digest
        or not reviewer_current(connection, approval, config)
    ):
        raise PolicyError("current human approval required")
    verify_snapshot(approval)
    if datetime.fromisoformat(approval["payload"]["valid_until"]).timestamp() <= time.time():
        raise PolicyError("approval expired")
    admission = reserve_admission(
        connection, assessment_id, ActionRequest.model_validate(approval["payload"]["action"])
    )
    if "existing_job_id" in admission:
        row = (
            connection.execute(select(jobs).where(jobs.c.id == admission["existing_job_id"]))
            .mappings()
            .one()
        )
        value = dict(row) | {
            "scheduling_decision": "suppressed-or-reused",
            "scheduling_reason": admission["reason"],
            "new_approval_consumed": False,
        }
        record_request(
            connection,
            assessment_id,
            actor,
            "job.suppressed",
            UUID(row["id"]),
            {"reason": admission["reason"]},
        )
        return value
    claim = consume(connection, config, assessment_id, approval_id, digest)
    now = time.time()
    value = dict(
        id=str(uuid4()),
        assessment_id=str(assessment_id),
        claim_id=claim["id"],
        state="queued",
        attempt=0,
        worker_id=None,
        epoch=None,
        lease_until=None,
        external_scan_id=None,
        created_at=now,
        updated_at=now,
        reason=None,
    )
    connection.execute(jobs.insert().values(**value))
    connection.execute(
        admissions.insert().values(
            job_id=value["id"], assessment_id=str(assessment_id), priority=priority, **admission
        )
    )
    connection.execute(outbox.insert().values(job_id=value["id"], attempts=0, available_at=now))
    record_request(connection, assessment_id, actor, "job.queued", UUID(value["id"]), value)
    return value


def publish_pending(engine: Engine, publish: Callable[[str], None], limit: int = 20) -> int:
    """A crash after publish and before commit can redeliver, never create another claim."""
    if not 1 <= limit <= 100:
        raise ValueError("bounded outbox batch required")
    sent = 0
    with engine.connect() as connection:
        ids = list(
            connection.execute(
                select(outbox.c.job_id)
                .where(
                    outbox.c.published_at.is_(None),
                    outbox.c.available_at <= time.time(),
                    outbox.c.attempts < 5,
                )
                .order_by(outbox.c.available_at, outbox.c.job_id)
                .limit(limit)
            ).scalars()
        )
        rankings = {
            item["job_id"]: item
            for item in connection.execute(
                select(admissions).where(admissions.c.job_id.in_(ids))
            ).mappings()
        }
        ids.sort(
            key=lambda value: (
                (
                    -(
                        rankings[value]["priority"]
                        + max(0.0, time.time() - rankings[value]["admitted_at"])
                    ),
                    rankings[value]["admitted_at"],
                    value,
                )
                if value in rankings
                else (0.0, 0.0, value)
            )
        )
    for job_id in ids:
        with engine.begin() as connection:
            job = lock_job(connection, UUID(job_id))
            item = (
                connection.execute(
                    select(outbox).where(outbox.c.job_id == job_id).with_for_update()
                )
                .mappings()
                .one()
            )
            if (
                item["published_at"] is not None
                or item["available_at"] > time.time()
                or item["attempts"] >= 5
            ):
                continue
            if job["state"] != "queued":
                connection.execute(
                    outbox.update()
                    .where(outbox.c.job_id == job_id)
                    .values(published_at=time.time())
                )
                continue
            attempt = item["attempts"] + 1
            try:
                publish(job_id)
            except Exception:
                connection.execute(
                    outbox.update()
                    .where(outbox.c.job_id == job_id)
                    .values(attempts=attempt, available_at=time.time() + min(60, 2**attempt))
                )
                connection.execute(
                    jobs.update()
                    .where(jobs.c.id == job_id)
                    .values(
                        reason="broker-unavailable; dispatch retry exhausted"
                        if attempt == 5
                        else "broker-unavailable; dispatch pending",
                        updated_at=time.time(),
                    )
                )
            else:
                connection.execute(
                    outbox.update()
                    .where(outbox.c.job_id == job_id)
                    .values(attempts=attempt, published_at=time.time())
                )
                sent += 1
    return sent


def abandon_queued(connection: Connection, row: Mapping[str, Any], reason: str) -> None:
    payload = dict(
        connection.execute(
            select(claims.c.payload).where(claims.c.id == row["claim_id"])
        ).scalar_one()
    )
    if payload["state"] == "claimed-not-executed":
        payload["state"] = "cancelled-before-start"
        connection.execute(
            claims.update().where(claims.c.id == row["claim_id"]).values(payload=payload)
        )
        release_policy(connection, UUID(payload["action"]["policy_id"]))
    connection.execute(
        jobs.update()
        .where(jobs.c.id == row["id"])
        .values(state="failed", reason=reason, updated_at=time.time())
    )
    job_event(connection, row, "failed-before-start", {"reason": reason})


def start_job(
    connection: Connection, config: Settings, job_id: UUID, worker_id: UUID
) -> dict[str, Any] | None:
    row = lock_job(connection, job_id)
    if row["state"] != "queued":
        return None
    # Savepoint allows a failed authority check to release only an unstarted reservation.
    try:
        with connection.begin_nested():
            execution = begin_execution(
                connection, UUID(row["claim_id"]), worker_id, "scanner", config
            )
    except ValueError:
        abandon_queued(
            connection, row, "current-authority-or-scope-check-failed; fresh approval required"
        )
        return None
    connection.execute(
        jobs.update()
        .where(jobs.c.id == str(job_id))
        .values(
            state="running",
            attempt=1,
            worker_id=str(worker_id),
            epoch=execution["epoch"],
            lease_until=execution["lease_until"],
            updated_at=time.time(),
            reason=None,
        )
    )
    job_event(
        connection,
        row,
        "started",
        {"worker_id": str(worker_id), "epoch": execution["epoch"], "attempt": 1},
    )
    return dict(row) | {
        "worker_id": str(worker_id),
        "epoch": execution["epoch"],
        "state": "running",
        "attempt": 1,
    }


def job_heartbeat(connection: Connection, job_id: UUID, worker_id: UUID, epoch: int) -> bool:
    row = lock_job(connection, job_id)
    if row["state"] != "running" or row["worker_id"] != str(worker_id) or row["epoch"] != epoch:
        raise PolicyError("job fence invalid")
    cancel = heartbeat(connection, UUID(row["claim_id"]), worker_id, epoch)
    lease = connection.execute(
        select(executions.c.lease_until).where(executions.c.claim_id == row["claim_id"])
    ).scalar_one()
    connection.execute(
        jobs.update()
        .where(jobs.c.id == str(job_id))
        .values(lease_until=lease, updated_at=time.time())
    )
    return cancel


def record_submission(
    connection: Connection, job_id: UUID, worker_id: UUID, epoch: int, external_id: str
) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}", external_id):
        raise ValueError("bounded opaque external ID required")
    row = lock_job(connection, job_id)
    if job_heartbeat(connection, job_id, worker_id, epoch):
        raise PolicyError("job cancellation requested")
    if row["external_scan_id"] is not None and row["external_scan_id"] != external_id:
        raise PolicyError("external submission already recorded")
    connection.execute(
        jobs.update().where(jobs.c.id == str(job_id)).values(external_scan_id=external_id)
    )
    job_event(connection, row, "submission-recorded", {"external_scan_id": external_id})


def append_output(
    connection: Connection, config: Settings, job_id: UUID, worker_id: UUID, epoch: int, raw: bytes
) -> str:
    lock_job(connection, job_id)
    if job_heartbeat(connection, job_id, worker_id, epoch):
        raise PolicyError("job cancellation requested")
    if config.evidence_key is None or not raw:
        raise PolicyError("encrypted nonempty output required")
    total, count = connection.execute(
        select(func.coalesce(func.sum(chunks.c.size), 0), func.count()).where(
            chunks.c.job_id == str(job_id)
        )
    ).one()
    if total + len(raw) > 2 * 1024 * 1024 or count >= 256:
        raise PolicyError("job output quota exceeded")
    nonce = secrets.token_bytes(12)
    aad = f"aegistrace:job:{job_id}:{count}".encode()
    digest = hashlib.sha256(raw).hexdigest()
    connection.execute(
        chunks.insert().values(
            job_id=str(job_id),
            sequence=count,
            sha256=digest,
            size=len(raw),
            nonce=nonce,
            ciphertext=AESGCM(bytes.fromhex(config.evidence_key.get_secret_value())).encrypt(
                nonce, raw, aad
            ),
            key_id=config.evidence_key_id,
            expires_at=time.time() + 3600,
        )
    )
    return digest


def purge_expired_output(connection: Connection) -> int:
    """Trusted retention sweeper; no raw output is logged or returned."""
    result = connection.execute(chunks.delete().where(chunks.c.expires_at <= time.time()))
    return int(result.rowcount)


def finish_job(
    connection: Connection,
    job_id: UUID,
    worker_id: UUID,
    epoch: int,
    outcome: str,
    termination_confirmed: bool,
) -> str:
    if outcome not in {"collected", "partial", "failed", "cancelled", "blocked"}:
        raise ValueError("worker cannot claim normalized/completed results")
    row = lock_job(connection, job_id)
    if row["state"] != "running" or row["worker_id"] != str(worker_id) or row["epoch"] != epoch:
        raise PolicyError("job fence invalid")
    cancellation = (
        connection.execute(
            select(executions.c.state).where(executions.c.claim_id == row["claim_id"])
        ).scalar_one()
        == "cancel-requested"
    )
    control = finish_execution(
        connection, UUID(row["claim_id"]), worker_id, epoch, termination_confirmed
    )
    state = ("cancelled" if cancellation else outcome) if control == "terminated" else control
    connection.execute(
        jobs.update()
        .where(jobs.c.id == str(job_id))
        .values(
            state=state,
            updated_at=time.time(),
            reason="verified-native-runner-unavailable" if outcome == "blocked" else None,
        )
    )
    job_event(
        connection,
        row,
        "finished",
        {"state": state, "termination_confirmed": termination_confirmed},
    )
    return state


def reconcile(connection: Connection, job_id: UUID) -> str:
    row = lock_job(connection, job_id)
    if row["state"] == "running" and row["lease_until"] <= time.time():
        connection.execute(
            jobs.update()
            .where(jobs.c.id == str(job_id))
            .values(
                state="unknown",
                reason="worker-lease-expired; reconcile external work before fresh approval",
                updated_at=time.time(),
            )
        )
        connection.execute(
            executions.update()
            .where(executions.c.claim_id == row["claim_id"])
            .values(state="unknown")
        )
        job_event(connection, row, "worker-lost", {"state": "unknown", "automatic_retry": False})
        return "unknown"
    if row["state"] == "queued":
        payload = connection.execute(
            select(claims.c.payload).where(claims.c.id == row["claim_id"])
        ).scalar_one()
        if payload["state"] == "cancelled-before-start":
            connection.execute(
                jobs.update()
                .where(jobs.c.id == str(job_id))
                .values(state="cancelled", updated_at=time.time())
            )
            return "cancelled"
        if datetime.fromisoformat(payload["deadline"]).timestamp() <= time.time():
            abandon_queued(connection, row, "unstarted-claim-expired; fresh approval required")
            return "failed"
    return str(row["state"])


def reconcile_batch(engine: Engine, limit: int = 100) -> int:
    if not 1 <= limit <= 100:
        raise ValueError("bounded reconciliation batch required")
    with engine.connect() as connection:
        ids = list(
            connection.execute(
                select(jobs.c.id)
                .where(jobs.c.state.in_(["queued", "running"]))
                .order_by(jobs.c.updated_at, jobs.c.id)
                .limit(limit)
            ).scalars()
        )
    for job_id in ids:
        with engine.begin() as connection:
            reconcile(connection, UUID(job_id))
            connection.execute(
                jobs.update().where(jobs.c.id == job_id).values(updated_at=time.time())
            )
    with engine.begin() as connection:
        purge_expired_output(connection)
    return len(ids)

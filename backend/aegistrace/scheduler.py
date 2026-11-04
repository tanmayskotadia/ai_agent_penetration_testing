"""Deterministic shared job admission. Logical dispatch rates are not packet-rate claims."""

import hashlib
import json
import time
from typing import Any
from uuid import UUID

from sqlalchemy import Connection, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from aegistrace.approvals import ActionRequest, validate_action
from aegistrace.job_schema import jobs
from aegistrace.policy import PolicyError, load_policy
from aegistrace.scheduler_schema import admissions, buckets, scheduler_lock

HELD = ("queued", "running", "unknown", "reset-required")
MAX_ASSESSMENT_JOBS_PER_HOUR = 30


def admission_lock(connection: Connection) -> None:
    insert = pg_insert if connection.dialect.name == "postgresql" else sqlite_insert
    connection.execute(insert(scheduler_lock).values(id=1).on_conflict_do_nothing())
    connection.execute(scheduler_lock.update().where(scheduler_lock.c.id == 1).values(id=1))


def fingerprint(
    connection: Connection, assessment_id: UUID, action: ActionRequest
) -> tuple[str, list[str], float]:
    checked = validate_action(connection, assessment_id, action)
    policy = load_policy(connection, assessment_id, action.policy_id)
    from aegistrace.policy import authorize

    destination = authorize(policy, action.destination_url, action.profile)
    value = {
        "policy_digest": checked["policy_digest"],
        "scope_id": str(policy.scope_id),
        "scope_revision": policy.scope_revision,
        "tool": action.tool,
        "template": action.template,
        "profile": action.profile,
        "parameters": action.parameters,
        "destination": destination.model_dump(),
        "plan_revision": action.plan_revision,
        "adapter_revision": "candidate-v1-no-live-execution",
    }
    digest = hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return digest, sorted(destination.pinned_addresses), min(1.0, float(policy.requests_per_second))


def reserve_admission(
    connection: Connection, assessment_id: UUID, action: ActionRequest
) -> dict[str, Any]:
    """Caller already holds its assessment lock; no code takes the global lock first."""
    admission_lock(connection)
    digest, targets, rate = fingerprint(connection, assessment_id, action)
    now = time.time()
    # Reuse requires the same current policy/scope/target/profile/template/parameters and adapter revision.
    previous = (
        connection.execute(
            select(jobs, admissions.c.admitted_at)
            .join(admissions, admissions.c.job_id == jobs.c.id)
            .where(
                admissions.c.assessment_id == str(assessment_id),
                admissions.c.fingerprint == digest,
                jobs.c.state.in_(["queued", "running", "completed"]),
            )
            .order_by(admissions.c.admitted_at.desc())
            .limit(1)
        )
        .mappings()
        .one_or_none()
    )
    if previous is not None and (
        previous["state"] != "completed" or now - previous["admitted_at"] <= 60
    ):
        return {
            "existing_job_id": previous["id"],
            "reason": "identical work pending"
            if previous["state"] != "completed"
            else "fresh normalized result; original capture time retained",
        }
    recent = list(
        connection.execute(
            select(admissions).where(
                admissions.c.assessment_id == str(assessment_id),
                admissions.c.admitted_at > now - 3600,
            )
        ).mappings()
    )
    if len(recent) >= MAX_ASSESSMENT_JOBS_PER_HOUR:
        raise PolicyError("assessment hourly job budget exhausted; retry after window expiry")
    held = list(
        connection.execute(
            select(admissions)
            .join(jobs, jobs.c.id == admissions.c.job_id)
            .where(jobs.c.state.in_(HELD))
        ).mappings()
    )
    validation = action.profile in {"active-web", "controlled-validation"}
    if len(held) >= 16 or sum(item["assessment_id"] == str(assessment_id) for item in held) >= 4:
        raise PolicyError(
            "global/assessment concurrency admission limit; unknown work retains slots"
        )
    if any(sum(target in item["targets"] for item in held) >= 2 for target in targets):
        raise PolicyError("shared target concurrency limit across assessments")
    if validation and any(item["validation"] for item in held):
        raise PolicyError("validation concurrency limit is one globally")
    keys = [("global", 4.0), ("assessment:" + str(assessment_id), rate)] + [
        ("target:" + target, rate) for target in targets
    ]
    updates = []
    for key, allowed_rate in keys:
        row = (
            connection.execute(select(buckets).where(buckets.c.key == key)).mappings().one_or_none()
        )
        effective_rate = min(allowed_rate, row["rate"]) if row else allowed_rate
        tokens = (
            min(1.0, row["tokens"] + max(0.0, now - row["updated_at"]) * effective_rate)
            if row
            else 1.0
        )
        if tokens < 1.0:
            raise PolicyError("shared dispatch rate/cooldown limit; retry later")
        updates.append((key, effective_rate, row is not None))
    # All checks precede mutation: caught denials cannot consume part of a bucket.
    for key, effective_rate, exists in updates:
        value = dict(tokens=0.0, rate=effective_rate, updated_at=now)
        connection.execute(
            buckets.update().where(buckets.c.key == key).values(**value)
            if exists
            else buckets.insert().values(key=key, **value)
        )
    return {"fingerprint": digest, "targets": targets, "admitted_at": now, "validation": validation}


def queue_for(connection: Connection, job_id: str) -> str:
    validation = connection.execute(
        select(admissions.c.validation).where(admissions.c.job_id == job_id)
    ).scalar_one_or_none()
    return "aegistrace.validation" if validation else "celery"

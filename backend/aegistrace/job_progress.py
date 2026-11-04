"""Truthful job status snapshots and persisted finite-batch event replay."""

import re
import time
from collections.abc import Mapping
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Connection, func, select

from aegistrace.job_progress_schema import progress_events

DIAGNOSTICS = {
    "approval-stale": "Authorization or scope changed. Review current scope and obtain fresh approval.",
    "broker-unavailable": "Queue broker is unavailable. Dispatch remains pending for bounded retry.",
    "broker-retries-exhausted": "Dispatch retries are exhausted. Check broker health before requesting fresh approval.",
    "worker-heartbeat-expired": "Worker heartbeat expired. Reconcile external work before any retry.",
    "runner-unavailable": "No verified native runner is available. No external scan was submitted.",
    "tool-unavailable": "The configured tool or API is unavailable or unverified. The task was not submitted.",
    "license-required": "A required tool license is unavailable or unverified. The task was not submitted.",
    "tool-exit-nonzero": "The tool exited unsuccessfully. Review retained evidence before deciding whether to retry.",
    "collection-failed": "Output collection failed. The run is partial until evidence is reviewed.",
    "cancel-unconfirmed": "Cancellation is not confirmed. Treat execution as unknown until termination is verified.",
    "late-output-quarantined": "Late output is encrypted and quarantined pending human review.",
    "late-output-reviewed": "Late output was reviewed. Inclusion requires a fresh evidence import.",
}
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+/-]{0,79}$")
_TERMINAL = {"partial", "failed", "cancelled", "blocked", "collected"}


def append_progress(
    connection: Connection,
    job: Mapping[str, Any],
    kind: str,
    state: str,
    *,
    attempt: int | None = None,
    worker_id: UUID | None = None,
    epoch: int | None = None,
    tool_version: str | None = None,
    exit_code: int | None = None,
    diagnostic_code: str | None = None,
) -> dict[str, Any]:
    """Append a bounded event; diagnostics are selected from safe static messages."""
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,39}", kind):
        raise ValueError("invalid progress event kind")
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,29}", state):
        raise ValueError("invalid job state")
    if tool_version is not None and not _VERSION.fullmatch(tool_version):
        raise ValueError("tool version must be a bounded identifier")
    if exit_code is not None and (type(exit_code) is not int or not -255 <= exit_code <= 255):
        raise ValueError("exit code is outside the supported range")
    if diagnostic_code is not None and diagnostic_code not in DIAGNOSTICS:
        raise ValueError("unsupported sanitized diagnostic code")
    sequence = (
        connection.execute(
            select(func.coalesce(func.max(progress_events.c.sequence), 0)).where(
                progress_events.c.job_id == str(job["id"])
            )
        ).scalar_one()
        + 1
    )
    now = time.time()
    started = connection.execute(
        select(func.min(progress_events.c.created_at)).where(
            progress_events.c.job_id == str(job["id"]), progress_events.c.kind == "started"
        )
    ).scalar_one_or_none()
    payload = {
        "schema_version": "1.0",
        "job_id": str(job["id"]),
        "assessment_id": str(job["assessment_id"]),
        "sequence": sequence,
        "event_id": str(uuid4()),
        "kind": kind,
        "state": state,
        "attempt": job["attempt"] if attempt is None else attempt,
        "created_at": now,
        "worker_id": str(worker_id) if worker_id else job.get("worker_id"),
        "epoch": epoch if epoch is not None else job.get("epoch"),
        "elapsed_ms": max(0, int((now - started) * 1000)) if started is not None else None,
        "tool_version": tool_version,
        "exit_code": exit_code,
        "diagnostic_code": diagnostic_code,
        "diagnostic": DIAGNOSTICS.get(diagnostic_code) if diagnostic_code else None,
    }
    connection.execute(progress_events.insert().values(**payload))
    return payload


def read_progress(
    connection: Connection, job_id: UUID, assessment_id: UUID, after: int = 0, limit: int = 100
) -> list[dict[str, Any]]:
    if after < 0 or not 1 <= limit <= 100:
        raise ValueError("invalid progress cursor or limit")
    return [
        dict(row)
        for row in connection.execute(
            select(progress_events)
            .where(
                progress_events.c.job_id == str(job_id),
                progress_events.c.assessment_id == str(assessment_id),
                progress_events.c.sequence > after,
            )
            .order_by(progress_events.c.sequence)
            .limit(limit)
        ).mappings()
    ]


def job_snapshot(
    connection: Connection, job: dict[str, Any], now: float | None = None
) -> dict[str, Any]:
    timestamp = time.time() if now is None else now
    first_start = (
        connection.execute(
            select(progress_events)
            .where(progress_events.c.job_id == str(job["id"]), progress_events.c.kind == "started")
            .order_by(progress_events.c.sequence)
            .limit(1)
        )
        .mappings()
        .first()
    )
    latest = (
        connection.execute(
            select(progress_events)
            .where(progress_events.c.job_id == str(job["id"]))
            .order_by(progress_events.c.sequence.desc())
            .limit(1)
        )
        .mappings()
        .first()
    )
    heartbeat_at = job["updated_at"] if job["state"] == "running" else None
    heartbeat_age = max(0, int(timestamp - heartbeat_at)) if heartbeat_at is not None else None
    heartbeat_stale = bool(
        heartbeat_at is not None
        and (heartbeat_age is not None and heartbeat_age > 120 or job["lease_until"] <= timestamp)
    )
    stored_state = str(job["state"])
    return dict(job) | {
        "status": "unknown" if heartbeat_stale else stored_state,
        "heartbeat_at": heartbeat_at,
        "heartbeat_age_seconds": heartbeat_age,
        "heartbeat_stale": heartbeat_stale,
        "started_at": first_start["created_at"] if first_start else None,
        "finished_at": (latest["created_at"] if latest and latest["state"] in _TERMINAL else None),
        "duration_ms": (
            latest["elapsed_ms"]
            if latest and latest["elapsed_ms"] is not None
            else max(0, int((timestamp - first_start["created_at"]) * 1000))
            if first_start
            else None
        ),
        "tool_version": latest["tool_version"] if latest else None,
        "exit_code": latest["exit_code"] if latest else None,
        "diagnostic_code": latest["diagnostic_code"] if latest else None,
        "diagnostic": latest["diagnostic"] if latest else None,
        "events_cursor": latest["sequence"] if latest else 0,
        "latest_event_kind": latest["kind"] if latest else None,
        "latest_event_at": latest["created_at"] if latest else None,
        "percentage_complete": None,
    }

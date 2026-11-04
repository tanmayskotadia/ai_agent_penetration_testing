"""Persisted worker progress exposes current state, safe diagnostics and replay cursors."""

import time
from uuid import UUID, uuid4

import pytest
from aegistrace.job_progress import append_progress
from aegistrace.job_progress_schema import progress_events, protect_progress
from aegistrace.job_schema import jobs
from aegistrace.jobs import finish_job, start_job
from sqlalchemy import select
from sqlalchemy.exc import DatabaseError
from test_jobs import policy_context as policy_context
from test_jobs import queued


def prepare(context):
    _, engine, _ = context
    if engine.dialect.name == "sqlite":
        with engine.begin() as connection:
            protect_progress(connection)


def test_status_and_sse_are_persisted_and_resumable(policy_context):
    client, engine, config = policy_context
    prepare(policy_context)
    base, headers, _, _, job = queued(policy_context)
    status = client.get(base + "/scan-jobs/" + job["id"], headers=headers())
    assert status.status_code == 200, status.text
    snapshot = status.json()
    assert snapshot["state"] == snapshot["status"] == "queued"
    assert snapshot["percentage_complete"] is None and snapshot["attempt"] == 0

    first = client.get(
        base + "/scan-jobs/" + job["id"] + "/events",
        headers=headers() | {"Last-Event-ID": "0"},
    )
    assert first.status_code == 200 and "event: job-status" in first.text
    assert '"kind":"queued"' in first.text

    worker_id = uuid4()
    with engine.begin() as connection:
        started = start_job(connection, config, UUID(job["id"]), worker_id)
        assert started is not None
        assert (
            finish_job(connection, UUID(job["id"]), worker_id, started["epoch"], "blocked", True)
            == "blocked"
        )

    blocked = client.get(base + "/scan-jobs/" + job["id"], headers=headers()).json()
    assert blocked["status"] == "blocked"
    assert blocked["attempt"] == 1 and blocked["duration_ms"] is not None
    assert blocked["diagnostic_code"] == "runner-unavailable"
    assert "No external scan was submitted" in blocked["diagnostic"]

    resumed = client.get(
        base + "/scan-jobs/" + job["id"] + "/events",
        headers=headers() | {"Last-Event-ID": "1"},
    )
    assert resumed.status_code == 200
    assert '"kind":"started"' in resumed.text and '"kind":"finished"' in resumed.text
    assert '"sequence":1' not in resumed.text


def test_stale_heartbeat_displays_unknown_without_fabricating_worker_state(policy_context):
    client, engine, config = policy_context
    prepare(policy_context)
    base, headers, _, _, job = queued(policy_context)
    worker_id = uuid4()
    with engine.begin() as connection:
        started = start_job(connection, config, UUID(job["id"]), worker_id)
        assert started is not None
        connection.execute(
            jobs.update()
            .where(jobs.c.id == job["id"])
            .values(updated_at=time.time() - 180, lease_until=time.time() + 300)
        )
    status = client.get(base + "/scan-jobs/" + job["id"], headers=headers()).json()
    assert status["state"] == "running"
    assert status["status"] == "unknown" and status["heartbeat_stale"]


def test_progress_rejects_untrusted_diagnostics_and_is_immutable(policy_context):
    _, engine, config = policy_context
    prepare(policy_context)
    *_, job = queued(policy_context)
    with engine.begin() as connection:
        row = connection.execute(select(jobs).where(jobs.c.id == job["id"])).mappings().one()
        with pytest.raises(ValueError):
            append_progress(
                connection,
                row,
                "failed",
                "failed",
                diagnostic_code="exception-contains-secret",
            )
        with pytest.raises(DatabaseError), connection.begin_nested():
            connection.execute(
                progress_events.delete().where(
                    progress_events.c.job_id == job["id"], progress_events.c.sequence == 1
                )
            )


@pytest.mark.services
def test_postgresql_job_progress_is_append_only(policy_context):
    test_progress_rejects_untrusted_diagnostics_and_is_immutable(policy_context)

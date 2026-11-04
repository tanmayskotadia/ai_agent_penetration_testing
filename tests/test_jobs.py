"""Durable dispatch/crash contracts; test-only authority, no native scanner execution."""

import hashlib
import os
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from aegistrace.approval_schema import claims
from aegistrace.job_schema import chunks, jobs, outbox
from aegistrace.jobs import (
    append_output,
    finish_job,
    job_heartbeat,
    publish_pending,
    purge_expired_output,
    reconcile,
    record_submission,
    start_job,
)
from aegistrace.policy import PolicyError
from aegistrace.scheduler_schema import buckets
from aegistrace_workers.app import create_worker
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import SecretStr
from sqlalchemy import select
from test_approvals import prepared, review
from test_policy import policy_context as policy_context


def queued(context):
    client, engine, config = context
    if config.evidence_key is None:
        config.evidence_key = SecretStr(secrets.token_hex(32))
    base, headers, approval, _ = prepared(context)
    review(context, base, headers, approval)
    body = {"approval_id": approval["id"], "action_digest": approval["action_digest"]}
    h = headers()
    response = client.post(base + "/scan-jobs", json=body, headers=h)
    assert response.status_code == 202, response.text
    return base, headers, body, h, response.json()


def test_atomic_enqueue_idempotency_and_approval_single_use(policy_context):
    client, engine, _ = policy_context
    base, headers, body, h, job = queued(policy_context)
    assert client.post(base + "/scan-jobs", json=body, headers=h).json() == job
    assert client.post(base + "/scan-jobs", json=body, headers=headers()).status_code == 422
    with engine.connect() as connection:
        assert connection.execute(select(outbox).where(outbox.c.job_id == job["id"])).one()
        assert connection.execute(select(claims).where(claims.c.id == job["claim_id"])).one()
    assert (
        client.get(base + "/scan-jobs/" + job["id"], headers=headers()).json()["state"] == "queued"
    )


def test_publish_rollback_redelivery_and_broker_failure(policy_context):
    _, engine, _ = policy_context
    *_, job = queued(policy_context)
    delivered = []

    def crash_after_send(job_id):
        delivered.append(job_id)
        raise KeyboardInterrupt("simulated process death after publish")

    with pytest.raises(KeyboardInterrupt):
        publish_pending(engine, crash_after_send)
    assert publish_pending(engine, delivered.append) == 1
    assert delivered == [job["id"], job["id"]]
    assert publish_pending(engine, delivered.append) == 0


def test_broker_failure_leaves_recoverable_outbox(policy_context):
    _, engine, _ = policy_context
    *_, job = queued(policy_context)

    def unavailable(_):
        raise ConnectionError("TEST ONLY broker unavailable; never log details")

    assert publish_pending(engine, unavailable) == 0
    with engine.begin() as connection:
        row = (
            connection.execute(select(outbox).where(outbox.c.job_id == job["id"])).mappings().one()
        )
        assert row["attempts"] == 1 and row["published_at"] is None
        connection.execute(
            outbox.update().where(outbox.c.job_id == job["id"]).values(available_at=0)
        )
    assert publish_pending(engine, lambda _: None) == 1


def test_two_workers_only_one_start_and_partial_output_survives_crash(policy_context):
    _, engine, config = policy_context
    *_, job = queued(policy_context)
    job_id = UUID(job["id"])

    def start(_):
        with engine.begin() as connection:
            return start_job(connection, config, job_id, uuid4())

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(start, range(2)))
    started = [value for value in results if value is not None]
    assert len(started) == 1
    value = started[0]
    worker_id = UUID(value["worker_id"])
    raw = b"TEST ONLY partial native-like bytes; not scanner proof"
    with engine.begin() as connection:
        record_submission(connection, job_id, worker_id, value["epoch"], "opaque-test-external-run")
        digest = append_output(connection, config, job_id, worker_id, value["epoch"], raw)
    assert digest == hashlib.sha256(raw).hexdigest()
    with engine.connect() as connection:
        row = (
            connection.execute(select(chunks).where(chunks.c.job_id == job["id"])).mappings().one()
        )
        assert raw not in row["ciphertext"]
        assert (
            AESGCM(bytes.fromhex(config.evidence_key.get_secret_value())).decrypt(
                row["nonce"], row["ciphertext"], f"aegistrace:job:{job_id}:0".encode()
            )
            == raw
        )
    with engine.begin() as connection:
        connection.execute(jobs.update().where(jobs.c.id == job["id"]).values(lease_until=0))
        assert reconcile(connection, job_id) == "unknown"
    with engine.begin() as connection:
        assert start_job(connection, config, job_id, uuid4()) is None
        with pytest.raises(PolicyError):
            append_output(connection, config, job_id, worker_id, value["epoch"], raw)
    with engine.connect() as connection:
        assert connection.execute(select(chunks).where(chunks.c.job_id == job["id"])).first()


def test_stop_before_start_prevents_dispatch_and_stop_during_work(policy_context):
    client, engine, config = policy_context
    base, headers, _, _, job = queued(policy_context)
    client.post(base + "/controls/stop", headers=headers())
    with engine.begin() as connection:
        assert reconcile(connection, UUID(job["id"])) == "cancelled"
        assert start_job(connection, config, UUID(job["id"]), uuid4()) is None


def test_worker_cannot_claim_completed_before_normalization(policy_context):
    _, engine, config = policy_context
    *_, job = queued(policy_context)
    worker = uuid4()
    with engine.begin() as connection:
        value = start_job(connection, config, UUID(job["id"]), worker)
        assert value is not None
        assert not job_heartbeat(connection, UUID(job["id"]), worker, value["epoch"])
        with pytest.raises(ValueError):
            finish_job(connection, UUID(job["id"]), worker, value["epoch"], "completed", True)
        assert (
            finish_job(connection, UUID(job["id"]), worker, value["epoch"], "partial", True)
            == "partial"
        )


def test_expired_unstarted_claim_and_output_retention(policy_context):
    _, engine, config = policy_context
    *_, job = queued(policy_context)
    worker = uuid4()
    with engine.begin() as connection:
        value = start_job(connection, config, UUID(job["id"]), worker)
        append_output(
            connection, config, UUID(job["id"]), worker, value["epoch"], b"TEST ONLY retention"
        )
        connection.execute(chunks.update().where(chunks.c.job_id == job["id"]).values(expires_at=0))
        assert purge_expired_output(connection) == 1
        assert (
            finish_job(connection, UUID(job["id"]), worker, value["epoch"], "partial", True)
            == "partial"
        )
    # A separate unstarted job expires without consuming a second execution attempt.
    with engine.begin() as connection:
        connection.execute(buckets.update().values(updated_at=buckets.c.updated_at - 10))
    *_, later = queued(policy_context)
    with engine.begin() as connection:
        payload = dict(
            connection.execute(
                select(claims.c.payload).where(claims.c.id == later["claim_id"])
            ).scalar_one()
        )
        payload["deadline"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
        connection.execute(
            claims.update().where(claims.c.id == later["claim_id"]).values(payload=payload)
        )
        assert reconcile(connection, UUID(later["id"])) == "failed"


@pytest.mark.services
def test_postgresql_outbox_and_actual_celery_job_redelivery(policy_context):
    if os.environ.get("RUN_SERVICE_TESTS") != "1":
        pytest.skip("requires actual PostgreSQL and running Redis/Celery")
    _, engine, config = policy_context
    # Other service-marked tests share the disposable database and global bucket.
    with engine.begin() as connection:
        connection.execute(buckets.update().values(tokens=1.0, updated_at=time.time()))
    *_, job = queued(policy_context)
    from aegistrace.settings import Settings

    worker = create_worker(Settings())
    deliveries = []

    def publish(job_id):
        deliveries.append(worker.send_task("aegistrace.jobs.consume", args=[job_id], retry=False))

    assert publish_pending(engine, publish) >= 1
    assert deliveries[-1].get(timeout=20) == "blocked"
    duplicate = worker.send_task("aegistrace.jobs.consume", args=[job["id"]], retry=False)
    assert duplicate.get(timeout=20).startswith("not-started")
    with engine.connect() as connection:
        row = connection.execute(select(jobs).where(jobs.c.id == job["id"])).mappings().one()
        assert row["attempt"] == 1 and row["state"] == "blocked"

"""Durable web-scan artifact linkage; input bytes are explicitly synthetic test data."""

import hashlib
import secrets
from uuid import UUID, uuid4

from aegistrace.api_schema import resources
from aegistrace.approval_schema import claims
from aegistrace.evidence_schema import objects
from aegistrace.job_schema import jobs
from aegistrace.jobs import start_job
from aegistrace.schema_v1 import evidence_references, tool_runs
from aegistrace_workers.jobs import _record_import
from pydantic import SecretStr
from sqlalchemy import select
from test_approvals import prepared, review

pytest_plugins = ("test_policy",)


def _queued(context):
    client, _, config = context
    if config.evidence_key is None:
        config.evidence_key = SecretStr(secrets.token_hex(32))
    base, headers, approval, _ = prepared(context)
    review(context, base, headers, approval)
    response = client.post(
        base + "/scan-jobs",
        json={"approval_id": approval["id"], "action_digest": approval["action_digest"]},
        headers=headers(),
    )
    assert response.status_code == 202, response.text
    return response.json()


def test_web_worker_artifact_is_durable_encrypted_and_importable(policy_context):
    """Synthetic output verifies linkage only; it is not scanner evidence."""
    _, engine, config = policy_context
    job = _queued(policy_context)
    worker = uuid4()
    with engine.begin() as connection:
        started = start_job(connection, config, UUID(job["id"]), worker)
        assert started is not None
        claim_payload = connection.execute(
            select(claims.c.payload).where(claims.c.id == job["claim_id"])
        ).scalar_one()
        claim = dict(claim_payload)
        claim["action"] = dict(claim["action"])
        claim["action"].update(tool="OWASP ZAP", template="zap.active.v1", evidence_ids=[])
        raw = b'{"site":[],"TEST ONLY":true}'
        import_id = _record_import(
            connection,
            config,
            UUID(job["id"]),
            worker,
            started,
            claim,
            "2.16.0",
            raw,
        )
        imported = connection.execute(
            select(resources.c.payload).where(resources.c.id == str(import_id))
        ).scalar_one()
        assert imported["state"] == "pending-ingestion"
        assert imported["request"]["format"] == "zap-alerts-json"
        evidence_id = UUID(imported["request"]["evidence_id"])
        reference = connection.execute(
            select(evidence_references.c.payload).where(
                evidence_references.c.id == str(evidence_id)
            )
        ).scalar_one()
        source_run = connection.execute(
            select(tool_runs.c.payload).where(tool_runs.c.id == reference["run_id"])
        ).scalar_one()
        stored = connection.execute(
            select(objects).where(objects.c.id == str(evidence_id))
        ).mappings().one()
        state = connection.execute(select(jobs.c.state).where(jobs.c.id == job["id"])).scalar_one()
        assert state == "running"
        assert source_run["mode"] == "live" and source_run["state"] == "completed"
        assert reference["sha256"] == hashlib.sha256(raw).hexdigest()
        assert raw not in stored["ciphertext"]

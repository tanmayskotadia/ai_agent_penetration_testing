"""Durable web-scan artifact linkage; input bytes are synthetic test data only."""

import hashlib
from datetime import UTC, datetime
from uuid import UUID, uuid4

from _pytest.monkeypatch import MonkeyPatch
from aegistrace import jobs as job_service
from aegistrace.api_schema import resources
from aegistrace.approval_schema import grants
from aegistrace.domain import ToolRun
from aegistrace.evidence import EvidenceStore
from aegistrace.evidence_schema import objects
from aegistrace.repository import get_record
from aegistrace.schema_v1 import (
    assessments,
    metadata,
    scope_versions,
)
from aegistrace.settings import Settings
from aegistrace_workers import jobs as worker_jobs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import SecretStr
from sqlalchemy import create_engine, select


def test_web_worker_artifact_is_durable_encrypted_and_importable(monkeypatch: MonkeyPatch) -> None:
    """The helper links the live run, encrypted artifact, and pending normalizer import."""
    engine = create_engine("sqlite:///:memory:")
    metadata.create_all(engine)
    config = Settings(
        app_secret=SecretStr("a" * 32),
        database_url="sqlite:///:memory:",
        evidence_key=SecretStr("b" * 64),
    )
    monkeypatch.setattr(job_service, "job_heartbeat", lambda *_args: False)
    monkeypatch.setattr(worker_jobs, "record_request", lambda *_args: None)
    monkeypatch.setattr(EvidenceStore, "event", staticmethod(lambda *_args: None))
    assessment_id, scope_id, policy_id, approval_id = (uuid4() for _ in range(4))
    job_id, worker_id = uuid4(), uuid4()
    scope_payload = {
        "id": str(scope_id),
        "assessment_id": str(assessment_id),
        "revision": 1,
        "targets": ["https://app.example.test/"],
        "exclusions": [],
        "authorization_reference": None,
        "valid_until": None,
        "mode": "recorded-import",
    }
    approval_payload = {
        "scope_id": str(scope_id),
        "scope_revision": 1,
    }
    claim = {
        "approval_id": str(approval_id),
        "action": {"tool": "OWASP ZAP", "template": "zap.active.v1"},
    }
    job = {"assessment_id": str(assessment_id), "epoch": 1}
    raw = b'{"site":[],"TEST ONLY":true}'
    try:
        with engine.begin() as connection:
            connection.execute(
                assessments.insert().values(
                    id=str(assessment_id),
                    owner_id="test-owner",
                    payload={"id": str(assessment_id), "owner_id": "test-owner"},
                )
            )
            connection.execute(
                scope_versions.insert().values(
                    id=str(scope_id),
                    assessment_id=str(assessment_id),
                    revision=1,
                    payload=scope_payload,
                )
            )
            connection.execute(
                grants.insert().values(
                    id=str(approval_id),
                    assessment_id=str(assessment_id),
                    policy_id=str(policy_id),
                    state="consumed",
                    action_digest="0" * 64,
                    payload=approval_payload,
                )
            )
            import_id = worker_jobs._record_import(
                connection,
                config,
                job_id,
                worker_id,
                job,
                claim,
                "2.16.0",
                raw,
            )
            imported = connection.execute(
                select(resources.c.payload).where(resources.c.id == str(import_id))
            ).scalar_one()
            evidence_id = imported["request"]["evidence_id"]
            evidence = get_record(
                connection, "evidence_references", assessment_id, UUID(evidence_id)
            )
            run = get_record(
                connection, "tool_runs", assessment_id, UUID(evidence["run_id"])
            )
            stored = connection.execute(
                select(objects).where(objects.c.id == evidence_id)
            ).mappings().one()
            assert imported["state"] == "pending-ingestion"
            assert imported["mode"] == "recorded-import"
            assert imported["request"]["format"] == "zap-alerts-json"
            assert run["mode"] == "live" and run["state"] == "completed"
            assert ToolRun.model_validate(run).captured_at <= datetime.now(UTC)
            assert evidence["sha256"] == hashlib.sha256(raw).hexdigest()
            assert raw not in stored["ciphertext"]
            assert AESGCM(bytes.fromhex(config.evidence_key.get_secret_value())).decrypt(
                stored["nonce"],
                stored["ciphertext"],
                EvidenceStore.aad(assessment_id, UUID(evidence_id)),
            ) == raw
    finally:
        engine.dispose()

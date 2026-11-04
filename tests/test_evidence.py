"""Private evidence acceptance using handcrafted canaries, never scanner output."""

import hashlib
import os
import secrets
import time
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from aegistrace.api import create_app
from aegistrace.auth import issue_identity, seal
from aegistrace.db import make_engine
from aegistrace.domain import Assessment, EvidenceReference, ReportSnapshot, ScopeVersion, ToolRun
from aegistrace.evidence import EvidenceError, EvidenceStore
from aegistrace.evidence_schema import access_events, objects
from aegistrace.repository import insert_record
from aegistrace.schema_v1 import metadata
from aegistrace.settings import Settings
from fastapi.testclient import TestClient
from sqlalchemy import select


@pytest.fixture
def evidence_context(tmp_path, request):
    settings = Settings(
        _env_file=None,
        app_secret=secrets.token_hex(32),
        evidence_key=secrets.token_hex(32),
        database_url=(
            os.environ["DATABASE_URL"]
            if request.node.get_closest_marker("services")
            else f"sqlite:///{tmp_path / 'evidence.db'}"
        ),
    )
    engine = make_engine(settings)
    metadata.create_all(engine)
    raw = b"TEST ONLY\nAuthorization: Bearer fake-canary-authorization\npassword=fake-canary-password\n<script>alert(1)</script>"
    now = datetime.now(UTC)
    assessment = Assessment(name="Evidence contract test", owner_id="owner", created_at=now)
    scope = ScopeVersion(assessment_id=assessment.id, revision=1, targets=["test-only"])
    run = ToolRun(
        assessment_id=assessment.id,
        scope_id=scope.id,
        tool="Nmap",
        tool_version="test-only",
        mode="recorded-import",
        captured_at=now,
        state="recorded",
    )
    evidence = EvidenceReference(
        assessment_id=assessment.id,
        run_id=run.id,
        sha256=hashlib.sha256(raw).hexdigest(),
        pointer="bytes:0-end",
        pointer_type="byte-range",
        captured_at=now,
    )
    with engine.begin() as connection:
        for collection, record in [
            ("assessments", assessment),
            ("scope_versions", scope),
            ("tool_runs", run),
            ("evidence_references", evidence),
        ]:
            insert_record(connection, collection, record)
    yield settings, engine, assessment, evidence, raw
    engine.dispose()


def test_authenticated_trace_download_and_separate_reviewed_redaction(evidence_context):
    settings, engine, assessment, evidence, raw = evidence_context
    headers = {"Authorization": "Bearer " + issue_identity(settings, "owner", "reviewer")}
    route = f"/api/v1/assessments/{assessment.id}/evidence/{evidence.id}"
    with TestClient(create_app(settings)) as client:
        assert (
            client.put(
                route + "/original",
                content=raw,
                params={"expires_at": (datetime.now(UTC) + timedelta(days=7)).isoformat()},
                headers=headers,
            ).status_code
            == 201
        )
        assert client.get(route + "/original").status_code == 401
        denied = {"Authorization": "Bearer " + issue_identity(settings, "other")}
        assert client.post(route + "/download-ticket", headers=denied).status_code == 404
        ticket = client.post(route + "/download-ticket", headers=headers).json()["ticket"]
        download = client.get(route + "/original", headers=headers | {"X-Download-Ticket": ticket})
        assert download.content == raw and download.headers["Cache-Control"] == "no-store"
        redaction = client.post(route + "/redaction", headers=headers).json()
        assert "fake-canary" not in redaction["snippet"] and "<script>" not in redaction["snippet"]
        with engine.begin() as connection:
            with pytest.raises(EvidenceError):
                EvidenceStore.derivative(connection, assessment.id, evidence.id, "owner")
        assert client.post(route + "/redaction-review", headers=headers).status_code == 200
        with engine.begin() as connection:
            assert (
                EvidenceStore.derivative(connection, assessment.id, evidence.id, "owner")
                == redaction["snippet"]
            )
            row = connection.execute(select(objects)).mappings().one()
            assert raw not in row["ciphertext"]
            assert (
                EvidenceStore(settings).read(connection, assessment.id, evidence.id, "owner") == raw
            )
            assert len(connection.execute(select(access_events)).all()) >= 5


def test_expired_and_cross_resource_tickets_and_identity_rejected(evidence_context):
    settings, engine, assessment, evidence, raw = evidence_context
    with engine.begin() as connection:
        EvidenceStore(settings).put(
            connection,
            assessment.id,
            evidence.id,
            "owner",
            raw,
            datetime.now(UTC) + timedelta(days=1),
        )
    headers = {"Authorization": "Bearer " + issue_identity(settings, "owner")}
    path = f"/api/v1/assessments/{assessment.id}/evidence/{evidence.id}/original"
    with TestClient(create_app(settings)) as client:
        for claims in [
            dict(
                assessment_id=str(assessment.id),
                evidence_id=str(evidence.id),
                subject="owner",
                expires=int(time.time()) - 1,
            ),
            dict(
                assessment_id=str(assessment.id),
                evidence_id=str(UUID(int=1)),
                subject="owner",
                expires=int(time.time()) + 60,
            ),
        ]:
            ticket = seal(settings.app_secret.get_secret_value(), "download", claims)
            assert (
                client.get(path, headers=headers | {"X-Download-Ticket": ticket}).status_code == 403
            )
        assert (
            client.get(
                path, headers={"Authorization": "Bearer forged", "X-Download-Ticket": "forged"}
            ).status_code
            == 401
        )


def test_tamper_hash_retention_and_snapshot_pin(evidence_context):
    settings, engine, assessment, evidence, raw = evidence_context
    store = EvidenceStore(settings)
    with engine.begin() as connection:
        with pytest.raises(EvidenceError):
            store.put(
                connection,
                assessment.id,
                evidence.id,
                "owner",
                raw + b"tampered",
                datetime.now(UTC) + timedelta(days=1),
            )
        store.put(
            connection,
            assessment.id,
            evidence.id,
            "owner",
            raw,
            datetime.now(UTC) + timedelta(days=1),
        )
        with connection.begin_nested() as nested:
            connection.execute(objects.update().values(ciphertext=b"tampered"))
            with pytest.raises(EvidenceError, match="integrity"):
                store.read(connection, assessment.id, evidence.id, "owner")
            nested.rollback()
        connection.execute(
            objects.update().values(
                expires_at=(datetime.now(UTC) - timedelta(seconds=1)).isoformat()
            )
        )
        with pytest.raises(EvidenceError, match="expired"):
            store.read(connection, assessment.id, evidence.id, "owner")
        snapshot = ReportSnapshot(
            assessment_id=assessment.id,
            created_at=datetime.now(UTC),
            source_digest="a" * 64,
            source_ids=[evidence.id],
        )
        insert_record(connection, "report_snapshots", snapshot)
        assert store.purge_expired(connection, assessment.id, "owner") == 0


def test_purge_keeps_reference_and_access_history(evidence_context):
    settings, engine, assessment, evidence, raw = evidence_context
    with engine.begin() as connection:
        store = EvidenceStore(settings)
        store.put(
            connection,
            assessment.id,
            evidence.id,
            "owner",
            raw,
            datetime.now(UTC) + timedelta(seconds=60),
        )
        connection.execute(
            objects.update().values(
                expires_at=(datetime.now(UTC) - timedelta(seconds=1)).isoformat()
            )
        )
        assert store.purge_expired(connection, assessment.id, "owner") == 1
        assert connection.execute(select(objects)).first() is None
        assert connection.execute(select(access_events)).first() is not None


def test_encryption_is_disabled_without_key_and_has_bounded_originals(evidence_context):
    settings, engine, assessment, evidence, _ = evidence_context
    with pytest.raises(EvidenceError):
        EvidenceStore(settings.model_copy(update={"evidence_key": None}))
    with engine.begin() as connection:
        with pytest.raises(EvidenceError):
            EvidenceStore(settings).put(
                connection,
                assessment.id,
                evidence.id,
                "owner",
                b"x" * (2097152 + 1),
                datetime.now(UTC) + timedelta(days=1),
            )


@pytest.mark.services
def test_evidence_storage_and_download_on_postgresql(evidence_context):
    if os.environ.get("RUN_SERVICE_TESTS") != "1":
        pytest.skip("requires actual PostgreSQL")
    test_authenticated_trace_download_and_separate_reviewed_redaction(evidence_context)

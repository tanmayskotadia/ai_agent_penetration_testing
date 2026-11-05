"""Human provenance reviews are append-only and never upgrade test-only evidence."""

import hashlib
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from aegistrace.api_contracts import SourceReviewCreate
from aegistrace.auth import issue_identity
from aegistrace.domain import EvidenceReference, ToolRun
from aegistrace.repository import insert_record

pytest_plugins = ("test_ingestion",)


def test_source_review_contract_requires_exact_digest_and_explicit_provenance():
    value = SourceReviewCreate(
        normalization_id=uuid4(),
        source_sha256="a" * 64,
        decision="verify",
        provenance="test-only",
        rationale="Handcrafted test data is not genuine evidence.",
    )
    assert value.provenance == "test-only"
    with pytest.raises(ValueError):
        SourceReviewCreate(
            normalization_id=uuid4(),
            source_sha256="not-a-hash",
            decision="verify",
            provenance="genuine-permitted-capture",
            rationale="A bounded reviewer explanation.",
        )


def test_source_review_is_bound_to_digest_and_preserves_test_only_label(import_context):
    client, settings = import_context
    reviewer = issue_identity(settings, "source-reviewer", "reviewer")

    def headers(token=reviewer):
        return {
            "Authorization": "Bearer " + token,
            "X-Request-ID": str(uuid4()),
            "Idempotency-Key": str(uuid4()),
        }

    def post(path, body, token=reviewer):
        response = client.post(path, json=body, headers=headers(token))
        assert response.status_code in {200, 201, 202}, response.text
        return response.json()

    assessment = post("/api/v1/assessments", {"name": "TEST ONLY source review"})
    assessment_id = assessment["id"]
    base = f"/api/v1/assessments/{assessment_id}"
    scope = post(base + "/scopes", {"revision": 1, "targets": ["192.0.2.10"]})
    now = datetime.now(UTC)
    run = ToolRun(
        assessment_id=assessment_id,
        scope_id=scope["id"],
        tool="Nmap",
        tool_version="7.95",
        mode="recorded-import",
        captured_at=now,
        state="recorded",
    )
    evidence = EvidenceReference(
        assessment_id=assessment_id,
        run_id=run.id,
        sha256=hashlib.sha256(b"TEST ONLY source bytes").hexdigest(),
        pointer="/",
        pointer_type="whole-file",
        captured_at=now,
    )
    with client.app.state.engine.begin() as connection:
        insert_record(connection, "tool_runs", run)
        insert_record(connection, "evidence_references", evidence)
    imported = post(
        base + "/imports",
        {
            "scope_id": scope["id"],
            "scope_revision": 1,
            "tool": "Nmap",
            "format": "nmap-xml",
            "evidence_id": str(evidence.id),
        },
    )
    from aegistrace.normalization_schema import normalizations

    normalization_id = uuid4()
    payload = {
        "id": str(normalization_id),
        "assessment_id": assessment_id,
        "run_id": str(run.id),
        "evidence_id": str(evidence.id),
        "import_id": imported["id"],
        "source_sha256": evidence.sha256,
        "parser_revision": "nmap-v1",
        "state": "normalized",
        "information_kind": "observed-evidence",
        "captured_at": now.isoformat(),
        "observation_ids": [],
    }
    with client.app.state.engine.begin() as connection:
        connection.execute(
            normalizations.insert().values(
                id=str(normalization_id),
                assessment_id=assessment_id,
                import_id=imported["id"],
                evidence_id=str(evidence.id),
                payload=payload,
            )
        )

    review = post(
        base + "/source-reviews",
        {
            "normalization_id": str(normalization_id),
            "source_sha256": evidence.sha256,
            "decision": "verify",
            "provenance": "test-only",
            "rationale": "Handcrafted test fixture; no genuine scan data is represented.",
        },
    )
    assert review["request"]["provenance_kind"].startswith("human review assertion")
    snapshot = client.get(base + "/coverage", headers=headers()).json()
    source = snapshot["tool_evidence"][0]["source_records"][0]
    assert source["authenticity"] == "test-only-reviewed"
    assert source["source_review_id"] == review["id"]
    assert snapshot["prototype_gate"]["three_verified_network_and_web_imports"]["passed"] is False
    analyst = issue_identity(settings, "source-reviewer", "analyst")
    denied = client.post(
        base + "/source-reviews",
        json={
            "normalization_id": str(normalization_id),
            "source_sha256": evidence.sha256,
            "decision": "verify",
            "provenance": "genuine-permitted-capture",
            "rationale": "Analyst role cannot mark provenance verified.",
        },
        headers=headers(analyst),
    )
    assert denied.status_code == 403

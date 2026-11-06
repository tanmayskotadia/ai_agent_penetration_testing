"""Synthetic reviewer/source records; these tests establish no scanner accuracy."""

from copy import deepcopy
from uuid import uuid4

import pytest
from aegistrace.auth import issue_identity
from aegistrace.pdf_report import render_evidence_report
from aegistrace.report_content import VaptReportContent, build_vapt_content
from test_ingestion import import_context as import_context
from test_nmap import source


def synthetic_report_source():
    observations = [
        {
            "id": "observation-a",
            "asset_id": "asset-a",
            "evidence_id": "evidence-a",
            "run_id": "run-a",
            "source_tool": "Nikto",
            "title": "TEST ONLY header observation",
            "source_severity": "medium",
            "validation_state": "suspected",
            "confidence": None,
        },
        {
            "id": "observation-b",
            "asset_id": "asset-b",
            "evidence_id": "evidence-b",
            "run_id": "run-b",
            "source_tool": "OWASP ZAP",
            "title": "TEST ONLY second source",
            "source_severity": "low",
            "validation_state": "unknown",
            "cvss_score": None,
        },
    ]
    request = {
        "finding_id": "report-finding-test",
        "observation_ids": [value["id"] for value in observations],
        "title": "TEST ONLY reviewed multi-asset finding",
        "description": "A human reviewer grouped two synthetic observations for this report test.",
        "technical_impact": "TEST ONLY technical consequence described by reviewer.",
        "business_impact": "TEST ONLY possible effect on test service availability.",
        "remediation": "TEST ONLY review the configuration and verify it against the cited baseline before applying changes.",
        "references": ["TEST ONLY internal configuration baseline"],
        "recorded_by": "test-reviewer",
        "recorded_at": "2026-11-07T00:00:00Z",
        "rationale": "Synthetic source review for report content regression.",
    }
    return {
        "assessment_id": str(uuid4()),
        "created_at": "2026-11-07T00:00:00Z",
        "scope": {
            "id": "scope-test",
            "revision": 1,
            "targets": ["asset-a.test", "asset-b.test"],
            "mode": "recorded-import",
        },
        "assets": [
            {"id": "asset-a", "identifier": "asset-a.test"},
            {"id": "asset-b", "identifier": "asset-b.test"},
        ],
        "observations": observations,
        "report_findings": [{"id": "review-record-test", "revision": 1, "request": request}],
        "tool_runs": [
            {"id": "run-a", "tool": "Nikto", "mode": "recorded-import", "state": "recorded"},
            {"id": "run-b", "tool": "OWASP ZAP", "mode": "recorded-import", "state": "failed"},
        ],
        "result_revisions": [
            {
                "run_id": "run-b",
                "state": "partial",
                "parser_code": "test-failure",
                "warnings": ["TEST ONLY failed collection"],
                "mode": "recorded-import",
            }
        ],
        "action_approvals": [{"id": "denied-test", "state": "denied", "action_digest": "a" * 64}],
        "evidence_references": [
            {
                "id": "evidence-a",
                "sha256": "b" * 64,
                "pointer": "/alerts/0",
                "pointer_type": "json-pointer",
                "captured_at": "2026-11-07T00:00:00Z",
            }
        ],
        "finding_reviews": [],
        "correlation": {},
        "coverage": {"gaps": ["TEST ONLY incomplete coverage"]},
        "limitations": ["All report contents are synthetic tests only."],
    }


def test_populated_multi_asset_contract_and_counts_reconcile():
    source_value = synthetic_report_source()
    content = build_vapt_content(source_value)
    assert content["content_revision"] == "1.1"
    assert content["summary_counts"]["reviewer_finding_count"] == 1
    assert content["summary_counts"]["source_observation_count"] == 2
    assert content["summary_counts"]["source_occurrence_count"] == 2
    finding = content["detailed_findings"][0]
    assert finding["asset_ids"] == ["asset-a", "asset-b"]
    assert finding["validation_state"] == "mixed-review-states"
    assert finding["remediation"].startswith("TEST ONLY")
    assert finding["content_provenance"]["reviewer"] == "test-reviewer"
    assert finding["source_records"][1]["cvss_score"] is None
    assert content["approvals_and_decisions"]["action_approvals"][0]["state"] == "denied"
    assert content["execution_summary"][0]["state"] == "partial"
    corrupted = deepcopy(content)
    corrupted["summary_counts"]["reviewer_finding_count"] = 2
    with pytest.raises(ValueError, match="reconcile"):
        VaptReportContent.model_validate(corrupted)
    pdf = render_evidence_report(
        {**source_value, "content": content}, source_value["observations"], {}
    )
    assert b"Detailed findings and source observations" in pdf
    assert b"reviewer-finding" in pdf and b"Remediation:" in pdf and b"denied-test" in pdf
    assert b"Observation 1: TEST ONLY header observation" not in pdf


def test_empty_partial_and_unknown_are_not_clean_or_confirmed():
    source_value = synthetic_report_source()
    source_value.update(observations=[], report_findings=[], assets=[])
    content = build_vapt_content(source_value)
    assert content["detailed_findings"] == []
    assert content["summary_counts"]["reviewer_finding_count"] == 0
    assert content["assessment_complete"] is False
    assert content["impact_and_remediation"]["business_impact"] == "unknown"
    assert content["execution_summary"][0]["state"] == "partial"


def test_report_input_freezes_revisions_and_rejects_stale_or_unowned_sources(import_context):
    client, config = import_context
    base, _, imported, _, _, _ = source(import_context)

    def headers(role="reviewer"):
        return {
            "Authorization": "Bearer " + issue_identity(config, "owner", role),
            "X-Request-ID": str(uuid4()),
            "Idempotency-Key": str(uuid4()),
        }

    normalized = client.post(
        base + "/imports/" + imported["id"] + "/normalize-nmap", json={}, headers=headers()
    ).json()
    body = {
        "observation_ids": normalized["observation_ids"],
        "title": "TEST ONLY reviewed source",
        "description": "TEST ONLY source-backed reviewer description.",
        "technical_impact": "TEST ONLY technical impact",
        "business_impact": "TEST ONLY business impact",
        "remediation": "TEST ONLY correct the reviewed configuration and validate the outcome.",
        "references": ["TEST ONLY baseline"],
        "rationale": "TEST ONLY content review; no exploitation proof.",
    }
    path = base + "/report-findings"
    assert client.post(path, json=body, headers=headers("analyst")).status_code == 403
    assert (
        client.post(
            path, json=body | {"observation_ids": [str(uuid4())]}, headers=headers()
        ).status_code
        == 404
    )
    created = client.post(path, json=body, headers=headers())
    assert created.status_code == 201, created.text
    value = created.json()
    assert client.post(path, json=body, headers=headers()).status_code == 409

    def freeze():
        result = client.post(
            base + "/result-exports",
            json={"revision_ids": [normalized["result_revision_id"]]},
            headers=headers(),
        )
        assert result.status_code == 201, result.text
        return client.get(base + "/result-exports/" + result.json()["id"], headers=headers()).json()

    first = freeze()
    assert (
        first["snapshot"]["content"]["detailed_findings"][0]["description"] == body["description"]
    )
    assert first["snapshot"]["evidence_references"][0]["sha256"]
    changed = client.post(
        path,
        json=body
        | {
            "finding_id": value["request"]["finding_id"],
            "expected_revision": 1,
            "description": "TEST ONLY revised description",
        },
        headers=headers(),
    )
    assert changed.status_code == 201, changed.text
    second = freeze()
    assert second["sha256"] != first["sha256"]
    assert (
        second["snapshot"]["content"]["detailed_findings"][0]["description"]
        == "TEST ONLY revised description"
    )
    assert client.get(base + "/result-exports/" + first["id"], headers=headers()).json() == first
    assert len(client.get(path, headers=headers()).json()["history"]) == 2
    assert second["snapshot"]["observations"] == first["snapshot"]["observations"]

"""Synthetic reviewer/source records; these tests establish no scanner accuracy."""

from copy import deepcopy
from uuid import uuid4

import pytest
from aegistrace.api_contracts import ReportFindingCreate
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
        "technical_impact_basis": "TEST ONLY source observations describe the affected configuration.",
        "business_impact": "TEST ONLY possible effect on test service availability.",
        "business_impact_basis": "TEST ONLY assumes the service is used by a customer workflow; verify with the asset owner.",
        "remediation": "TEST ONLY review the configuration and verify it against the cited baseline before applying changes.",
        "remediation_basis": "TEST ONLY source title identifies the configuration area; exact implementation remains unverified.",
        "remediation_owner": "TEST ONLY platform team",
        "verification_steps": [
            "TEST ONLY inspect the configuration in a non-production environment.",
            "TEST ONLY rerun the relevant safe check and compare the result.",
        ],
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
        "correlation": {
            "contextual_risk_ranking": {
                "ranked_observations": [
                    {
                        "id": "observation-a",
                        "observation_id": "observation-a",
                        "source_severity": "medium",
                        "priority": {
                            "local_priority_index": None,
                            "review_attention": "standard-review",
                            "factors": {
                                "source_cvss": {
                                    "value": 6.1,
                                    "version": "3.1",
                                    "state": "source-reported",
                                },
                                "exposure": {"value": "internal", "state": "recorded-context"},
                            },
                            "missing_context": ["exploitability", "asset_criticality"],
                        },
                    }
                ]
            }
        },
        "coverage": {"gaps": ["TEST ONLY incomplete coverage"]},
        "limitations": ["All report contents are synthetic tests only."],
    }


def test_populated_multi_asset_contract_and_counts_reconcile():
    source_value = synthetic_report_source()
    content = build_vapt_content(source_value)
    assert content["content_revision"] == "1.2"
    assert content["summary_counts"]["reviewer_finding_count"] == 1
    assert content["summary_counts"]["source_observation_count"] == 2
    assert content["summary_counts"]["source_occurrence_count"] == 2
    finding = content["detailed_findings"][0]
    assert finding["asset_ids"] == ["asset-a", "asset-b"]
    assert finding["validation_state"] == "mixed-review-states"
    assert finding["remediation"].startswith("TEST ONLY")
    assert finding["technical_impact_basis"].startswith("TEST ONLY")
    assert finding["business_impact_basis"].startswith("TEST ONLY")
    assert len(finding["verification_steps"]) == 2
    assert finding["remediation_owner"] == "TEST ONLY platform team"
    assert finding["content_provenance"]["reviewer"] == "test-reviewer"
    assert finding["source_records"][1]["cvss_score"] is None
    assert content["approvals_and_decisions"]["action_approvals"][0]["state"] == "denied"
    assert content["execution_summary"][0]["state"] == "partial"
    assert (
        "reviewer-authored report findings group those observations" in content["executive_summary"]
    )
    assert "Partial or failed source processing" in content["executive_summary"]
    assert "not independently verified; no live scan is claimed" in content["executive_summary"]
    assert "observation-a (source severity medium" in content["executive_summary"]
    assert "rationale: source_cvss=6.1 v3.1; exposure=internal" in content["executive_summary"]
    assert "unknown context: exploitability, asset_criticality" in content["executive_summary"]
    corrupted = deepcopy(content)
    corrupted["summary_counts"]["reviewer_finding_count"] = 2
    with pytest.raises(ValueError, match="reconcile"):
        VaptReportContent.model_validate(corrupted)
    pdf = render_evidence_report(
        {**source_value, "content": content}, source_value["observations"], {}
    )
    assert b"Detailed findings and source observations" in pdf
    assert b"reviewer-finding" in pdf and b"Evidence basis for technical impact:" in pdf
    assert b"Observed basis for remediation:" in pdf
    assert b"Remediation owner \\(reviewer supplied\\)" in pdf
    assert b"TEST ONLY platform team" in pdf
    assert b"Verification/retest steps:" in pdf and b"denied-test" in pdf
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


def test_business_impact_and_remediation_require_basis_and_verification():
    base = {
        "observation_ids": [str(uuid4())],
        "title": "TEST ONLY report finding",
        "description": "TEST ONLY source-backed description.",
        "rationale": "TEST ONLY analyst review rationale.",
    }
    with pytest.raises(ValueError, match="business impact requires"):
        ReportFindingCreate.model_validate(base | {"business_impact": "TEST ONLY impact"})
    with pytest.raises(ValueError, match="technical impact requires"):
        ReportFindingCreate.model_validate(base | {"technical_impact": "TEST ONLY impact"})
    with pytest.raises(ValueError, match="remediation requires"):
        ReportFindingCreate.model_validate(base | {"remediation": "TEST ONLY action"})
    with pytest.raises(ValueError, match="remediation requires"):
        ReportFindingCreate.model_validate(
            base
            | {
                "remediation": "TEST ONLY action",
                "remediation_basis": "TEST ONLY observed basis",
            }
        )
    valid = ReportFindingCreate.model_validate(
        base
        | {
            "business_impact": "TEST ONLY impact",
            "business_impact_basis": "TEST ONLY context assumption",
            "technical_impact": "TEST ONLY technical effect",
            "technical_impact_basis": "TEST ONLY supporting source observations",
            "remediation": "TEST ONLY action",
            "remediation_basis": "TEST ONLY observed basis",
            "remediation_owner": "TEST ONLY operations team",
            "verification_steps": ["TEST ONLY verify safely"],
        }
    )
    assert valid.business_impact_basis == "TEST ONLY context assumption"
    assert valid.technical_impact_basis == "TEST ONLY supporting source observations"
    assert valid.verification_steps == ["TEST ONLY verify safely"]
    assert valid.remediation_owner == "TEST ONLY operations team"


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
        "technical_impact_basis": "TEST ONLY source evidence indicates this configuration.",
        "business_impact": "TEST ONLY business impact",
        "business_impact_basis": "TEST ONLY synthetic context assumption.",
        "remediation": "TEST ONLY correct the reviewed configuration and validate the outcome.",
        "remediation_basis": "TEST ONLY relevant source title and observation evidence.",
        "remediation_owner": "TEST ONLY platform team",
        "verification_steps": ["TEST ONLY validate the change with a safe repeat check."],
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

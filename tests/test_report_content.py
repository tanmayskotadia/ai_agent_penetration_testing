from uuid import uuid4

from aegistrace.pdf_report import render_evidence_report
from aegistrace.report_content import build_vapt_content


def test_vapt_content_emits_required_sections_with_unknowns_not_guesses():
    source = {
        "assessment_id": str(uuid4()),
        "created_at": "2026-11-05T10:00:00+00:00",
        "scope": {
            "id": str(uuid4()),
            "revision": 2,
            "targets": ["app.test.invalid"],
            "exclusions": [],
            "authorization_reference": "synthetic-test-only",
            "mode": "recorded-import",
        },
        "assets": [{"id": "asset-test", "identifier": "app.test.invalid", "kind": "host"}],
        "tool_runs": [
            {"id": "run-test", "tool": "Nmap", "mode": "recorded-import", "state": "recorded"}
        ],
        "observations": [{"source_severity": "High"}],
        "findings": [],
        "occurrences": [],
        "decisions": [],
        "approvals": [],
        "correlation": {
            "correlation_method": "exact CVE",
            "cross_tool_candidate_groups": [],
            "reviewed_clusters": [
                {
                    "cluster_id": "review-cluster-test",
                    "review_state": "reviewer-merged",
                    "information_kind": "reviewer-decision",
                    "rationale": "synthetic test-only duplicate decision",
                    "observation_ids": ["obs-test-a", "obs-test-b"],
                    "asset_ids": ["asset-a", "asset-b"],
                    "source_tools": ["Nikto", "OWASP ZAP"],
                    "occurrence_count": 2,
                }
            ],
            "contextual_risk_ranking": {
                "policy": "aegistrace-context-priority-v1",
                "ranked_observations": [],
            },
        },
        "coverage": {"gaps": ["synthetic test: live coverage unknown"]},
    }

    content = build_vapt_content(source)
    snapshot = {
        **source,
        "content": content,
        "coverage_snapshot": source["coverage"],
        "limitations": content["limitations"],
    }
    pdf = render_evidence_report(snapshot, [], {})

    assert content["assessment_complete"] is False
    assert (
        content["scope"]["authorization_status"]
        == "participant-supplied; not independently verified"
    )
    assert content["source_severity_distribution"] == {"high": 1}
    assert content["impact_and_remediation"]["business_impact"] == "unknown"
    assert content["reviewed_correlations"][0]["occurrence_count"] == 2
    for heading in (
        b"Executive summary",
        b"Assessment scope and rules of engagement",
        b"Methodology",
        b"Asset inventory",
        b"Tool execution summary",
        b"Severity distribution (source-reported)",
        b"Prioritized observations and reviewer findings",
        b"Reviewer correlation decisions",
        b"Business impact, recommendations and references",
        b"Human approvals and decisions",
        b"Assumptions, scan failures and limitations",
        b"Evidence manifest",
    ):
        escaped = heading.replace(b"(", b"\\(").replace(b")", b"\\)")
        assert escaped in pdf

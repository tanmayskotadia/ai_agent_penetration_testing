from uuid import uuid4

from aegistrace.pdf_report import TEXT_WIDTH, _advance, _paginate, _wrap, render_evidence_report
from aegistrace.report_content import SCOPE_TRACE_LAYOUT, build_vapt_content


def test_pdf_keeps_multiline_finding_heading_with_body():
    heading = [("Long title", 1), ("continued title", 1), ("Finding ID: example", 2)]
    pages = _paginate([("Previous text", 2)] * 48 + heading + [("Details", 2)] * 60)
    assert pages[1][:3] == heading
    assert [line for page in pages for line in page].count(("Details", 2)) == 60


def test_pdf_wraps_long_wide_source_text_without_dropping_characters():
    text = "W" * 160
    lines = _wrap(text, width=68)
    assert "".join(lines) == text
    assert max(_advance(line) * 10 for line in lines) <= TEXT_WIDTH * 1000


def test_pdf_links_only_frozen_evidence_and_keeps_hostile_text_inert():
    observations = [
        {"id": "observation-1", "title": "Café (demo)", "evidence_id": "source-1"},
        {"id": "observation-2", "title": "Other source", "evidence_id": "absent"},
    ]
    source = {
        "assessment_id": str(uuid4()),
        "created_at": "2026-11-05T10:00:00+00:00",
        "observations": observations,
        "evidence_references": [{"id": "source-1"}],
    }
    content = build_vapt_content(source)
    baseline = render_evidence_report({"content": content}, observations, {})
    content["evidence_manifest"] = []
    missing = render_evidence_report({"content": content}, observations, {})
    assert baseline.count(b"/Subtype /Link") == missing.count(b"/Subtype /Link") + 1
    assert b"Evidence source source-1" in baseline
    assert b"Caf\xe9 \\(demo\\)" in baseline
    assert b"/WinAnsiEncoding" in baseline
    assert b"/URI" not in baseline


def test_pdf_displays_each_selected_scope_and_binds_it_to_the_source_run():
    scopes = [
        {
            "id": f"scope-{revision}",
            "revision": revision,
            "targets": [f"lab-{revision}.test.invalid"],
            "exclusions": [f"excluded-{revision}.test.invalid"],
            "mode": "recorded-import",
        }
        for revision in (1, 2)
    ]
    runs = [
        {"id": f"run-{index}", "scope_id": scope["id"], "tool": "Nmap"}
        for index, scope in enumerate(scopes, 1)
    ]
    source = {
        "assessment_id": str(uuid4()),
        "created_at": "2026-11-05T10:00:00+00:00",
        "scope": scopes[-1],
        "scope_snapshots": scopes,
        "tool_runs": runs,
        "result_revisions": [
            {"run_id": run["id"], "tool": run["tool"], "state": "normalized"} for run in runs
        ],
        "coverage_snapshot": {},
    }
    snapshot = {**source, "content": build_vapt_content(source)}
    legacy_pdf = render_evidence_report(snapshot, [], {})
    assert b"Coverage and capabilities at export time" in legacy_pdf
    assert b"Targets: lab-1.test.invalid" not in legacy_pdf
    pdf = render_evidence_report({**snapshot, "report_layout_revision": SCOPE_TRACE_LAYOUT}, [], {})
    assert b"Assessment-wide coverage and capabilities" in pdf
    scope_section = pdf.split(b"(Assessment scope and rules of engagement)", 1)[1].split(
        b"(Standards and reference coverage)", 1
    )[0]
    for revision in (1, 2):
        assert f"(Scope revision: {revision})".encode() in scope_section
        assert f"(Targets: lab-{revision}.test.invalid)".encode() in scope_section
        assert f"(Exclusions: excluded-{revision}.test.invalid)".encode() in scope_section
    runs_section = pdf.split(b"(Frozen source runs)", 1)[1]
    first_run, second_run = runs_section.split(b"(Source 2:", 1)
    assert b"(Scope revision: 1 | Scope ID: scope-1)" in first_run
    assert b"(Scope revision: 2 | Scope ID: scope-2)" in second_run
    assert b"(Scope revision: 2 | Scope ID: scope-2)" not in first_run


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

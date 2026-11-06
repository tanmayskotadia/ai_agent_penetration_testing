"""One synthetic assessment traverses the minimum prototype; never scanner evidence."""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from aegistrace.auth import issue_identity

NMAP_TEST_XML = (
    b'<nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05">'
    b'<host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/>'
    b'<ports><port protocol="tcp" portid="443"><state state="open"/>'
    b'<service name="https"/></port></ports></host>'
    b'<runstats><finished exit="success"/></runstats></nmaprun>'
)

pytest_plugins = ("test_ingestion",)


def test_one_assessment_runs_test_only_vertical_slice(import_context):
    client, settings = import_context
    token = issue_identity(settings, "t30-test-owner", "reviewer")

    def headers():
        return {
            "Authorization": "Bearer " + token,
            "X-Request-ID": str(uuid4()),
            "Idempotency-Key": str(uuid4()),
        }

    def post(path, body):
        response = client.post(path, json=body, headers=headers())
        assert response.status_code in {200, 201, 202}, response.text
        return response.json()

    assessment = post("/api/v1/assessments", {"name": "T30 synthetic vertical slice; test only"})
    base = "/api/v1/assessments/" + assessment["id"]
    scope = post(
        base + "/scopes",
        {
            "revision": 1,
            "targets": [
                "192.0.2.10",
                "https://example.invalid/app",
                "https://other.example.invalid/app",
            ],
            "exclusions": ["https://admin.example.invalid/app"],
            "authorization_reference": "TEST ONLY; synthetic fixture; no scan permission",
        },
    )
    plan = post(
        base + "/plans/intake",
        {
            "message": "Review network, web, API and Nikto evidence, then actively scan and exploit the app",
            "conversation_id": str(uuid4()),
            "scope_id": scope["id"],
            "scope_revision": 1,
        },
    )
    proposal = plan["request"]["proposal"]
    assert plan["mode"] == "request-only"
    assert "active-validation-not-enabled" in proposal["blockers"]
    assert all(step.get("mode") == "recorded-import" for step in proposal["steps"])
    excluded_plan = post(
        base + "/plans/intake",
        {
            "message": "Review https://admin.example.invalid/app with OWASP ZAP",
            "conversation_id": str(uuid4()),
            "scope_id": scope["id"],
            "scope_revision": 1,
        },
    )
    assert excluded_plan["state"] == "blocked"
    assert "target-outside-scope" in excluded_plan["request"]["proposal"]["blockers"]

    zap = json.dumps(
        {
            "alerts": [
                {
                    "id": "10021",
                    "pluginId": "10021",
                    "alertRef": "10021-1",
                    "alert": "TEST ONLY explicit source reference",
                    "cve": "CVE-2024-12345",
                    "cweid": 79,
                    "riskdesc": "Low",
                    "confidence": "Medium",
                    "instances": [
                        {
                            "uri": "https://example.invalid/app/check",
                            "method": "GET",
                        }
                    ],
                },
                {
                    "id": "10022",
                    "pluginId": "10022",
                    "alertRef": "10022-1",
                    "alert": "TEST ONLY same CVE on different endpoint",
                    "cve": "CVE-2024-12345",
                    "cweid": 79,
                    "instances": [
                        {
                            "uri": "https://example.invalid/app/other",
                            "method": "GET",
                        }
                    ],
                },
                {
                    "id": "10023",
                    "pluginId": "10023",
                    "alertRef": "10023-1",
                    "alert": "TEST ONLY same CVE on different parameter",
                    "cve": "CVE-2024-12345",
                    "cweid": 79,
                    "instances": [
                        {
                            "uri": "https://example.invalid/app/check?account=fixture-secret",
                            "method": "GET",
                        }
                    ],
                },
                {
                    "id": "10024",
                    "pluginId": "10024",
                    "alertRef": "10024-1",
                    "alert": "TEST ONLY same CVE on different asset",
                    "cve": "CVE-2024-12345",
                    "cweid": 79,
                    "instances": [
                        {
                            "uri": "https://other.example.invalid/app/check",
                            "method": "GET",
                        }
                    ],
                },
            ]
        }
    ).encode()
    nikto = json.dumps(
        [
            {
                "host": "example.invalid",
                "vulnerabilities": [
                    {
                        "id": "OSVDB-12345",
                        "references": "CVE-2024-12345; CWE-79",
                        "method": "GET",
                        "url": "https://example.invalid/app/check",
                        "msg": "TEST ONLY same explicitly referenced observation",
                    }
                ],
            }
        ]
    ).encode()
    openapi = json.dumps(
        {
            "openapi": "3.0.3",
            "info": {"title": "TEST ONLY API", "version": "1"},
            "servers": [{"url": "https://example.invalid/app"}],
            "paths": {
                "/check": {"get": {"responses": {"200": {"description": "TEST ONLY response"}}}}
            },
        }
    ).encode()
    captures = (
        ("Nmap", "nmap-xml", "7.95", NMAP_TEST_XML, "normalize-nmap"),
        ("OWASP ZAP", "zap-alerts-json", "2.16.0", zap, "normalize-zap"),
        ("Nikto", "nikto-json", "2.6.1", nikto, "normalize-nikto"),
        ("OpenAPI", "openapi-json", "3.0.3", openapi, "normalize-openapi"),
    )
    for tool, format_name, version, raw, normalizer in captures:
        captured_at = datetime.now(UTC)
        run = post(
            base + "/runs",
            {
                "scope_id": scope["id"],
                "tool": tool,
                "tool_version": version,
                "captured_at": captured_at.isoformat(),
            },
        )
        evidence = post(
            base + "/runs/" + run["id"] + "/evidence",
            {
                "sha256": hashlib.sha256(raw).hexdigest(),
                "pointer": "/",
                "pointer_type": "whole-file",
                "captured_at": captured_at.isoformat(),
            },
        )
        uploaded = client.put(
            base + "/evidence/" + evidence["id"] + "/original",
            content=raw,
            params={"expires_at": (captured_at + timedelta(days=1)).isoformat()},
            headers=headers(),
        )
        assert uploaded.status_code == 201, uploaded.text
        imported = post(
            base + "/imports",
            {
                "scope_id": scope["id"],
                "scope_revision": 1,
                "tool": tool,
                "format": format_name,
                "evidence_id": evidence["id"],
            },
        )
        result = post(base + "/imports/" + imported["id"] + "/" + normalizer, {})
        assert result["state"] == "normalized", result
        if tool != "OpenAPI":
            review = post(
                base + "/source-reviews",
                {
                    "normalization_id": result["id"],
                    "source_sha256": result["source_sha256"],
                    "decision": "verify",
                    "provenance": "test-only",
                    "rationale": "Handcrafted end-to-end fixture; not a genuine or permitted scan.",
                },
            )
            assert review["request"]["provenance"] == "test-only"

    # A corrupted recorded result must be retained as an explicit quarantined
    # failure, never converted into clean coverage or a successful empty scan.
    failed_raw = b"<nmaprun><host><ports>"
    failed_at = datetime.now(UTC)
    failed_run = post(
        base + "/runs",
        {
            "scope_id": scope["id"],
            "tool": "Nmap",
            "tool_version": "7.95",
            "captured_at": failed_at.isoformat(),
        },
    )
    failed_evidence = post(
        base + "/runs/" + failed_run["id"] + "/evidence",
        {
            "sha256": hashlib.sha256(failed_raw).hexdigest(),
            "pointer": "/",
            "pointer_type": "whole-file",
            "captured_at": failed_at.isoformat(),
        },
    )
    failed_upload = client.put(
        base + "/evidence/" + failed_evidence["id"] + "/original",
        content=failed_raw,
        params={"expires_at": (failed_at + timedelta(days=1)).isoformat()},
        headers=headers(),
    )
    assert failed_upload.status_code == 201, failed_upload.text
    failed_import = post(
        base + "/imports",
        {
            "scope_id": scope["id"],
            "scope_revision": 1,
            "tool": "Nmap",
            "format": "nmap-xml",
            "evidence_id": failed_evidence["id"],
        },
    )
    failure = post(base + "/imports/" + failed_import["id"] + "/normalize-nmap", {})
    assert failure["state"] == "quarantined"

    assessment_response = client.get(base, headers=headers())
    assert assessment_response.status_code == 200, assessment_response.text
    coverage_response = client.get(base + "/coverage", headers=headers())
    assert coverage_response.status_code == 200, coverage_response.text
    snapshot = coverage_response.json()
    assert snapshot["prototype_gate"]["three_verified_network_and_web_imports"]["passed"] is False
    assert any(
        source["state"] == "quarantined"
        for tool in snapshot["tool_evidence"]
        for source in tool["source_records"]
    )
    authenticity = {
        tool["name"]: [source["authenticity"] for source in tool["source_records"]]
        for tool in snapshot["tool_evidence"]
    }
    assert "test-only-reviewed" in authenticity["Nmap"]
    assert "not-verified" in authenticity["Nmap"]
    assert authenticity["OWASP ZAP"] == ["test-only-reviewed"]
    assert authenticity["Nikto"] == ["test-only-reviewed"]
    assert snapshot["openapi_defined_endpoint_count"] == 1
    candidates = snapshot["observation_analytics"]["cross_tool_candidate_groups"]
    shared_source_candidate = next(
        item for item in candidates if {"OWASP ZAP", "Nikto"}.issubset(item["source_tools"])
    )
    assert len(candidates) == 1
    assert shared_source_candidate["observation_count"] == 2
    assert shared_source_candidate["asset_ids"] == [
        shared_source_candidate["observations"][0]["asset_id"]
    ]
    assert all(
        item["endpoint"] == {"path": "/app/check", "method": "GET"}
        and item["parameter_names"] == []
        for item in shared_source_candidate["observations"]
    )
    observation_ids = shared_source_candidate["observation_ids"]
    assert len({item["evidence_id"] for item in shared_source_candidate["observations"]}) == 2
    all_observations = snapshot["observation_analytics"]["ranked_observations"]
    assert len(all_observations) == 5
    assert "fixture-secret" not in json.dumps(snapshot["observation_analytics"])
    zap_only = [
        item
        for item in all_observations
        if item["source_tool"] == "OWASP ZAP" and item["observation_id"] not in observation_ids
    ]
    assert len(zap_only) == 3
    assert {item["endpoint"]["path"] for item in zap_only} == {
        "/app/check",
        "/app/other",
    }
    assert any(item["parameter_names"] == ["account"] for item in zap_only)
    assert len({item["asset_id"] for item in all_observations}) == 2
    assert len({item["endpoint_id"] for item in all_observations}) == 3
    review = post(
        base + "/correlations/reviews",
        {
            "action": "merge",
            "observation_ids": observation_ids,
            "rationale": "TEST ONLY exact shared endpoint and source-reported CVE; reviewer decision fixture.",
        },
    )
    assert review["request"]["action"] == "merge"
    review_state = client.get(base + "/correlations/reviews", headers=headers()).json()
    reviewed_group = review_state["reviewed_clusters"][0]
    assert reviewed_group["occurrence_count"] == 2
    assert {item["evidence_id"] for item in reviewed_group["observations"]} == {
        item["evidence_id"] for item in shared_source_candidate["observations"]
    }
    assert all(
        item["endpoint"] == {"path": "/app/check", "method": "GET"}
        for item in reviewed_group["observations"]
    )
    after_review = client.get(base + "/coverage", headers=headers()).json()
    assert after_review["observed_record_count"] == 5
    assert {item["observation_id"] for item in after_review["observation_analytics"]["ranked_observations"]} == {
        item["observation_id"] for item in all_observations
    }

    assets = client.get(base + "/assets", headers=headers()).json()
    web_asset = next(asset for asset in assets if asset["identifier"] == "https://example.invalid")
    context = post(
        base + "/asset-contexts",
        {
            "asset_id": web_asset["id"],
            "revision": 1,
            "exposure": "internal",
            "exposure_reference": "TEST ONLY reviewer-context fixture",
            "exploitability": "unknown",
            "criticality": 3,
            "criticality_reference": "TEST ONLY reviewer-context fixture",
            "reviewer_note": "Synthetic input solely to exercise contextual ranking.",
        },
    )
    assert context["request"]["provenance_kind"] == "reviewer-supplied; not independently verified"

    revisions = client.get(base + "/result-revisions", headers=headers()).json()
    export = post(
        base + "/result-exports",
        {"revision_ids": [item["id"] for item in revisions]},
    )
    frozen = client.get(base + "/result-exports/" + export["id"], headers=headers())
    assert frozen.status_code == 200
    assert frozen.json()["snapshot"]["complete_assessment"] is False
    assert frozen.json()["snapshot"]["correlation"]["reviewed_cluster_count"] == 1
    pdf = client.get(base + "/result-exports/" + export["id"] + "/pdf", headers=headers())
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF-1.4")
    assert pdf.content.rstrip().endswith(b"%%EOF")
    pdf_text = pdf.content.decode("latin-1")
    for heading in (
        "Executive summary",
        "Assessment scope and rules of engagement",
        "Methodology",
        "Asset inventory",
        "Tool execution summary",
        "Severity distribution (source-reported)",
        "Prioritized observations and reviewer findings",
        "Reviewer correlation decisions",
        "Business impact, recommendations and references",
        "Human approvals and decisions",
        "Assumptions, scan failures and limitations",
        "Evidence manifest",
    ):
        escaped = heading.replace("(", "\\(").replace(")", "\\)")
        assert escaped in pdf_text
    assert "OWASP ZAP" in pdf_text and "Nikto" in pdf_text
    assert "Source occurrence" in pdf_text and "GET /app/check" in pdf_text
    assert "Coverage status: NOT ESTABLISHED" in pdf_text
    assert "TEST ONLY" in pdf_text

"""Coverage provenance, invalid results and frozen-report consistency tests."""

import re
from uuid import UUID

import pytest
from aegistrace import capabilities, coverage
from aegistrace.api_check_worker import execute_check
from aegistrace.capabilities import CapabilityRegistry
from aegistrace.coverage import effective_job_state, operation_coverage, snapshot_digest
from aegistrace.pdf_report import render_evidence_report
from test_api_check_workflow import TOKEN, prepare
from test_capabilities import policy_simulation
from test_nmap import source

pytest_plugins = ("test_ingestion",)


def test_stale_worker_state_is_unknown_without_inventing_completion():
    assert effective_job_state({"state": "running", "lease_until": 0}, native=True) == "unknown"
    assert (
        effective_job_state({"state": "cancel-requested", "payload": {"deadline": 0}}, native=False)
        == "unknown"
    )
    assert (
        effective_job_state({"state": "completed", "payload": {"deadline": 0}}, native=False)
        == "completed"
    )


def test_long_capability_metadata_paginates_above_footer():
    tools = CapabilityRegistry().snapshot()
    for tool in tools:
        tool["installed_edition"] = "TEST ONLY LONG EDITION " * 40
    pdf = render_evidence_report(
        {
            "assessment_id": "test-only",
            "coverage_snapshot": {
                "capabilities": tools,
                "operation_coverage": {},
                "gaps": ["test-only gap " * 100],
            },
        },
        [],
        {},
    )
    assert pdf.count(b"/Type /Page ") > 1
    positions = [int(value) for value in re.findall(rb"rg 48 (-?\d+) Td", pdf)]
    assert positions and all(value >= 80 or value == 28 for value in positions)


def test_recorded_import_remains_recorded_and_does_not_promote_a_tool(import_context):
    client, _ = import_context
    base, headers, imported, *_ = source(import_context)
    response = client.post(
        base + "/imports/" + imported["id"] + "/normalize-nmap", json={}, headers=headers()
    )
    assert response.status_code == 201
    snapshot = client.get(base + "/coverage", headers=headers()).json()
    tool = snapshot["tool_evidence"][0]
    assert tool["name"] == "Nmap" and tool["recorded_import_count"] == 1
    assert tool["normalization_states"] == {"normalized": 1}
    assert tool["source_records"][0]["mode"] == "recorded-import"
    assert tool["source_records"][0]["authenticity"] == "not-verified"
    assert tool["capability"]["mode"] == "planned"
    assert not snapshot["prototype_gate"]["three_verified_network_and_web_imports"]["passed"]


def sample_result(mode="live-request", completed=1.0, check_id="check"):
    endpoints = [
        {"id": "one", "asset_id": "host-a", "method": "GET", "path": "/same"},
        {"id": "two", "asset_id": "host-b", "method": "GET", "path": "/same"},
    ]
    source = {
        "id": "source",
        "source_kind": "api-definition",
        "state": "normalized",
        "evidence_id": "evidence",
        "endpoint_ids": ["one", "two"],
    }
    result = {
        "check_id": check_id,
        "source_normalization_id": "source",
        "source_evidence_id": "evidence",
        "execution_mode": mode,
        "completed_at": completed,
        "operations": [
            {
                "endpoint_id": "one",
                "method": "GET",
                "state": "succeeded",
                "attempted": True,
                "status_code": 200,
                "authentication": "credentials-sent-unverified",
            }
        ],
    }
    result["sha256"] = snapshot_digest(result)
    check = {
        "id": check_id,
        "state": "completed",
        "payload": {"source_normalization_id": "source"},
        "result": result,
    }
    return check, endpoints, [source]


def test_modes_assets_and_unknown_endpoint_denominator_are_separate():
    check, endpoints, sources = sample_result("disposable-test")
    result = operation_coverage([check], endpoints, sources)
    assert result["live-request"]["attempted_count"] == 0
    assert result["disposable-test"]["attempted_count"] == 1
    assert result["disposable-test"]["state_counts"]["untested"] == 1
    assert result["identity_verification"] == "not-established"
    assert {row["asset_id"] for row in result["live-request"]["operations"]} == {"host-a", "host-b"}


def test_protected_session_coverage_requires_credentials_and_success_for_each_declared_route():
    check, endpoints, sources = sample_result()
    sources[0]["operations"] = [
        {
            "endpoint_id": "one",
            "authentication_required": True,
            "security_alternatives": [{"bearer": []}],
        }
    ]
    result = operation_coverage([check], endpoints, sources)["live-request"]

    assert result["protected_session_coverage"] == {
        "declared_protected_count": 1,
        "attempted_with_credentials_count": 1,
        "successful_response_count": 1,
        "identity_verification": "credentials-sent-unverified",
    }

    check["result"]["operations"][0]["authentication"] = "unavailable-or-expired"
    check["result"]["sha256"] = snapshot_digest(
        {key: value for key, value in check["result"].items() if key != "sha256"}
    )
    result = operation_coverage([check], endpoints, sources)["live-request"]
    assert result["protected_session_coverage"]["attempted_with_credentials_count"] == 0


@pytest.mark.parametrize(
    "case", ["hash", "foreign-source", "pending", "unknown-mode", "impossible-success"]
)
def test_unverifiable_outcomes_never_count_as_coverage(case):
    check, endpoints, sources = sample_result()
    if case == "hash":
        check["result"]["sha256"] = "wrong"
    elif case == "foreign-source":
        check["result"]["source_evidence_id"] = "foreign"
        check["result"]["sha256"] = snapshot_digest(
            {k: v for k, v in check["result"].items() if k != "sha256"}
        )
    elif case == "pending":
        check["state"] = "running"
    elif case == "unknown-mode":
        check["result"]["execution_mode"] = "invented-live"
        check["result"]["sha256"] = snapshot_digest(
            {k: v for k, v in check["result"].items() if k != "sha256"}
        )
    else:
        check["result"]["operations"][0]["attempted"] = False
        check["result"]["sha256"] = snapshot_digest(
            {k: v for k, v in check["result"].items() if k != "sha256"}
        )
    result = operation_coverage([check], endpoints, sources)
    assert result["live-request"]["attempted_count"] == 0
    assert result["invalid_or_unverifiable_result_ids"] == ["check"]


def test_latest_rejected_auth_does_not_erase_historical_attempts():
    first, endpoints, sources = sample_result()
    second, _, _ = sample_result(completed=2.0, check_id="second")
    second["result"]["operations"][0].update(
        state="blocked", attempted=False, status_code=None, authentication="unavailable-or-expired"
    )
    second["result"]["sha256"] = snapshot_digest(
        {k: v for k, v in second["result"].items() if k != "sha256"}
    )
    result = operation_coverage([first, second], endpoints, sources)["live-request"]
    assert result["attempted_count"] == 0 and result["ever_attempted_count"] == 1
    assert result["state_counts"]["blocked"] == 1


def test_operator_license_revocation_needs_new_proof():
    registry = CapabilityRegistry()
    capability, proof, run, evidence, fixture, raw = policy_simulation()
    registry.verify_and_register(capability, proof, run, evidence, fixture, raw)
    registry.revoke("Nmap", "TEST ONLY license revoked", license_missing=True)
    current = registry.snapshot()[0]
    assert current["mode"] == current["status"] == "unsupported"
    assert current["license_status"] == "missing" and current["supported_formats"] == []
    assert current["last_verified_run_id"] == str(run.id)


def test_workspace_export_and_pdf_share_frozen_status_and_source_counts(
    import_context, monkeypatch
):
    registry = CapabilityRegistry()
    monkeypatch.setattr(capabilities, "DEFAULT_REGISTRY", registry)
    client, config = import_context
    base, headers, post, secret, check = prepare(import_context)
    post(
        base + "/api-checks/" + check["id"] + "/decision",
        {"decision": "approve", "digest": check["plan"]["digest"]},
    )
    execute_check(
        client.app.state.engine,
        config,
        UUID(check["assessment_id"]),
        UUID(check["id"]),
        transport=lambda *_: 200,
    )
    current = client.get(base + "/coverage", headers=headers()).json()
    assert len(current["capabilities"]) == len(current["tool_evidence"]) == 7
    assert all(row["mode"] == "planned" for row in current["capabilities"])
    assert current["operation_coverage"]["live-request"]["attempted_count"] == 0
    assert current["operation_coverage"]["disposable-test"]["attempted_count"] == 3
    assert not current["prototype_gate"]["three_verified_network_and_web_imports"]["passed"]
    revision_ids = [
        row["id"] for row in client.get(base + "/result-revisions", headers=headers()).json()
    ]
    exported = post(base + "/result-exports", {"revision_ids": revision_ids})
    frozen = exported["snapshot"]["coverage_snapshot"]
    assert frozen["capabilities"] == current["capabilities"]
    assert frozen["operation_coverage"] == current["operation_coverage"]
    assert frozen["snapshot_sha256"] == snapshot_digest(
        {k: v for k, v in frozen.items() if k != "snapshot_sha256"}
    )
    registry.revoke("Nessus", "TEST ONLY disabled commercial tool", license_missing=True)
    post(base + "/api-credentials/" + secret["id"] + "/revoke", {})
    after = client.get(base + "/coverage", headers=headers()).json()
    assert after["capabilities"][1]["mode"] == "unsupported"
    assert after["api_credential_states"] == {"revoked": 1}
    assert after["operation_coverage"]["disposable-test"]["attempted_count"] == 3
    historical = client.get(base + "/result-exports/" + exported["id"], headers=headers()).json()
    assert historical["snapshot"]["coverage_snapshot"] == frozen
    pdf = client.get(base + "/result-exports/" + exported["id"] + "/pdf", headers=headers())
    assert pdf.status_code == 200 and b"Nessus: planned" in pdf.content
    assert frozen["snapshot_sha256"].encode() in pdf.content
    assert TOKEN not in pdf.content.decode("latin-1") and TOKEN not in str(after)
    assert client.get(base + "/coverage", headers=headers("outsider")).status_code == 404
    monkeypatch.setattr(coverage, "ROW_LIMIT", 1)
    bounded = client.get(base + "/coverage", headers=headers()).json()
    assert (
        not bounded["snapshot_complete"]
        and bounded["coverage_state"] == "bounded-snapshot-incomplete"
    )
    assert "endpoints" in bounded["truncated_collections"]

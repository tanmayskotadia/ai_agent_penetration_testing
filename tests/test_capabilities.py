"""Synthetic adapter-policy contracts only. No fixture here proves scanner availability."""

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from aegistrace.api import create_app
from aegistrace.capabilities import (
    Capability,
    CapabilityRegistry,
    VerificationProof,
    capability_snapshot,
)
from aegistrace.domain import EvidenceReference, ToolRun
from aegistrace.fixtures import Fixture
from aegistrace.settings import Settings
from aegistrace_reports import report_capabilities
from aegistrace_workers.adapters.base import (
    Adapter,
    AdapterPlan,
    ExecutionGrant,
    HealthResult,
    PlanValidation,
    RunStatus,
)
from fastapi.testclient import TestClient
from pydantic import ValidationError


def policy_simulation(mode="import-only"):
    # Deliberately simulated provenance/attestation metadata for policy branches.
    # Never write these entries to the real registry/corpus or present them as tool evidence.
    raw = b"TEST ONLY POLICY SIMULATION; NOT SCANNER OUTPUT"
    digest = hashlib.sha256(raw).hexdigest()
    now = datetime.now(UTC)
    assessment = uuid4()
    run = ToolRun(
        assessment_id=assessment,
        scope_id=uuid4(),
        tool="Nmap",
        tool_version="TEST-ONLY-VERSION",
        mode="live" if mode == "live" else "recorded-import",
        captured_at=now,
        state="completed" if mode == "live" else "recorded",
    )
    evidence = EvidenceReference(
        assessment_id=assessment,
        run_id=run.id,
        sha256=digest,
        pointer="TEST-ONLY",
        pointer_type="whole-file",
        captured_at=now,
    )
    fixture = Fixture(
        id="TEST_ONLY_POLICY_METADATA",
        path="tests/fixtures/NO_REAL_CAPTURE",
        sha256=digest,
        tool="Nmap",
        tool_version="TEST-ONLY-VERSION",
        format="TEST-ONLY-CONTRACT",
        provenance="live_capture" if mode == "live" else "recorded_import",
        split="parser_test",
        captured_at=now,
        target_pseudonym="TEST ONLY",
        capture_reference="TEST ONLY SIMULATED PROVENANCE",
        organizer_authorization_reference="TEST ONLY NOT AUTHORITY",
        redistribution_allowed=True,
        rights_basis="TEST ONLY POLICY METADATA",
        redaction_reviewed=True,
        used_for_tuning=False,
    )
    capability = Capability(
        name="Nmap",
        mode=mode,
        status=mode,
        installed_edition="TEST ONLY",
        installed_version="TEST-ONLY-VERSION",
        api_version="test-api-v1",
        supported_formats=("TEST-ONLY-CONTRACT",),
        license_status="verified",
        license_reference="TEST ONLY SIMULATED ENTITLEMENT",
        adapter_implementation="test-harness-only",
        last_verified_run_id=run.id,
        last_verified_at=now,
    )
    proof = VerificationProof(
        name="Nmap",
        mode=mode,
        run_id=run.id,
        evidence_id=evidence.id,
        source_sha256=digest,
        contract_suite_sha256="a" * 64,
        adapter_implementation="test-harness-only",
        adapter_api_version="test-api-v1",
        reviewed_by="TEST ONLY REVIEWER",
        reviewed_at=now,
        authorization_reference="TEST ONLY NOT AUTHORITY",
        runtime_gate_verification_reference="TEST ONLY NOT EXECUTION PROOF",
    )
    return capability, proof, run, evidence, fixture, raw


def test_all_seven_default_tools_and_api_report_registry_agree(tmp_path):
    settings = Settings(
        _env_file=None,
        app_secret="test-only-not-a-real-secret-value-32chars",
        database_url=f"sqlite:///{tmp_path / 'status.db'}",
    )
    with TestClient(create_app(settings)) as client:
        api = client.get("/api/v1/system/capabilities").json()
        assert client.get("/api/v1/system/status").json()["tools"] == api
        assert report_capabilities() == api == capability_snapshot()
        assert len(api) == 7 and {tool["mode"] for tool in api} == {"planned"}
        assert all(
            tool["last_verified_run_id"] is None and tool["installed_version"] is None
            for tool in api
        )
        assert any(tool["guarded_containers"] for tool in api)
        api[0]["mode"] = "live"
        assert capability_snapshot()[0]["mode"] == "planned"


@pytest.mark.parametrize("mode", ["live", "import-only"])
def test_simulated_reviewed_mode_gate_labels_source_and_does_not_modify_real_registry(mode):
    registry = CapabilityRegistry()
    registry.verify_and_register(*policy_simulation(mode))
    value = registry.snapshot()[0]
    assert value["mode"] == mode
    if mode == "import-only":
        assert "not a live scan" in value["demonstration_label"]
    assert {value["mode"] for value in capability_snapshot()} == {"planned"}


@pytest.mark.parametrize("failure", ["handcrafted", "hash", "api", "license", "run", "authority"])
def test_promotion_rejects_unverified_modes_and_mismatched_metadata(failure):
    registry = CapabilityRegistry()
    capability, proof, run, evidence, fixture, raw = policy_simulation("live")
    if failure == "handcrafted":
        fixture = fixture.model_copy(update={"provenance": "handcrafted_test"})
    elif failure == "hash":
        raw += b"tamper"
    elif failure == "api":
        proof = proof.model_copy(update={"adapter_api_version": "wrong-version"})
    elif failure == "license":
        capability = capability.model_copy(update={"license_status": "missing"})
    elif failure == "run":
        run = run.model_copy(update={"mode": "recorded-import"})
    else:
        proof = proof.model_copy(update={"authorization_reference": None})
    with pytest.raises(ValueError):
        registry.verify_and_register(capability, proof, run, evidence, fixture, raw)
    assert registry.snapshot()[0]["mode"] == "planned"


def test_unverified_live_declaration_and_inconsistent_status_rejected():
    with pytest.raises(ValidationError):
        Capability(name="Nessus", mode="live", status="live", license_status="missing")
    with pytest.raises(ValidationError):
        Capability(name="Nmap", mode="planned", status="live")


class HarnessAdapter:
    """Protocol harness: no network/process tool calls, outcomes explicitly unknown."""

    def __init__(self, mode):
        self.mode = mode

    def healthcheck(self):
        return HealthResult(
            available=self.mode == "live",
            version="TEST ONLY",
            reason="contract harness, no scanner",
        )

    def capabilities(self):
        return policy_simulation(self.mode)[0]

    def validate_plan(self, plan):
        return PlanValidation(accepted=self.mode == "live", reasons=("TEST ONLY POLICY HARNESS",))

    def submit(self, plan, grant):
        if self.mode != "live":
            raise ValueError("import-only adapter cannot submit scans")
        if (
            grant.action_digest != plan.action_digest
            or grant.scope_id != plan.scope_id
            or grant.scope_revision != plan.scope_revision
            or grant.expires_at <= datetime.now(UTC)
        ):
            raise ValueError("invalid grant")
        return RunStatus(run_id=uuid4(), state="unknown", reason="TEST ONLY; no scanner executed")

    def status(self, run_id):
        return RunStatus(run_id=run_id, state="unknown", reason="TEST ONLY; no scanner executed")

    def cancel(self, run_id):
        return self.status(run_id)

    def collect(self, run_id):
        return ()

    def normalize(self, artifact, original):
        return ()


def test_live_and_import_protocol_harness_never_claim_actual_execution():
    plan = AdapterPlan(
        assessment_id=uuid4(),
        scope_id=uuid4(),
        scope_revision=1,
        target_asset_ids=(uuid4(),),
        profile="discovery",
        action_digest="a" * 64,
    )
    grant = ExecutionGrant(
        approval_id=uuid4(),
        action_digest=plan.action_digest,
        scope_id=plan.scope_id,
        scope_revision=1,
        expires_at=datetime.now(UTC) + timedelta(minutes=1),
        grant_reference="TEST ONLY; not an execution grant",
    )
    for mode in ["live", "import-only"]:
        adapter = HarnessAdapter(mode)
        assert isinstance(adapter, Adapter)
        if mode == "live":
            result = adapter.submit(plan, grant)
            assert result.state == "unknown" and adapter.cancel(result.run_id).state == "unknown"
            with pytest.raises(ValueError):
                adapter.submit(plan, grant.model_copy(update={"action_digest": "b" * 64}))
        else:
            with pytest.raises(ValueError):
                adapter.submit(plan, grant)

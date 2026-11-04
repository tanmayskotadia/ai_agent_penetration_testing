"""One truthful registry for API, UI and report snapshots. No live adapter is bundled."""

import hashlib
from datetime import UTC, datetime
from typing import Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

from aegistrace.domain import EvidenceReference, ToolName, ToolRun
from aegistrace.fixtures import Fixture

ToolMode = Literal["live", "import-only", "planned", "unsupported"]
TOOL_NAMES: tuple[ToolName, ...] = (
    "Nmap",
    "Nessus",
    "Greenbone",
    "Nikto",
    "OWASP ZAP",
    "Burp Suite",
    "Metasploit",
)


class Capability(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1.0"] = "1.0"
    name: ToolName
    mode: ToolMode = "planned"
    status: ToolMode = "planned"
    installed_edition: str | None = None
    installed_version: str | None = None
    api_version: str | None = None
    supported_formats: tuple[str, ...] = ()
    guarded_containers: tuple[str, ...] = ()
    license_status: Literal["verified", "missing", "unknown"] = "unknown"
    license_reference: str | None = None
    adapter_implementation: str | None = None
    last_verified_run_id: UUID | None = None
    last_verified_at: AwareDatetime | None = None
    demonstration_label: str = "Planned; no verified scanner integration"
    limitations: tuple[str, ...] = (
        "Native adapter and genuine fixture verification pending",
        "Edition/API/license capability unverified",
    )

    @model_validator(mode="after")
    def consistent(self) -> Self:
        if self.mode != self.status:
            raise ValueError("capability status and mode must agree")
        if self.mode in {"live", "import-only"} and (
            self.license_status != "verified"
            or not self.license_reference
            or not self.installed_version
            or not self.installed_edition
            or not self.adapter_implementation
            or self.last_verified_run_id is None
            or self.last_verified_at is None
        ):
            raise ValueError("working status requires version, license and run verification")
        if self.mode == "import-only" and not self.supported_formats:
            raise ValueError("import-only status requires a verified native format")
        return self


class VerificationProof(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: ToolName
    mode: Literal["live", "import-only"]
    run_id: UUID
    evidence_id: UUID
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    contract_suite_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    adapter_implementation: str = Field(min_length=1, max_length=200)
    adapter_api_version: str | None = None
    reviewed_by: str = Field(min_length=1, max_length=200)
    reviewed_at: AwareDatetime
    authorization_reference: str | None = None
    runtime_gate_verification_reference: str | None = None


class CapabilityRegistry:
    def __init__(self) -> None:
        guards: dict[ToolName, tuple[str, ...]] = {
            "Nmap": ("nmap-xml",),
            "Nikto": ("nikto-json",),
            "OWASP ZAP": ("zap-alerts-json",),
        }
        self._entries = {
            name: Capability(name=name, guarded_containers=guards.get(name, ()))
            for name in TOOL_NAMES
        }

    def snapshot(self) -> list[dict[str, object]]:
        return [self._entries[name].model_dump(mode="json") for name in TOOL_NAMES]

    def verify_and_register(
        self,
        capability: Capability,
        proof: VerificationProof,
        run: ToolRun,
        evidence: EvidenceReference,
        fixture: Fixture,
        original: bytes,
    ) -> None:
        # Metadata does not authenticate a capture. This operator-only gate also requires
        # genuine-source review; never expose a user-facing mode-toggle endpoint.
        capability = Capability.model_validate(capability.model_dump())
        if (
            capability.mode not in {"live", "import-only"}
            or proof.mode != capability.mode
            or proof.name != capability.name
        ):
            raise ValueError("mode transition requires matching reviewed verification")
        if capability.license_status != "verified" or not capability.license_reference:
            raise ValueError("license/edition entitlement missing")
        if fixture.provenance == "handcrafted_test" or not fixture.redaction_reviewed:
            raise ValueError("handcrafted/unreviewed fixtures cannot promote an integration")
        if (
            hashlib.sha256(original).hexdigest() != fixture.sha256
            or fixture.sha256 != evidence.sha256
            or proof.source_sha256 != evidence.sha256
        ):
            raise ValueError("verification evidence hash mismatch")
        if not (
            capability.name == run.tool == fixture.tool
            and capability.installed_version == run.tool_version == fixture.tool_version
        ):
            raise ValueError("tool/version verification mismatch")
        if not (
            proof.run_id == run.id == evidence.run_id == capability.last_verified_run_id
            and proof.evidence_id == evidence.id
            and run.assessment_id == evidence.assessment_id
        ):
            raise ValueError("verification run/evidence identity mismatch")
        if (
            proof.adapter_implementation != capability.adapter_implementation
            or proof.adapter_api_version != capability.api_version
        ):
            raise ValueError("adapter/API version mismatch")
        if (
            proof.reviewed_at > datetime.now(UTC)
            or capability.last_verified_at != proof.reviewed_at
        ):
            raise ValueError("invalid verification timestamp")
        if capability.mode == "live" and (
            run.mode != "live"
            or run.state != "completed"
            or fixture.provenance != "live_capture"
            or not proof.authorization_reference
            or not proof.runtime_gate_verification_reference
        ):
            raise ValueError(
                "live requires completed authorized execution and runtime-gate verification"
            )
        if capability.mode == "import-only" and (
            fixture.format not in capability.supported_formats or run.mode != "recorded-import"
        ):
            raise ValueError("native import verification mismatch")
        label = (
            "Verified live execution; source evidence linked"
            if capability.mode == "live"
            else "Recorded native import; not a live scan by this application"
        )
        self._entries[capability.name] = capability.model_copy(
            update={"demonstration_label": label}
        )


DEFAULT_REGISTRY = CapabilityRegistry()


def capability_snapshot() -> list[dict[str, object]]:
    return DEFAULT_REGISTRY.snapshot()

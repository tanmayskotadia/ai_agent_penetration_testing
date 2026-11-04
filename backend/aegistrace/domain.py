"""Versioned canonical contracts. Observations are never confirmation decisions."""

from datetime import datetime
from typing import Literal, Self
from uuid import UUID, uuid4

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator

ToolName = Literal[
    "Nmap", "Nessus", "Greenbone", "Nikto", "OWASP ZAP", "Burp Suite", "Metasploit", "OpenAPI"
]
ValidationState = Literal["suspected", "confirmed", "false-positive", "contradictory", "unknown"]


class Contract(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    schema_version: Literal["1.0"] = "1.0"
    id: UUID = Field(default_factory=uuid4)


class Assessment(Contract):
    name: str = Field(min_length=1, max_length=200)
    owner_id: str = Field(min_length=1, max_length=200)
    created_at: AwareDatetime


class ScopeVersion(Contract):
    assessment_id: UUID
    revision: int = Field(ge=1)
    targets: list[str] = Field(min_length=1, max_length=200)
    exclusions: list[str] = Field(default_factory=list, max_length=200)
    authorization_reference: str | None = Field(default=None, max_length=500)
    valid_until: AwareDatetime | None = None
    # Draft/import scope is not live-scan authority.
    mode: Literal["recorded-import", "live-request"] = "recorded-import"


class Asset(Contract):
    assessment_id: UUID
    identifier: str = Field(min_length=1, max_length=500)
    kind: Literal["host", "url", "application"]


class Service(Contract):
    assessment_id: UUID
    asset_id: UUID
    port: int = Field(ge=1, le=65535)
    protocol: Literal["tcp", "udp"]
    observed_name: str | None = Field(default=None, max_length=200)


class Endpoint(Contract):
    assessment_id: UUID
    asset_id: UUID
    path: str = Field(min_length=1, max_length=2000)
    method: str = Field(pattern=r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)$")


class ToolRun(Contract):
    assessment_id: UUID
    scope_id: UUID
    tool: ToolName
    tool_version: str = Field(min_length=1, max_length=100)
    mode: Literal["recorded-import", "live"]
    captured_at: AwareDatetime
    state: Literal["recorded", "pending", "running", "partial", "failed", "completed"]


class EvidenceReference(Contract):
    assessment_id: UUID
    run_id: UUID
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    pointer: str = Field(min_length=1, max_length=2000)
    pointer_type: Literal["byte-range", "xml-path", "json-pointer", "whole-file"]
    captured_at: AwareDatetime


class Observation(Contract):
    assessment_id: UUID
    asset_id: UUID
    run_id: UUID
    evidence_id: UUID
    source_key: str = Field(min_length=1, max_length=500)
    title: str = Field(min_length=1, max_length=500)
    observed_at: AwareDatetime
    source_severity: str | None = Field(default=None, max_length=100)
    cvss_score: float | None = Field(default=None, ge=0, le=10, allow_inf_nan=False)
    cvss_vector: str | None = Field(default=None, max_length=200)
    cvss_version: Literal["2.0", "3.0", "3.1", "4.0"] | None = None
    cve: str | None = Field(default=None, pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")
    cwe: str | None = Field(default=None, pattern=r"^CWE-[0-9]+$")
    confidence: float | None = Field(default=None, ge=0, le=1, allow_inf_nan=False)
    confidence_method: str | None = Field(default=None, max_length=200)
    information_kind: Literal["observed-evidence"] = "observed-evidence"
    validation_state: Literal["suspected", "unknown"] = "suspected"

    @model_validator(mode="after")
    def confidence_is_explained(self) -> Self:
        if self.confidence is not None and not self.confidence_method:
            raise ValueError("confidence requires its method; it is not a calibrated probability")
        if self.cvss_vector is not None and self.cvss_version is None:
            raise ValueError("a source CVSS vector requires an explicit version")
        return self


class VulnerabilityConcept(Contract):
    assessment_id: UUID
    title: str = Field(min_length=1, max_length=500)
    cve: str | None = Field(default=None, pattern=r"^CVE-[0-9]{4}-[0-9]{4,}$")


class Occurrence(Contract):
    assessment_id: UUID
    concept_id: UUID
    asset_id: UUID
    observation_id: UUID
    location: str = Field(min_length=1, max_length=2000)


class Finding(Contract):
    assessment_id: UUID
    concept_id: UUID
    title: str = Field(min_length=1, max_length=500)
    information_kind: Literal["reviewer-decision", "ai-inference"]
    validation_state: ValidationState = "suspected"
    decision_id: UUID | None = None
    limitations: list[str] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def require_review(self) -> Self:
        if self.validation_state in {"confirmed", "false-positive"} and (
            self.decision_id is None or self.information_kind != "reviewer-decision"
        ):
            raise ValueError(
                "confirmation/false-positive classification requires a reviewer decision"
            )
        return self


class Decision(Contract):
    assessment_id: UUID
    actor_id: str = Field(min_length=1, max_length=200)
    information_kind: Literal["reviewer-decision", "ai-inference"]
    rationale: str = Field(min_length=1, max_length=4000)
    decided_at: AwareDatetime


class Approval(Contract):
    assessment_id: UUID
    decision_id: UUID
    action_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    scope_revision: int = Field(ge=1)
    expires_at: AwareDatetime
    state: Literal["requested", "approved", "denied", "revoked", "consumed"] = "requested"


class ReportSnapshot(Contract):
    assessment_id: UUID
    created_at: AwareDatetime
    source_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_ids: list[UUID] = Field(min_length=1, max_length=10000)
    limitations: list[str] = Field(default_factory=list, max_length=100)


CONTRACTS: dict[str, type[Contract]] = {
    "assessments": Assessment,
    "scope_versions": ScopeVersion,
    "assets": Asset,
    "services": Service,
    "endpoints": Endpoint,
    "tool_runs": ToolRun,
    "evidence_references": EvidenceReference,
    "observations": Observation,
    "vulnerability_concepts": VulnerabilityConcept,
    "occurrences": Occurrence,
    "decisions": Decision,
    "findings": Finding,
    "approvals": Approval,
    "report_snapshots": ReportSnapshot,
}


def utc_iso(value: datetime) -> str:
    return value.isoformat()

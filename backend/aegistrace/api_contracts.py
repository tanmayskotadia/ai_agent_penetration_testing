"""Versioned requests; accepted requests are not completed scanner/report operations."""

from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator


class ApiContract(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    schema_version: Literal["1.0"] = "1.0"


class AssessmentCreate(ApiContract):
    name: str = Field(min_length=1, max_length=200)


class ScopeCreate(ApiContract):
    revision: int = Field(ge=1)
    targets: list[str] = Field(min_length=1, max_length=200)
    exclusions: list[str] = Field(default_factory=list, max_length=200)
    authorization_reference: str | None = Field(default=None, max_length=500)
    valid_until: AwareDatetime | None = None
    mode: Literal["recorded-import", "live-request"] = "recorded-import"


class AssetCreate(ApiContract):
    identifier: str = Field(min_length=1, max_length=500)
    kind: Literal["host", "url", "application"]


class AssetRiskContextCreate(ApiContract):
    asset_id: UUID
    revision: int = Field(ge=1)
    exposure: Literal["internet-facing", "internal", "restricted", "unknown"] = "unknown"
    exposure_reference: str | None = Field(default=None, max_length=1000)
    exploitability: Literal["confirmed", "suspected", "unknown"] = "unknown"
    exploitability_reference: str | None = Field(default=None, max_length=1000)
    criticality: int | None = Field(default=None, ge=1, le=5)
    criticality_reference: str | None = Field(default=None, max_length=1000)
    reviewer_note: str = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def context_requires_references(self) -> "AssetRiskContextCreate":
        if self.exposure != "unknown" and not self.exposure_reference:
            raise ValueError("recorded exposure requires a provenance reference")
        if self.exploitability != "unknown" and not self.exploitability_reference:
            raise ValueError("recorded exploitability requires an evidence reference")
        if self.criticality is not None and not self.criticality_reference:
            raise ValueError("asset criticality requires an analyst provenance reference")
        return self


class CorrelationReviewCreate(ApiContract):
    action: Literal["merge", "split", "undo"]
    rationale: str = Field(min_length=1, max_length=2000)
    observation_ids: list[UUID] = Field(default_factory=list, max_length=100)
    cluster_id: str | None = Field(default=None, min_length=16, max_length=64)
    partitions: list[list[UUID]] = Field(default_factory=list, max_length=50)
    target_review_id: UUID | None = None

    @model_validator(mode="after")
    def action_shape(self) -> "CorrelationReviewCreate":
        if self.action == "merge":
            if len(self.observation_ids) < 2 or self.partitions or self.target_review_id:
                raise ValueError("merge requires at least two observation IDs only")
            if len(set(self.observation_ids)) != len(self.observation_ids):
                raise ValueError("merge observation IDs must be unique")
        elif self.action == "split":
            if (
                not self.cluster_id
                or self.observation_ids
                or self.target_review_id
                or len(self.partitions) < 2
                or any(not group for group in self.partitions)
            ):
                raise ValueError("split requires a cluster ID and at least two partitions")
            flattened = [item for group in self.partitions for item in group]
            if len(flattened) > 100:
                raise ValueError("split decision cannot include more than 100 observations")
            if len(flattened) != len(set(flattened)):
                raise ValueError("split partitions must not repeat observation IDs")
        elif self.action == "undo":
            if (
                self.observation_ids
                or self.cluster_id
                or self.partitions
                or not self.target_review_id
            ):
                raise ValueError("undo requires only a target review ID")
        return self


class FindingReviewCreate(ApiContract):
    """Human triage of one source observation; never changes source evidence."""

    observation_id: UUID
    validation_state: Literal[
        "suspected", "confirmed", "false-positive", "contradictory", "unknown"
    ]
    rationale: str = Field(min_length=1, max_length=2000)
    contradictory_observation_ids: list[UUID] = Field(default_factory=list, max_length=50)

    @model_validator(mode="after")
    def contradiction_references(self) -> "FindingReviewCreate":
        if len(set(self.contradictory_observation_ids)) != len(self.contradictory_observation_ids):
            raise ValueError("contradiction references must be unique")
        if self.observation_id in self.contradictory_observation_ids:
            raise ValueError("an observation cannot contradict itself")
        if self.validation_state == "contradictory" and not self.contradictory_observation_ids:
            raise ValueError("contradictory state requires at least one cited observation")
        if self.validation_state != "contradictory" and self.contradictory_observation_ids:
            raise ValueError("contradiction references require contradictory state")
        return self


class SourceReviewCreate(ApiContract):
    normalization_id: UUID
    source_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    decision: Literal["verify", "reject"]
    provenance: Literal["genuine-permitted-capture", "test-only"]
    rationale: str = Field(min_length=10, max_length=2000)


class RunCreate(ApiContract):
    scope_id: UUID
    tool: Literal[
        "Nmap", "Nessus", "Greenbone", "Nikto", "OWASP ZAP", "Burp Suite", "Metasploit", "OpenAPI"
    ]
    tool_version: str = Field(min_length=1, max_length=100)
    captured_at: AwareDatetime
    mode: Literal["recorded-import"] = "recorded-import"


class EvidenceCreate(ApiContract):
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    pointer: str = Field(min_length=1, max_length=2000)
    pointer_type: Literal["byte-range", "xml-path", "json-pointer", "whole-file"]
    captured_at: AwareDatetime


class PlanCreate(ApiContract):
    scope_id: UUID
    scope_revision: int = Field(ge=1)
    revision: int = Field(ge=1)
    steps: list[str] = Field(min_length=1, max_length=50)


class PlanIntake(ApiContract):
    """Natural-language request used to create a deterministic, reviewable draft."""

    message: str = Field(min_length=1, max_length=4000)
    conversation_id: UUID | None = None
    scope_id: UUID | None = None
    scope_revision: int | None = Field(default=None, ge=1)
    constraints: list[str] = Field(default_factory=list, max_length=30)
    prior_result_revision_ids: list[UUID] = Field(default_factory=list, max_length=100)

    @model_validator(mode="after")
    def scope_revision_pair(self) -> "PlanIntake":
        if not self.message.strip():
            raise ValueError("message must contain assessment intent")
        if (self.scope_id is None) != (self.scope_revision is None):
            raise ValueError("scope_id and scope_revision must be supplied together")
        if any(not item.strip() or len(item) > 500 for item in self.constraints):
            raise ValueError("constraints must be non-empty and at most 500 characters")
        return self


class JobCreate(ApiContract):
    plan_id: UUID
    plan_revision: int = Field(ge=1)


class PlanReviewCreate(ApiContract):
    plan_revision: int = Field(ge=1)
    plan_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    decision: Literal["approve", "reject"]
    rationale: str = Field(min_length=10, max_length=2000)


class ImportCreate(ApiContract):
    scope_id: UUID
    scope_revision: int = Field(ge=1)
    tool: Literal[
        "Nmap", "Nessus", "Greenbone", "Nikto", "OWASP ZAP", "Burp Suite", "Metasploit", "OpenAPI"
    ]
    format: str = Field(min_length=1, max_length=100)
    evidence_id: UUID


class ApprovalCreate(ApiContract):
    plan_id: UUID
    plan_revision: int = Field(ge=1)
    action_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class ReportCreate(ApiContract):
    format: Literal["pdf", "json"] = "pdf"


class WorkflowResource(ApiContract):
    id: UUID
    assessment_id: UUID
    kind: Literal[
        "plans",
        "jobs",
        "imports",
        "approvals",
        "reports",
        "asset-contexts",
        "correlation-reviews",
        "finding-reviews",
        "source-reviews",
        "plan-reviews",
    ]
    revision: int = Field(default=1, ge=1)
    state: Literal["draft", "blocked", "pending-review", "pending-ingestion", "reviewed"]
    reason: str | None = None
    mode: Literal["request-only", "recorded-import"] = "request-only"
    request: dict[str, object]


class ApiError(BaseModel):
    code: str
    message: str
    request_id: str | None = None

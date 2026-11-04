"""Typed boundary every native/live adapter must satisfy under runtime policy enforcement."""

from typing import Literal, Protocol, runtime_checkable
from uuid import UUID

from aegistrace.capabilities import Capability
from aegistrace.domain import Observation, ToolName
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


class AdapterPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    assessment_id: UUID
    scope_id: UUID
    scope_revision: int = Field(ge=1)
    target_asset_ids: tuple[UUID, ...] = Field(min_length=1, max_length=200)
    profile: Literal["discovery", "passive-web", "active-web", "controlled-validation"]
    action_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


class ExecutionGrant(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    approval_id: UUID
    action_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    scope_id: UUID
    scope_revision: int = Field(ge=1)
    expires_at: AwareDatetime
    # A transport contract, not an authorization verifier. Runtime policy validates it.
    grant_reference: str = Field(min_length=1, max_length=500)


class HealthResult(BaseModel):
    available: bool
    version: str | None = None
    reason: str | None = None


class PlanValidation(BaseModel):
    accepted: bool
    reasons: tuple[str, ...] = ()


class RunStatus(BaseModel):
    run_id: UUID
    state: Literal["pending", "running", "completed", "partial", "failed", "cancelled", "unknown"]
    reason: str | None = None


class CollectedArtifact(BaseModel):
    evidence_id: UUID
    run_id: UUID
    tool: ToolName
    tool_version: str
    mode: Literal["live", "recorded-import"]
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    format: str
    captured_at: AwareDatetime


@runtime_checkable
class Adapter(Protocol):
    def healthcheck(self) -> HealthResult: ...
    def capabilities(self) -> Capability: ...
    def validate_plan(self, plan: AdapterPlan) -> PlanValidation: ...
    def submit(self, plan: AdapterPlan, grant: ExecutionGrant) -> RunStatus: ...
    def status(self, run_id: UUID) -> RunStatus: ...
    def cancel(self, run_id: UUID) -> RunStatus: ...
    def collect(self, run_id: UUID) -> tuple[CollectedArtifact, ...]: ...
    def normalize(
        self, artifact: CollectedArtifact, original: bytes
    ) -> tuple[Observation, ...]: ...

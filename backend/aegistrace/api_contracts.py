"""Versioned requests; accepted requests are not completed scanner/report operations."""

from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


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


class JobCreate(ApiContract):
    plan_id: UUID
    plan_revision: int = Field(ge=1)


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
    kind: Literal["plans", "jobs", "imports", "approvals", "reports"]
    revision: int = Field(default=1, ge=1)
    state: Literal["draft", "blocked", "pending-review", "pending-ingestion"]
    reason: str | None = None
    mode: Literal["request-only", "recorded-import"] = "request-only"
    request: dict[str, object]


class ApiError(BaseModel):
    code: str
    message: str
    request_id: str | None = None

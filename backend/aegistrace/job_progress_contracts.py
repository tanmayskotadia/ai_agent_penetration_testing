"""Versioned public contracts for durable job status and progress SSE."""

from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class JobProgressEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    job_id: UUID
    assessment_id: UUID
    sequence: int = Field(ge=1)
    event_id: UUID
    kind: str = Field(pattern=r"^[a-z][a-z0-9-]{0,39}$")
    state: str = Field(pattern=r"^[a-z][a-z0-9-]{0,29}$")
    attempt: int = Field(ge=0)
    created_at: float
    worker_id: UUID | None = None
    epoch: int | None = Field(default=None, ge=1)
    elapsed_ms: int | None = Field(default=None, ge=0)
    tool_version: str | None = Field(default=None, max_length=80)
    exit_code: int | None = Field(default=None, ge=-255, le=255)
    diagnostic_code: str | None = Field(default=None, max_length=50)
    diagnostic: str | None = Field(default=None, max_length=300)


class JobStatusSnapshot(BaseModel):
    model_config = ConfigDict(extra="ignore", frozen=True)

    schema_version: Literal["1.0"] = "1.0"
    id: UUID
    assessment_id: UUID
    state: str
    status: str
    attempt: int = Field(ge=0)
    created_at: float
    updated_at: float
    heartbeat_at: float | None = None
    heartbeat_age_seconds: int | None = Field(default=None, ge=0)
    heartbeat_stale: bool
    started_at: float | None = None
    finished_at: float | None = None
    duration_ms: int | None = Field(default=None, ge=0)
    tool_version: str | None = Field(default=None, max_length=80)
    exit_code: int | None = Field(default=None, ge=-255, le=255)
    diagnostic_code: str | None = Field(default=None, max_length=50)
    diagnostic: str | None = Field(default=None, max_length=300)
    events_cursor: int = Field(ge=0)
    latest_event_kind: str | None = Field(default=None, max_length=40)
    latest_event_at: float | None = None
    percentage_complete: None = None

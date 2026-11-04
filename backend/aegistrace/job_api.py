"""Human-submitted approved jobs and owner-bound worker status views."""

import json
from collections.abc import Iterator
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Engine, select

from aegistrace.auth import Identity, identity_dependency
from aegistrace.job_progress import job_snapshot, read_progress
from aegistrace.job_progress_contracts import JobProgressEvent, JobStatusSnapshot
from aegistrace.job_schema import jobs
from aegistrace.jobs import enqueue
from aegistrace.mutations import mutation
from aegistrace.repository import require_access
from aegistrace.settings import Settings


class JobSubmit(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"] = "1.0"
    approval_id: UUID
    action_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    priority: int = Field(default=0, ge=0, le=10, strict=True)


def job_router(engine: Engine, config: Settings) -> APIRouter:
    router = APIRouter(
        prefix="/api/v1/assessments/{assessment_id}/scan-jobs", tags=["durable-jobs"]
    )
    actor_dependency = Depends(identity_dependency(config))

    @router.get("", response_model=list[JobStatusSnapshot])
    def list_jobs(assessment_id: UUID, actor: Identity = actor_dependency) -> list[dict[str, Any]]:
        with engine.connect() as connection:
            require_access(connection, assessment_id, actor.subject)
            rows = connection.execute(
                select(jobs)
                .where(jobs.c.assessment_id == str(assessment_id))
                .order_by(jobs.c.created_at.desc(), jobs.c.id)
                .limit(50)
            ).mappings()
            return [job_snapshot(connection, dict(row)) for row in rows]

    @router.post("", status_code=202)
    def submit(
        assessment_id: UUID, body: JobSubmit, request: Request, actor: Identity = actor_dependency
    ) -> JSONResponse:
        return mutation(
            engine,
            request,
            actor,
            body.model_dump(mode="json"),
            lambda connection: enqueue(
                connection,
                config,
                assessment_id,
                body.approval_id,
                body.action_digest,
                actor,
                body.priority,
            ),
            202,
        )

    @router.get("/{job_id}", response_model=JobStatusSnapshot)
    def read(
        assessment_id: UUID, job_id: UUID, actor: Identity = actor_dependency
    ) -> dict[str, Any]:
        try:
            with engine.connect() as connection:
                require_access(connection, assessment_id, actor.subject)
                row = (
                    connection.execute(
                        select(jobs).where(
                            jobs.c.id == str(job_id), jobs.c.assessment_id == str(assessment_id)
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is None:
                    raise LookupError("job not found")
                return job_snapshot(connection, dict(row))
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error

    @router.get("/{job_id}/events")
    def events(
        assessment_id: UUID,
        job_id: UUID,
        last_event_id: int = Header(default=0, ge=0),
        actor: Identity = actor_dependency,
    ) -> StreamingResponse:
        try:
            with engine.connect() as connection:
                require_access(connection, assessment_id, actor.subject)
                row = connection.execute(
                    select(jobs.c.id).where(
                        jobs.c.id == str(job_id), jobs.c.assessment_id == str(assessment_id)
                    )
                ).scalar_one_or_none()
                if row is None:
                    raise LookupError("job not found")
                values = read_progress(connection, job_id, assessment_id, last_event_id, 100)
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error

        def frames() -> Iterator[str]:
            for value in values:
                yield (
                    f"id: {value['sequence']}\nevent: job-status\ndata: "
                    f"{json.dumps(JobProgressEvent.model_validate(value).model_dump(mode='json'), separators=(',', ':'))}\n\n"
                )
            yield "retry: 2000\n: batch-end; reconnect with last received ID\n\n"

        return StreamingResponse(
            frames(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    return router

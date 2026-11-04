"""Human-submitted approved jobs; worker/control endpoints are not public."""

from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Engine, select

from aegistrace.auth import Identity, identity_dependency
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

    @router.get("/{job_id}")
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
                return dict(row)
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error

    return router

"""Owned immutable result snapshots, private exports and explicit late-output review."""

from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Engine, select

from aegistrace.auth import Identity, identity_dependency
from aegistrace.mutations import mutation
from aegistrace.repository import require_access
from aegistrace.result_schema import exports, revisions
from aegistrace.results import content_hash, freeze_export, review_late
from aegistrace.settings import Settings


class ExportCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    revision_ids: tuple[UUID, ...] = Field(min_length=1, max_length=50)


class LateReview(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["include", "reject"]
    evidence_id: UUID | None = None


def result_router(engine: Engine, config: Settings) -> APIRouter:
    router = APIRouter(prefix="/api/v1/assessments/{assessment_id}", tags=["result-revisions"])
    actor_dependency = Depends(identity_dependency(config))

    @router.get("/result-revisions")
    def list_revisions(
        assessment_id: UUID, actor: Identity = actor_dependency
    ) -> list[dict[str, Any]]:
        try:
            with engine.connect() as connection:
                require_access(connection, assessment_id, actor.subject)
                return [
                    dict(value)
                    for value in connection.execute(
                        select(revisions.c.payload)
                        .where(revisions.c.assessment_id == str(assessment_id))
                        .order_by(revisions.c.run_id, revisions.c.revision)
                        .limit(200)
                    ).scalars()
                ]
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error

    @router.post("/result-exports", status_code=201)
    def freeze(
        assessment_id: UUID,
        body: ExportCreate,
        request: Request,
        actor: Identity = actor_dependency,
    ) -> JSONResponse:
        return mutation(
            engine,
            request,
            actor,
            body.model_dump(mode="json"),
            lambda connection: freeze_export(connection, assessment_id, body.revision_ids, actor),
        )

    @router.get("/result-exports/{export_id}")
    def read_export(
        assessment_id: UUID, export_id: UUID, actor: Identity = actor_dependency
    ) -> JSONResponse:
        try:
            with engine.connect() as connection:
                require_access(connection, assessment_id, actor.subject)
                row = (
                    connection.execute(
                        select(exports).where(
                            exports.c.id == str(export_id),
                            exports.c.assessment_id == str(assessment_id),
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is None:
                    raise LookupError("not found")
                if content_hash(row["payload"]) != row["sha256"]:
                    raise HTTPException(409, "Export integrity unavailable")
                return JSONResponse(
                    {"id": str(export_id), "sha256": row["sha256"], "snapshot": row["payload"]},
                    headers={
                        "Cache-Control": "no-store",
                        "Content-Disposition": f'attachment; filename="result-{export_id}.json"',
                    },
                )
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error

    @router.post("/scan-jobs/{job_id}/late-artifacts/{artifact_id}/review")
    def review(
        assessment_id: UUID,
        job_id: UUID,
        artifact_id: UUID,
        body: LateReview,
        request: Request,
        actor: Identity = actor_dependency,
    ) -> JSONResponse:
        return mutation(
            engine,
            request,
            actor,
            body.model_dump(mode="json"),
            lambda connection: review_late(
                connection,
                config,
                assessment_id,
                job_id,
                artifact_id,
                body.decision,
                body.evidence_id,
                actor,
            ),
        )

    return router

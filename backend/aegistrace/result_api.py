"""Owned immutable result snapshots, private exports and explicit late-output review."""

from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Engine, select

from aegistrace.auth import Identity, identity_dependency
from aegistrace.mutations import mutation
from aegistrace.pdf_report import render_evidence_report
from aegistrace.repository import require_access
from aegistrace.result_schema import exports, revisions
from aegistrace.results import content_hash, freeze_export, review_late
from aegistrace.schema_v1 import assets, observations
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

    @router.get("/result-exports/{export_id}/pdf")
    def read_export_pdf(
        assessment_id: UUID, export_id: UUID, actor: Identity = actor_dependency
    ) -> Response:
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
                snapshot = dict(row["payload"])
                all_observation_ids = list(
                    dict.fromkeys(
                        observation_id
                        for revision in snapshot.get("result_revisions", [])
                        for observation_id in revision.get("observation_ids", [])
                    )
                )
                snapshot["observation_reference_count"] = len(all_observation_ids)
                observation_ids = all_observation_ids[:250]
                observation_rows = (
                    connection.execute(
                        select(observations.c.payload).where(
                            observations.c.assessment_id == str(assessment_id),
                            observations.c.id.in_(observation_ids),
                        )
                    ).scalars().all()
                    if observation_ids
                    else []
                )
                asset_ids = list(
                    dict.fromkeys(str(value.get("asset_id")) for value in observation_rows)
                )
                asset_rows = (
                    connection.execute(
                        select(assets.c.id, assets.c.payload).where(
                            assets.c.assessment_id == str(assessment_id), assets.c.id.in_(asset_ids)
                        )
                    ).all()
                    if asset_ids
                    else []
                )
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error
        snapshot["id"] = str(export_id)
        snapshot["sha256"] = row["sha256"]
        asset_names = {str(asset_id): str(payload.get("identifier", "unmapped asset")) for asset_id, payload in asset_rows}
        pdf = render_evidence_report(snapshot, [dict(value) for value in observation_rows], asset_names)
        return Response(
            content=pdf,
            media_type="application/pdf",
            headers={
                "Cache-Control": "no-store",
                "Content-Disposition": f'attachment; filename="aegistrace-{export_id}.pdf"',
                "X-Content-Type-Options": "nosniff",
            },
        )

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

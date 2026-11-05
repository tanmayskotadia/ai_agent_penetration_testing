"""Append-only human source-provenance decisions for imported evidence."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import Connection, Engine, select

from aegistrace.api_contracts import SourceReviewCreate, WorkflowResource
from aegistrace.api_schema import resources
from aegistrace.auth import Identity, identity_dependency
from aegistrace.mutations import mutation
from aegistrace.normalization_schema import normalizations
from aegistrace.platform_api import record_request
from aegistrace.repository import require_access
from aegistrace.settings import Settings


def source_review_router(engine: Engine, config: Settings) -> APIRouter:
    router = APIRouter(
        prefix="/api/v1/assessments/{assessment_id}/source-reviews", tags=["source review"]
    )
    actor_dependency = Depends(identity_dependency(config))

    @router.get("")
    def list_reviews(
        assessment_id: UUID, actor: Identity = actor_dependency
    ) -> list[dict[str, Any]]:
        try:
            with engine.connect() as connection:
                require_access(connection, assessment_id, actor.subject)
                return [
                    dict(value)
                    for value in connection.execute(
                        select(resources.c.payload)
                        .where(
                            resources.c.assessment_id == str(assessment_id),
                            resources.c.kind == "source-reviews",
                        )
                        .order_by(resources.c.id)
                        .limit(1000)
                    ).scalars()
                ]
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error

    @router.post("", response_model=WorkflowResource, status_code=201)
    def save_review(
        assessment_id: UUID,
        body: SourceReviewCreate,
        request: Request,
        actor: Identity = actor_dependency,
    ) -> JSONResponse:
        request_payload = body.model_dump(mode="json")

        def apply(connection: Connection) -> dict[str, Any]:
            require_access(connection, assessment_id, actor.subject)
            if actor.principal_kind != "human" or actor.role not in {"reviewer", "admin"}:
                raise HTTPException(403, "Reviewer or administrator role required")
            revision = connection.execute(
                select(normalizations.c.payload).where(
                    normalizations.c.assessment_id == str(assessment_id),
                    normalizations.c.id == str(body.normalization_id),
                )
            ).scalar_one_or_none()
            if revision is None:
                raise HTTPException(404, "Normalized source revision not found")
            if (
                revision.get("state") != "normalized"
                or revision.get("source_sha256") != body.source_sha256
                or revision.get("information_kind") != "observed-evidence"
            ):
                raise HTTPException(409, "Source revision is not normalized or its digest changed")
            prior_rows = (
                connection.execute(
                    select(resources.c.payload)
                    .where(
                        resources.c.assessment_id == str(assessment_id),
                        resources.c.kind == "source-reviews",
                    )
                    .limit(1001)
                )
                .scalars()
                .all()
            )
            if len(prior_rows) > 1000:
                raise HTTPException(409, "Source review history exceeds the review limit")
            prior = [
                dict(value)
                for value in prior_rows
                if value.get("request", {}).get("normalization_id") == str(body.normalization_id)
            ]
            revision_number = max((int(item["revision"]) for item in prior), default=0) + 1
            recorded_at = datetime.now(UTC).isoformat()
            stored_request = request_payload | {
                "reviewer": actor.subject,
                "recorded_at": recorded_at,
                "source_run_id": revision["run_id"],
                "evidence_id": revision["evidence_id"],
                "provenance_kind": "human review assertion; not independent scanner or authorization proof",
            }
            value = WorkflowResource.model_validate(
                {
                    "id": uuid4(),
                    "assessment_id": assessment_id,
                    "kind": "source-reviews",
                    "revision": revision_number,
                    "state": "draft",
                    "mode": "request-only",
                    "request": stored_request,
                }
            ).model_dump(mode="json")
            connection.execute(
                resources.insert().values(
                    id=value["id"],
                    assessment_id=str(assessment_id),
                    kind="source-reviews",
                    payload=value,
                )
            )
            record_request(
                connection,
                assessment_id,
                actor,
                "source.review-recorded",
                UUID(value["id"]),
                value,
            )
            return value

        return mutation(engine, request, actor, request_payload, apply, 201)

    return router

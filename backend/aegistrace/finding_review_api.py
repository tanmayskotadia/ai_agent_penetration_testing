"""Append-only human triage decisions for normalized source observations."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import Connection, Engine, select

from aegistrace.api_contracts import FindingReviewCreate, WorkflowResource
from aegistrace.api_schema import resources
from aegistrace.auth import Identity, identity_dependency
from aegistrace.finding_reviews import latest_by_observation, validate_review
from aegistrace.mutations import mutation
from aegistrace.platform_api import record_request
from aegistrace.repository import require_access
from aegistrace.schema_v1 import assessments, observations
from aegistrace.settings import Settings


def _history(connection: Connection, assessment_id: UUID) -> list[dict[str, Any]]:
    rows = (
        connection.execute(
            select(resources.c.payload)
            .where(
                resources.c.assessment_id == str(assessment_id),
                resources.c.kind == "finding-reviews",
            )
            .order_by(resources.c.id)
            .limit(1001)
        )
        .scalars()
        .all()
    )
    if len(rows) > 1000:
        raise HTTPException(409, "Finding review history exceeds the review limit")
    return sorted((dict(row) for row in rows), key=lambda item: int(item["revision"]))


def finding_review_router(engine: Engine, config: Settings) -> APIRouter:
    router = APIRouter(
        prefix="/api/v1/assessments/{assessment_id}/finding-reviews", tags=["finding-review"]
    )
    actor_dependency = Depends(identity_dependency(config))

    @router.get("")
    def list_finding_reviews(
        assessment_id: UUID, actor: Identity = actor_dependency
    ) -> dict[str, Any]:
        try:
            with engine.begin() as connection:
                require_access(connection, assessment_id, actor.subject)
                history = _history(connection, assessment_id)
                observations_for_assessment = (
                    connection.execute(
                        select(observations.c.id).where(
                            observations.c.assessment_id == str(assessment_id)
                        )
                    )
                    .scalars()
                    .all()
                )
                known_ids = {str(value) for value in observations_for_assessment}
                latest = latest_by_observation(history)
                # A stale/corrupt reference is never returned as an active decision.
                latest = {key: value for key, value in latest.items() if key in known_ids}
                return {
                    "revision": int(history[-1]["revision"]) if history else 0,
                    "information_kind": "reviewer-decision",
                    "confidence_policy": "unknown unless source or independently validated method supplies a value",
                    "calibration_status": "not-calibrated",
                    "latest_by_observation": latest,
                    "reviews": [
                        {
                            key: value
                            for key, value in item.items()
                            if key in {"id", "revision", "created_at", "request"}
                        }
                        for item in history[-100:]
                    ],
                    "history_truncated": len(history) > 100,
                }
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error

    @router.post("", response_model=WorkflowResource, status_code=201)
    def save_finding_review(
        assessment_id: UUID,
        body: FindingReviewCreate,
        request: Request,
        actor: Identity = actor_dependency,
    ) -> JSONResponse:
        request_payload = body.model_dump(mode="json")

        def apply(connection: Connection) -> dict[str, Any]:
            require_access(connection, assessment_id, actor.subject)
            if actor.principal_kind != "human" or actor.role not in {"reviewer", "admin"}:
                raise HTTPException(403, "Reviewer or administrator role required")
            connection.execute(
                select(assessments.c.id)
                .where(assessments.c.id == str(assessment_id))
                .with_for_update()
            ).one()
            history = _history(connection, assessment_id)
            current_revision = int(history[-1]["revision"]) if history else 0
            if body.expected_revision != current_revision:
                raise HTTPException(
                    409, "Finding review changed. Reload current decisions and review again."
                )
            selected_ids = {
                str(body.observation_id),
                *(str(value) for value in body.contradictory_observation_ids),
            }
            found = {
                str(value)
                for value in connection.execute(
                    select(observations.c.id).where(
                        observations.c.assessment_id == str(assessment_id),
                        observations.c.id.in_(selected_ids),
                    )
                ).scalars()
            }
            if found != selected_ids:
                raise HTTPException(404, "Review observations must belong to this assessment")
            try:
                decision = validate_review(request_payload, found)
            except ValueError as error:
                raise HTTPException(422, str(error)) from error
            revision = int(history[-1]["revision"]) + 1 if history else 1
            stored_request = decision | {
                "recorded_by": actor.subject,
                "recorded_at": datetime.now(UTC).isoformat(),
                "source_observation_unchanged": True,
            }
            value = WorkflowResource.model_validate(
                {
                    "id": uuid4(),
                    "assessment_id": assessment_id,
                    "kind": "finding-reviews",
                    "revision": revision,
                    "state": "draft",
                    "mode": "request-only",
                    "request": stored_request,
                }
            ).model_dump(mode="json")
            connection.execute(
                resources.insert().values(
                    id=value["id"],
                    assessment_id=str(assessment_id),
                    kind="finding-reviews",
                    payload=value,
                )
            )
            record_request(
                connection,
                assessment_id,
                actor,
                "finding.review-recorded",
                UUID(value["id"]),
                value,
            )
            return value

        return mutation(engine, request, actor, request_payload, apply, 201)

    return router

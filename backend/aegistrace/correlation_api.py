"""Reviewer-controlled, append-only cross-tool correlation decisions."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import Connection, Engine, select

from aegistrace.api_contracts import CorrelationReviewCreate, WorkflowResource
from aegistrace.api_schema import resources
from aegistrace.auth import Identity, identity_dependency
from aegistrace.correlation_review import (
    materialize_clusters,
    materialize_splits,
    merge_clusters,
    normalize_clusters,
    split_cluster,
)
from aegistrace.mutations import mutation
from aegistrace.platform_api import record_request
from aegistrace.repository import require_access
from aegistrace.schema_v1 import assessments, observations, tool_runs
from aegistrace.settings import Settings


def _latest_reviews(connection: Connection, assessment_id: UUID) -> list[dict[str, Any]]:
    rows = (
        connection.execute(
            select(resources.c.payload)
            .where(
                resources.c.assessment_id == str(assessment_id),
                resources.c.kind == "correlation-reviews",
            )
            .order_by(resources.c.id)
            .limit(1001)
        )
        .scalars()
        .all()
    )
    if len(rows) > 1000:
        raise HTTPException(409, "Correlation review history exceeds the review limit")
    return sorted((dict(row) for row in rows), key=lambda row: int(row["revision"]))


def correlation_router(engine: Engine, config: Settings) -> APIRouter:
    router = APIRouter(
        prefix="/api/v1/assessments/{assessment_id}/correlations", tags=["correlation"]
    )
    actor_dependency = Depends(identity_dependency(config))

    @router.get("/reviews")
    def list_reviews(assessment_id: UUID, actor: Identity = actor_dependency) -> dict[str, Any]:
        try:
            with engine.begin() as connection:
                require_access(connection, assessment_id, actor.subject)
                history = _latest_reviews(connection, assessment_id)
                latest = history[-1] if history else None
                active = latest["request"].get("reviewed_clusters", []) if latest else []
                observation_rows = (
                    connection.execute(
                        select(observations.c.payload)
                        .where(observations.c.assessment_id == str(assessment_id))
                        .order_by(observations.c.id)
                        .limit(1001)
                    )
                    .scalars()
                    .all()
                )
                if len(observation_rows) > 1000:
                    raise HTTPException(409, "Observation inventory exceeds the review limit")
                run_rows = (
                    connection.execute(
                        select(tool_runs.c.id, tool_runs.c.payload).where(
                            tool_runs.c.assessment_id == str(assessment_id)
                        )
                    )
                    .mappings()
                    .all()
                )
                run_tools = {str(row["id"]): row["payload"]["tool"] for row in run_rows}
                rendered_observations = [
                    dict(value)
                    | {"source_tool": run_tools.get(str(value.get("run_id")), "unknown")}
                    for value in observation_rows
                ]
                reviewed = materialize_clusters(
                    active,
                    rendered_observations,
                )
                active_splits = latest["request"].get("reviewed_splits", []) if latest else []
                reviewed_splits = materialize_splits(active_splits, rendered_observations)
                return {
                    "review_state": "reviewer-overrides-active"
                    if reviewed or reviewed_splits
                    else "no-reviewer-overrides",
                    "revision": int(latest["revision"]) if latest else 0,
                    "reviews": [
                        {
                            key: value
                            for key, value in item.items()
                            if key in {"id", "revision", "created_at", "request"}
                        }
                        | {
                            "request": {
                                key: item["request"].get(key)
                                for key in (
                                    "action",
                                    "rationale",
                                    "recorded_by",
                                    "recorded_at",
                                    "provenance_kind",
                                )
                            }
                        }
                        for item in history[-100:]
                    ],
                    "history_truncated": len(history) > 100,
                    "reviewed_clusters": reviewed,
                    "reviewed_splits": reviewed_splits,
                }
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error

    @router.post("/reviews", response_model=WorkflowResource, status_code=201)
    def save_review(
        assessment_id: UUID,
        body: CorrelationReviewCreate,
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
            history = _latest_reviews(connection, assessment_id)
            prior = history[-1] if history else None
            revision = int(prior["revision"]) + 1 if prior else 1
            prior_clusters = prior["request"].get("reviewed_clusters", []) if prior else []
            prior_splits = prior["request"].get("reviewed_splits", []) if prior else []
            known_ids = {
                str(value)
                for group in [*prior_clusters, *prior_splits]
                for value in group["observation_ids"]
            }
            requested_ids = set(str(value) for value in body.observation_ids)
            for group in body.partitions:
                requested_ids.update(str(value) for value in group)
            if requested_ids:
                found = set(
                    connection.execute(
                        select(observations.c.id).where(
                            observations.c.assessment_id == str(assessment_id),
                            observations.c.id.in_(requested_ids),
                        )
                    ).scalars()
                )
                if found != requested_ids:
                    raise HTTPException(404, "One or more observations are not in this assessment")
                known_ids.update(found)
            if body.action == "merge":
                try:
                    current = normalize_clusters(prior_clusters, known_ids)
                    next_clusters = merge_clusters(
                        current, requested_ids, body.rationale, known_ids
                    )
                    if any(
                        requested_ids.intersection(split["observation_ids"])
                        and not set(split["observation_ids"]) <= requested_ids
                        for split in prior_splits
                    ):
                        raise ValueError(
                            "merge must select every member of an existing split decision"
                        )
                    next_splits = [
                        split
                        for split in prior_splits
                        if not requested_ids.intersection(split["observation_ids"])
                    ]
                except ValueError as error:
                    raise HTTPException(409, str(error)) from error
            elif body.action == "split":
                try:
                    current = normalize_clusters(prior_clusters, known_ids)
                    target = next(
                        (item for item in current if item["cluster_id"] == body.cluster_id),
                        None,
                    )
                    if target is None:
                        raise ValueError("reviewed cluster not found")
                    next_clusters = split_cluster(
                        current,
                        str(body.cluster_id),
                        [[str(value) for value in group] for group in body.partitions],
                        body.rationale,
                        known_ids,
                    )
                    split_record = {
                        "cluster_id": target["cluster_id"],
                        "observation_ids": target["observation_ids"],
                        "partitions": [
                            sorted(str(value) for value in group) for group in body.partitions
                        ],
                        "rationale": body.rationale.strip(),
                    }
                    next_splits = [
                        item
                        for item in prior_splits
                        if not set(item["observation_ids"]).intersection(target["observation_ids"])
                    ] + [split_record]
                except ValueError as error:
                    raise HTTPException(409, str(error)) from error
            else:
                if (
                    prior is None
                    or prior["id"] != str(body.target_review_id)
                    or prior["request"].get("action") == "undo"
                ):
                    raise HTTPException(409, "Only the latest non-undo review can be undone")
                next_clusters = normalize_clusters(
                    prior["request"].get("previous_clusters", []), known_ids
                )
                next_splits = prior["request"].get("previous_splits", [])
            stored_request = request_payload | {
                "reviewed_clusters": next_clusters,
                "reviewed_splits": next_splits,
                "previous_clusters": prior_clusters,
                "previous_splits": prior_splits,
                "recorded_by": actor.subject,
                "recorded_at": datetime.now(UTC).isoformat(),
                "provenance_kind": "explicit human reviewer decision; source observations unchanged",
            }
            value = WorkflowResource.model_validate(
                {
                    "id": uuid4(),
                    "assessment_id": assessment_id,
                    "kind": "correlation-reviews",
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
                    kind="correlation-reviews",
                    payload=value,
                )
            )
            record_request(
                connection,
                assessment_id,
                actor,
                "correlation.review-recorded",
                UUID(value["id"]),
                value,
            )
            return value

        return mutation(engine, request, actor, request_payload, apply, 201)

    return router

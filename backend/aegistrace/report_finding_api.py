"""Append-only reviewer report content linked to assessment-owned observations."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import Connection, Engine, select

from aegistrace.api_contracts import ReportFindingCreate, WorkflowResource
from aegistrace.api_schema import resources
from aegistrace.auth import Identity, identity_dependency
from aegistrace.mutations import mutation
from aegistrace.platform_api import record_request
from aegistrace.repository import require_access
from aegistrace.schema_v1 import assessments, observations
from aegistrace.settings import Settings


def report_finding_history(connection: Connection, assessment_id: UUID) -> list[dict[str, Any]]:
    values = (
        connection.execute(
            select(resources.c.payload)
            .where(
                resources.c.assessment_id == str(assessment_id),
                resources.c.kind == "report-findings",
            )
            .limit(1001)
        )
        .scalars()
        .all()
    )
    if len(values) > 1000:
        raise ValueError("Report finding history exceeds snapshot limit")
    return sorted((dict(value) for value in values), key=lambda value: int(value["revision"]))


def latest_report_findings(history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for value in history:
        latest[str(value["request"]["finding_id"])] = value
    return sorted(latest.values(), key=lambda value: value["request"]["finding_id"])


def report_finding_router(engine: Engine, config: Settings) -> APIRouter:
    router = APIRouter(
        prefix="/api/v1/assessments/{assessment_id}/report-findings", tags=["report-content"]
    )
    actor_dependency = Depends(identity_dependency(config))

    @router.get("")
    def listing(assessment_id: UUID, actor: Identity = actor_dependency) -> dict[str, Any]:
        try:
            with engine.begin() as connection:
                require_access(connection, assessment_id, actor.subject)
                history = report_finding_history(connection, assessment_id)
                return {
                    "schema_version": "1.0",
                    "revision": history[-1]["revision"] if history else 0,
                    "findings": latest_report_findings(history),
                    "history": history,
                }
        except LookupError as error:
            raise HTTPException(404, "Assessment not found") from error

    @router.post("", status_code=201, response_model=WorkflowResource)
    def save(
        assessment_id: UUID,
        body: ReportFindingCreate,
        request: Request,
        actor: Identity = actor_dependency,
    ) -> JSONResponse:
        def apply(connection: Connection) -> dict[str, Any]:
            require_access(connection, assessment_id, actor.subject)
            if actor.principal_kind != "human" or actor.role not in {"reviewer", "admin"}:
                raise HTTPException(403, "Human reviewer required for report content")
            connection.execute(
                select(assessments.c.id)
                .where(assessments.c.id == str(assessment_id))
                .with_for_update()
            ).one()
            history = report_finding_history(connection, assessment_id)
            revision = int(history[-1]["revision"]) if history else 0
            if body.expected_revision != revision:
                raise HTTPException(409, "Report content changed. Reload and review again.")
            latest = latest_report_findings(history)
            if body.finding_id is not None and not any(
                value["request"]["finding_id"] == str(body.finding_id) for value in latest
            ):
                raise HTTPException(404, "Report finding not found")
            selected = {str(value) for value in body.observation_ids}
            known = set(
                connection.execute(
                    select(observations.c.id).where(
                        observations.c.assessment_id == str(assessment_id),
                        observations.c.id.in_(selected),
                    )
                ).scalars()
            )
            if known != selected:
                raise HTTPException(404, "Report observations must belong to this assessment")
            for value in latest:
                prior = value["request"]
                if prior["finding_id"] != str(body.finding_id) and selected.intersection(
                    prior["observation_ids"]
                ):
                    raise HTTPException(
                        409,
                        "An observation already belongs to another report finding; revise that finding",
                    )
            payload = body.model_dump(mode="json") | {
                "finding_id": str(body.finding_id or uuid4()),
                "information_kind": "reviewer-decision",
                "recorded_by": actor.subject,
                "recorded_at": datetime.now(UTC).isoformat(),
                "confirmation": "content review does not confirm exploitability",
            }
            value = WorkflowResource(
                id=uuid4(),
                assessment_id=assessment_id,
                kind="report-findings",
                revision=revision + 1,
                state="reviewed",
                request=payload,
            ).model_dump(mode="json")
            connection.execute(
                resources.insert().values(
                    id=value["id"],
                    assessment_id=str(assessment_id),
                    kind="report-findings",
                    payload=value,
                )
            )
            record_request(
                connection,
                assessment_id,
                actor,
                "report.finding-reviewed",
                UUID(value["id"]),
                value,
            )
            return value

        return mutation(engine, request, actor, body.model_dump(mode="json"), apply, 201)

    return router

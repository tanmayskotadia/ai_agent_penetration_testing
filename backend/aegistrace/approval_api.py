"""Human review endpoints; deliberately no client-facing grant-consumption endpoint."""

from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Connection, Engine, select

from aegistrace.approval_schema import grants
from aegistrace.approvals import (
    ActionRequest,
    ApprovalView,
    decide,
    request_approval,
    view_approval,
)
from aegistrace.auth import Identity, identity_dependency
from aegistrace.mutations import mutation
from aegistrace.repository import require_access
from aegistrace.settings import Settings


class ReviewDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["approve", "deny", "revoke"]
    action_digest: str = Field(pattern=r"^[a-f0-9]{64}$")


def approval_router(engine: Engine, config: Settings) -> APIRouter:
    router = APIRouter(
        prefix="/api/v1/assessments/{assessment_id}/action-approvals", tags=["human-approval"]
    )
    actor_dependency = Depends(identity_dependency(config))

    @router.post("", status_code=201, response_model=ApprovalView)
    def create(
        assessment_id: UUID,
        body: ActionRequest,
        request: Request,
        actor: Identity = actor_dependency,
    ) -> JSONResponse:
        return mutation(
            engine,
            request,
            actor,
            body.model_dump(mode="json"),
            lambda connection: request_approval(connection, assessment_id, body, actor),
        )

    @router.get("", response_model=list[ApprovalView])
    def listing(assessment_id: UUID, actor: Identity = actor_dependency) -> list[dict[str, Any]]:
        try:
            with engine.connect() as connection:
                require_access(connection, assessment_id, actor.subject)
                ids = (
                    connection.execute(
                        select(grants.c.id)
                        .where(grants.c.assessment_id == str(assessment_id))
                        .order_by(grants.c.id)
                        .limit(100)
                    )
                    .scalars()
                    .all()
                )
                return [
                    view_approval(connection, assessment_id, UUID(value), actor) for value in ids
                ]
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error

    @router.get("/{approval_id}", response_model=ApprovalView)
    def read(
        assessment_id: UUID, approval_id: UUID, actor: Identity = actor_dependency
    ) -> dict[str, Any]:
        try:
            with engine.connect() as connection:
                return view_approval(connection, assessment_id, approval_id, actor)
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error

    @router.post("/{approval_id}/decision", response_model=ApprovalView)
    def review(
        assessment_id: UUID,
        approval_id: UUID,
        body: ReviewDecision,
        request: Request,
        actor: Identity = actor_dependency,
    ) -> JSONResponse:
        if actor.principal_kind != "human" or actor.role not in {"reviewer", "admin"}:
            raise HTTPException(403, "Human reviewer required")

        def apply(connection: Connection) -> dict[str, Any]:
            return decide(
                connection, assessment_id, approval_id, body.decision, body.action_digest, actor
            )

        return mutation(engine, request, actor, body.model_dump(), apply, 200)

    return router

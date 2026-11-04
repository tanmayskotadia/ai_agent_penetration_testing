"""Proposals/context never mint authority, run a model or publish confirmed findings."""

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Connection, Engine, select

from aegistrace.auth import Identity, identity_dependency
from aegistrace.inference_guards import ReasoningProposal, model_context, store_proposal
from aegistrace.mutations import mutation
from aegistrace.reasoning_schema import proposals
from aegistrace.repository import require_access
from aegistrace.settings import Settings


class ContextRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    evidence_ids: tuple[UUID, ...] = Field(min_length=1, max_length=50)


def inference_router(engine: Engine, config: Settings) -> APIRouter:
    router = APIRouter(
        prefix="/api/v1/assessments/{assessment_id}/reasoning", tags=["inference-boundary"]
    )
    actor_dependency = Depends(identity_dependency(config))

    @router.post("/proposals", status_code=201)
    def propose(
        assessment_id: UUID,
        body: ReasoningProposal,
        request: Request,
        actor: Identity = actor_dependency,
    ) -> JSONResponse:
        return mutation(
            engine,
            request,
            actor,
            body.model_dump(mode="json"),
            lambda connection: store_proposal(connection, config, assessment_id, body, actor),
        )

    @router.post("/context")
    def context(
        assessment_id: UUID,
        body: ContextRequest,
        request: Request,
        actor: Identity = actor_dependency,
    ) -> JSONResponse:
        def apply(connection: Connection) -> dict[str, Any]:
            return {
                "information_kind": "reviewed-untrusted-source-context",
                "blocks": model_context(
                    connection, config, assessment_id, body.evidence_ids, actor
                ),
                "model_called": False,
                "execution_enabled": False,
            }

        return mutation(
            engine,
            request,
            actor,
            body.model_dump(mode="json"),
            apply,
            200,
            allow_readonly=True,
            replay_check=lambda connection: model_context(
                connection, config, assessment_id, body.evidence_ids, actor
            ),
        )

    @router.get("/proposals/{proposal_id}")
    def read(
        assessment_id: UUID, proposal_id: UUID, actor: Identity = actor_dependency
    ) -> dict[str, Any]:
        try:
            with engine.connect() as connection:
                require_access(connection, assessment_id, actor.subject)
                value = connection.execute(
                    select(proposals.c.payload).where(
                        proposals.c.id == str(proposal_id),
                        proposals.c.assessment_id == str(assessment_id),
                    )
                ).scalar_one_or_none()
                if value is None:
                    raise LookupError("not found")
                return dict(value)
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error

    return router

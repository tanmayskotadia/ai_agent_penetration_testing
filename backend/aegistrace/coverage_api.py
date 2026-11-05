"""Owned live snapshots of the same coverage payload frozen into reports."""

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import Engine

from aegistrace.auth import Identity, identity_dependency
from aegistrace.coverage import assessment_coverage
from aegistrace.repository import require_access
from aegistrace.settings import Settings


def coverage_router(engine: Engine, config: Settings) -> APIRouter:
    router = APIRouter(prefix="/api/v1/assessments/{assessment_id}/coverage", tags=["coverage"])
    actor_dependency = Depends(identity_dependency(config))

    @router.get("")
    def snapshot(assessment_id: UUID, actor: Identity = actor_dependency) -> dict[str, Any]:
        try:
            with engine.begin() as connection:
                require_access(connection, assessment_id, actor.subject)
                return assessment_coverage(connection, assessment_id)
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error

    return router

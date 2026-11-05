"""Assessment-owned API check requests and secrets; execution stays in private workers."""

import hashlib
import hmac
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import Engine, select

from aegistrace.api_assessment import Credential
from aegistrace.api_check_schema import api_checks
from aegistrace.api_check_service import (
    CheckCreate,
    CheckDecision,
    check_row,
    create_check,
    decide_check,
    revoke_secret,
    store_secret,
    view,
)
from aegistrace.auth import Identity, identity_dependency
from aegistrace.mutations import mutation
from aegistrace.repository import require_access
from aegistrace.settings import Settings


def api_check_router(engine: Engine, config: Settings) -> APIRouter:
    router = APIRouter(prefix="/api/v1/assessments/{assessment_id}", tags=["api-assessment"])
    actor_dependency = Depends(identity_dependency(config))

    @router.post("/api-credentials", status_code=201)
    def credential(
        assessment_id: UUID, body: Credential, request: Request, actor: Identity = actor_dependency
    ) -> JSONResponse:
        # The idempotency receipt hashes an HMAC, never raw credential material.
        payload = body.model_dump(mode="json") | {
            "value_fingerprint": hmac.new(
                config.app_secret.get_secret_value().encode(),
                body.value.get_secret_value().encode(),
                hashlib.sha256,
            ).hexdigest()
        }
        return mutation(
            engine,
            request,
            actor,
            payload,
            lambda connection: store_secret(connection, config, assessment_id, body, actor),
        )

    @router.post("/api-credentials/{credential_id}/revoke")
    def revoke(
        assessment_id: UUID,
        credential_id: UUID,
        request: Request,
        actor: Identity = actor_dependency,
    ) -> JSONResponse:
        return mutation(
            engine,
            request,
            actor,
            {"credential_id": str(credential_id)},
            lambda connection: revoke_secret(connection, assessment_id, credential_id, actor),
            200,
        )

    @router.post("/api-checks", status_code=201)
    def create(
        assessment_id: UUID, body: CheckCreate, request: Request, actor: Identity = actor_dependency
    ) -> JSONResponse:
        return mutation(
            engine,
            request,
            actor,
            body.model_dump(mode="json"),
            lambda connection: create_check(connection, config, assessment_id, body, actor),
        )

    @router.post("/api-checks/{check_id}/decision")
    def decision(
        assessment_id: UUID,
        check_id: UUID,
        body: CheckDecision,
        request: Request,
        actor: Identity = actor_dependency,
    ) -> JSONResponse:
        return mutation(
            engine,
            request,
            actor,
            body.model_dump(mode="json"),
            lambda connection: decide_check(
                connection, config, assessment_id, check_id, body, actor
            ),
            200,
        )

    @router.get("/api-checks")
    def listing(assessment_id: UUID, actor: Identity = actor_dependency) -> list[dict[str, Any]]:
        with engine.connect() as connection:
            require_access(connection, assessment_id, actor.subject)
            rows = connection.execute(
                select(api_checks)
                .where(api_checks.c.assessment_id == str(assessment_id))
                .order_by(api_checks.c.id)
                .limit(100)
            ).mappings()
            return [view(dict(row)) for row in rows]

    @router.get("/api-checks/{check_id}")
    def read(
        assessment_id: UUID, check_id: UUID, actor: Identity = actor_dependency
    ) -> dict[str, Any]:
        try:
            with engine.connect() as connection:
                require_access(connection, assessment_id, actor.subject)
                return view(check_row(connection, assessment_id, check_id))
        except LookupError as error:
            raise HTTPException(404, "API check not found") from error

    @router.get("/api-checks/{check_id}/export")
    def export(assessment_id: UUID, check_id: UUID, actor: Identity = actor_dependency) -> Response:
        import json

        with engine.connect() as connection:
            require_access(connection, assessment_id, actor.subject)
            row = check_row(connection, assessment_id, check_id)
            if row["state"] not in {"completed", "cancelled", "unknown"}:
                raise HTTPException(409, "Check has not reached a terminal state")
            return Response(
                json.dumps(view(row), sort_keys=True),
                media_type="application/json",
                headers={
                    "Content-Disposition": f'attachment; filename="api-check-{check_id}.json"',
                    "Cache-Control": "no-store",
                },
            )

    return router

"""Authenticated evidence routes using the same transactional mutation receipts."""

import hashlib
import time
from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import Connection, Engine, select

from aegistrace.auth import Identity, identity_dependency, seal, unseal
from aegistrace.evidence import MAX_BYTES, EvidenceError, EvidenceStore
from aegistrace.evidence_schema import objects
from aegistrace.mutations import mutation
from aegistrace.repository import require_access
from aegistrace.settings import Settings


def evidence_router(engine: Engine, config: Settings) -> APIRouter:
    router = APIRouter(prefix="/api/v1/assessments/{assessment_id}/evidence", tags=["evidence"])
    actor_dependency = Depends(identity_dependency(config))

    def store() -> EvidenceStore:
        try:
            return EvidenceStore(config)
        except EvidenceError as error:
            raise HTTPException(503, str(error)) from error

    @router.put("/{evidence_id}/original", status_code=201)
    async def upload(
        assessment_id: UUID,
        evidence_id: UUID,
        request: Request,
        expires_at: datetime,
        actor: Identity = actor_dependency,
    ) -> JSONResponse:
        raw = bytearray()
        async for chunk in request.stream():
            raw.extend(chunk)
            if len(raw) > MAX_BYTES:
                raise HTTPException(413, "Evidence exceeds 2 MiB")

        def apply(connection: Connection) -> dict[str, Any]:
            store().put(
                connection, assessment_id, evidence_id, actor.subject, bytes(raw), expires_at
            )
            return {"id": str(evidence_id), "status": "stored"}

        return mutation(
            engine,
            request,
            actor,
            {"sha256": hashlib.sha256(raw).hexdigest(), "expires_at": expires_at.isoformat()},
            apply,
        )

    @router.post("/{evidence_id}/download-ticket")
    def ticket(
        assessment_id: UUID, evidence_id: UUID, request: Request, actor: Identity = actor_dependency
    ) -> JSONResponse:
        def apply(connection: Connection) -> dict[str, Any]:
            store().read(connection, assessment_id, evidence_id, actor.subject)
            expires = min(actor.expires, int(time.time()) + 60)
            value = seal(
                config.app_secret.get_secret_value(),
                "download",
                {
                    "assessment_id": str(assessment_id),
                    "evidence_id": str(evidence_id),
                    "subject": actor.subject,
                    "expires": expires,
                },
            )
            return {
                "ticket": value,
                "expires_at": expires,
                "requires": "Bearer identity and X-Download-Ticket header",
            }

        return mutation(engine, request, actor, {}, apply, 200, allow_readonly=True)

    @router.get("/{evidence_id}/original")
    def download(
        assessment_id: UUID,
        evidence_id: UUID,
        x_download_ticket: str = Header(),
        actor: Identity = actor_dependency,
    ) -> Response:
        try:
            claims = unseal(config.app_secret.get_secret_value(), "download", x_download_ticket)
            if any(
                claims.get(k) != v
                for k, v in {
                    "assessment_id": str(assessment_id),
                    "evidence_id": str(evidence_id),
                    "subject": actor.subject,
                }.items()
            ):
                raise ValueError("wrong ticket")
        except ValueError as error:
            raise HTTPException(403, "Invalid or expired download ticket") from error
        try:
            with engine.begin() as connection:
                raw = store().read(connection, assessment_id, evidence_id, actor.subject)
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error
        except EvidenceError as error:
            raise HTTPException(409, str(error)) from error
        return Response(
            raw,
            media_type="application/octet-stream",
            headers={
                "Cache-Control": "no-store",
                "Content-Disposition": f'attachment; filename="{evidence_id}.bin"',
                "X-Content-Type-Options": "nosniff",
            },
        )

    @router.post("/{evidence_id}/redaction")
    def redact(
        assessment_id: UUID, evidence_id: UUID, request: Request, actor: Identity = actor_dependency
    ) -> JSONResponse:
        def apply(connection: Connection) -> dict[str, Any]:
            return {
                "snippet": store().redact(connection, assessment_id, evidence_id, actor.subject),
                "review": "required",
                "information_kind": "redacted-source-derivative",
            }

        return mutation(
            engine,
            request,
            actor,
            {},
            apply,
            200,
            replay_check=lambda connection: store().read(
                connection, assessment_id, evidence_id, actor.subject
            ),
        )

    @router.get("/{evidence_id}/reviewed-derivative")
    def reviewed_derivative(
        assessment_id: UUID, evidence_id: UUID, actor: Identity = actor_dependency
    ) -> dict[str, str]:
        try:
            with engine.begin() as connection:
                snippet = EvidenceStore.derivative(
                    connection, assessment_id, evidence_id, actor.subject
                )
                EvidenceStore.event(
                    connection, assessment_id, evidence_id, actor.subject, "derivative-read"
                )
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error
        except EvidenceError as error:
            raise HTTPException(409, str(error)) from error
        return {"snippet": snippet, "information_kind": "reviewed-source-derivative"}

    @router.post("/{evidence_id}/redaction-review")
    def review(
        assessment_id: UUID, evidence_id: UUID, request: Request, actor: Identity = actor_dependency
    ) -> JSONResponse:
        if actor.role not in {"reviewer", "admin"} or actor.principal_kind != "human":
            raise HTTPException(403, "Reviewer identity required")

        def apply(connection: Connection) -> dict[str, Any]:
            require_access(connection, assessment_id, actor.subject)
            row = connection.execute(
                select(objects.c.redacted).where(
                    objects.c.id == str(evidence_id), objects.c.assessment_id == str(assessment_id)
                )
            ).first()
            if row is None or row[0] is None:
                raise LookupError("redaction not found")
            connection.execute(
                objects.update()
                .where(objects.c.id == str(evidence_id))
                .values(redaction_reviewed=True)
            )
            EvidenceStore.event(
                connection, assessment_id, evidence_id, actor.subject, "redaction-reviewed"
            )
            return {"status": "reviewed"}

        return mutation(engine, request, actor, {}, apply, 200)

    return router

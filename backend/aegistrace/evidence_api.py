"""Authenticated evidence routes using the same transactional mutation receipts."""

import hashlib
import time
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import Connection, Engine, select

from aegistrace.auth import Identity, identity_dependency, seal, unseal
from aegistrace.evidence import MAX_BYTES, EvidenceError, EvidenceStore, redacted_snippet
from aegistrace.evidence_schema import objects
from aegistrace.mutations import mutation
from aegistrace.repository import get_record, require_access
from aegistrace.settings import Settings


class EvidenceInspectorView(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    id: UUID
    observation_id: UUID | None
    sha256: str
    raw_reference: str
    pointer_type: str
    captured_at: str
    run_id: UUID
    tool: str
    tool_version: str
    mode: Literal["recorded-import", "live"]
    run_state: str
    information_kind: str
    original_available: bool
    original_access: str
    reviewed_derivative_available: bool
    can_generate_derivative: bool
    can_review_derivative: bool


def evidence_router(engine: Engine, config: Settings) -> APIRouter:
    router = APIRouter(prefix="/api/v1/assessments/{assessment_id}/evidence", tags=["evidence"])
    actor_dependency = Depends(identity_dependency(config))

    def store() -> EvidenceStore:
        try:
            return EvidenceStore(config)
        except EvidenceError as error:
            raise HTTPException(503, str(error)) from error

    @router.get("/{evidence_id}/inspector", response_model=EvidenceInspectorView)
    def inspect(
        assessment_id: UUID,
        evidence_id: UUID,
        response: Response,
        observation_id: UUID | None = None,
        actor: Identity = actor_dependency,
    ) -> dict[str, Any]:
        """Metadata only; originals and unreviewed snippets are never returned here."""
        response.headers["Cache-Control"] = "no-store"
        try:
            with engine.begin() as connection:
                require_access(connection, assessment_id, actor.subject)
                evidence = get_record(connection, "evidence_references", assessment_id, evidence_id)
                if observation_id is not None:
                    observation = get_record(
                        connection, "observations", assessment_id, observation_id
                    )
                    if observation["evidence_id"] != str(evidence_id):
                        raise LookupError("evidence does not match observation")
                run = get_record(connection, "tool_runs", assessment_id, UUID(evidence["run_id"]))
                row = (
                    connection.execute(
                        select(
                            objects.c.expires_at, objects.c.redaction_reviewed, objects.c.size
                        ).where(
                            objects.c.id == str(evidence_id),
                            objects.c.assessment_id == str(assessment_id),
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                available = row is not None and datetime.fromisoformat(
                    row["expires_at"]
                ) > datetime.now(UTC)
                EvidenceStore.event(
                    connection, assessment_id, evidence_id, actor.subject, "inspector-read"
                )
                return {
                    "schema_version": "1.0",
                    "id": str(evidence_id),
                    "observation_id": str(observation_id) if observation_id else None,
                    "sha256": evidence["sha256"],
                    "raw_reference": redacted_snippet(evidence["pointer"].encode()),
                    "pointer_type": evidence["pointer_type"],
                    "captured_at": evidence["captured_at"],
                    "run_id": evidence["run_id"],
                    "tool": run["tool"],
                    "tool_version": run["tool_version"],
                    "mode": run["mode"],
                    "run_state": run["state"],
                    "information_kind": "observed-source-metadata; authenticity not established",
                    "original_available": available,
                    "original_access": "assessment access plus short-lived download ticket; integrity verified at read",
                    "reviewed_derivative_available": bool(
                        available and row and row["redaction_reviewed"]
                    ),
                    "can_generate_derivative": actor.role != "auditor" and available,
                    "can_review_derivative": actor.principal_kind == "human"
                    and actor.role in {"reviewer", "admin"},
                }
        except LookupError as error:
            raise HTTPException(404, "Matching evidence not found") from error

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

"""Human emergency stop and evidence-bound reconciliation, never fabricated cancellation."""

import time
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict
from sqlalchemy import Connection, Engine, select

from aegistrace.approval_schema import claims
from aegistrace.auth import Identity, identity_dependency
from aegistrace.control import cancel_job, control_state, emergency_stop, resume
from aegistrace.control_schema import executions
from aegistrace.evidence import EvidenceStore
from aegistrace.mutations import mutation
from aegistrace.platform_api import record_request
from aegistrace.policy import release_policy
from aegistrace.repository import get_record, require_access
from aegistrace.settings import Settings


class ControlEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    evidence_id: UUID
    attestation: Literal["termination-reviewed", "reset-reviewed"]


def control_router(engine: Engine, config: Settings) -> APIRouter:
    router = APIRouter(
        prefix="/api/v1/assessments/{assessment_id}/controls", tags=["emergency-control"]
    )
    actor_dependency = Depends(identity_dependency(config))

    @router.post("/stop")
    def stop(
        assessment_id: UUID, request: Request, actor: Identity = actor_dependency
    ) -> JSONResponse:
        return mutation(
            engine,
            request,
            actor,
            {},
            lambda connection: emergency_stop(connection, assessment_id, actor),
            200,
        )

    @router.post("/resume")
    def resume_assessment(
        assessment_id: UUID, request: Request, actor: Identity = actor_dependency
    ) -> JSONResponse:
        return mutation(
            engine,
            request,
            actor,
            {},
            lambda connection: resume(connection, assessment_id, actor),
            200,
        )

    @router.get("")
    def status(assessment_id: UUID, actor: Identity = actor_dependency) -> dict[str, Any]:
        try:
            with engine.begin() as connection:
                require_access(connection, assessment_id, actor.subject)
                state = control_state(connection, assessment_id)
                rows = [
                    dict(row)
                    for row in connection.execute(
                        select(executions).where(executions.c.assessment_id == str(assessment_id))
                    ).mappings()
                ]
                for row in rows:
                    if (
                        row["state"] in {"running", "cancel-requested"}
                        and row["lease_until"] <= time.time()
                    ):
                        row["state"] = "unknown"
                        row["reason"] = "worker lease expired; termination not confirmed"
                return state | {"jobs": rows}
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error

    @router.post("/jobs/{claim_id}/cancel")
    def cancel(
        assessment_id: UUID, claim_id: UUID, request: Request, actor: Identity = actor_dependency
    ) -> JSONResponse:
        return mutation(
            engine,
            request,
            actor,
            {},
            lambda connection: cancel_job(connection, assessment_id, claim_id, actor),
            200,
        )

    @router.post("/jobs/{claim_id}/evidence")
    def attest(
        assessment_id: UUID,
        claim_id: UUID,
        body: ControlEvidence,
        request: Request,
        actor: Identity = actor_dependency,
    ) -> JSONResponse:
        if actor.principal_kind != "human" or actor.role not in {"reviewer", "admin"}:
            raise HTTPException(403, "Human reviewer required")

        def apply(connection: Connection) -> dict[str, Any]:
            row = (
                connection.execute(
                    select(executions)
                    .where(
                        executions.c.claim_id == str(claim_id),
                        executions.c.assessment_id == str(assessment_id),
                    )
                    .with_for_update()
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise LookupError("execution not found")
            evidence = get_record(
                connection, "evidence_references", assessment_id, body.evidence_id
            )
            if (
                datetime.fromisoformat(evidence["captured_at"].replace("Z", "+00:00")).timestamp()
                < row["started_at"]
            ):
                raise ValueError("reconciliation evidence predates execution")
            EvidenceStore(config).read(connection, assessment_id, body.evidence_id, actor.subject)
            if (
                body.attestation == "termination-reviewed"
                and row["state"] in {"running", "cancel-requested", "unknown"}
                and (row["state"] == "unknown" or row["lease_until"] <= time.time())
            ):
                state = "reset-required" if row["reset_required"] else "termination-attested"
                updates = {"state": state, "termination_evidence_id": str(body.evidence_id)}
            elif body.attestation == "reset-reviewed" and row["state"] == "reset-required":
                state = "reset-attested"
                updates = {"state": state, "reset_evidence_id": str(body.evidence_id)}
            else:
                raise ValueError("attestation does not match unresolved execution state")
            connection.execute(
                executions.update().where(executions.c.claim_id == str(claim_id)).values(**updates)
            )
            if state in {"termination-attested", "reset-attested"}:
                payload = connection.execute(
                    select(claims.c.payload).where(claims.c.id == str(claim_id))
                ).scalar_one()
                release_policy(connection, UUID(payload["action"]["policy_id"]))
            result = {
                "state": state,
                "evidence_id": str(body.evidence_id),
                "reviewed_by": actor.subject,
                "basis": "human-reviewed evidence; not an automatic target-reset claim",
            }
            record_request(
                connection, assessment_id, actor, "control.evidence-reviewed", claim_id, result
            )
            return result

        return mutation(engine, request, actor, body.model_dump(mode="json"), apply, 200)

    return router

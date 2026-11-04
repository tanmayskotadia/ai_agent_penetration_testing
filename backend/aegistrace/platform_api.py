"""Authenticated owner-bound persistence contracts, without unimplemented side effects."""

import hashlib
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from sqlalchemy import Connection, Engine, func, select

from aegistrace.api_contracts import (
    ApprovalCreate,
    AssessmentCreate,
    AssetCreate,
    EvidenceCreate,
    ImportCreate,
    JobCreate,
    PlanCreate,
    ReportCreate,
    RunCreate,
    ScopeCreate,
    WorkflowResource,
)
from aegistrace.api_schema import resources
from aegistrace.audit import AuditEvent, append_event, checkpoint, read_events, request_context
from aegistrace.auth import Identity, identity_dependency
from aegistrace.domain import Assessment, Asset, EvidenceReference, Finding, ScopeVersion, ToolRun
from aegistrace.identity_schema import members
from aegistrace.mutations import mutation
from aegistrace.repository import get_record, insert_record, require_access
from aegistrace.schema_v1 import assessments, findings, scope_versions
from aegistrace.settings import Settings


def resource(
    connection: Connection, assessment_id: UUID, kind: str, resource_id: UUID
) -> dict[str, Any]:
    row = connection.execute(
        select(resources.c.payload).where(
            resources.c.id == str(resource_id),
            resources.c.assessment_id == str(assessment_id),
            resources.c.kind == kind,
        )
    ).scalar_one_or_none()
    if row is None:
        raise LookupError("resource not found")
    return dict(row)


def record_request(
    connection: Connection,
    assessment_id: UUID,
    actor: Identity,
    action: str,
    resource_id: UUID,
    payload: dict[str, Any],
) -> None:
    context = request_context.get() or (uuid4(), uuid4())
    append_event(
        connection,
        AuditEvent(
            assessment_id=assessment_id,
            actor_id=actor.subject,
            request_id=context[0],
            correlation_id=context[1],
            action=action,
            resource_id=resource_id,
            action_digest=hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest(),
            outcome="accepted",
        ),
    )


def current_scope(
    connection: Connection, assessment_id: UUID, scope_id: UUID, revision: int
) -> dict[str, Any]:
    scope = get_record(connection, "scope_versions", assessment_id, scope_id)
    latest = connection.execute(
        select(func.max(scope_versions.c.revision)).where(
            scope_versions.c.assessment_id == str(assessment_id)
        )
    ).scalar()
    if scope["revision"] != revision or latest != revision:
        raise HTTPException(409, "Stale scope revision")
    return scope


def platform_router(engine: Engine, config: Settings) -> APIRouter:
    router = APIRouter(prefix="/api/v1", tags=["platform"])
    actor_dependency = Depends(identity_dependency(config))

    @router.post("/assessments", response_model=Assessment, status_code=201)
    def create_assessment(
        body: AssessmentCreate, request: Request, actor: Identity = actor_dependency
    ) -> JSONResponse:
        def apply(connection: Connection) -> dict[str, Any]:
            assessment = Assessment(
                name=body.name, owner_id=actor.subject, created_at=datetime.now(UTC)
            )
            insert_record(connection, "assessments", assessment)
            result = assessment.model_dump(mode="json")
            record_request(
                connection, assessment.id, actor, "assessment.created", assessment.id, result
            )
            return result

        return mutation(engine, request, actor, body.model_dump(mode="json"), apply)

    @router.get("/assessments", response_model=list[Assessment])
    def list_assessments(actor: Identity = actor_dependency) -> list[dict[str, Any]]:
        with engine.connect() as connection:
            visible = (
                assessments.c.owner_id == actor.subject
                if actor.session_id is None
                else assessments.c.id.in_(
                    select(members.c.assessment_id).where(
                        members.c.subject == actor.subject, members.c.active.is_(True)
                    )
                )
            )
            return [
                dict(value)
                for value in connection.execute(
                    select(assessments.c.payload)
                    .where(visible)
                    .order_by(assessments.c.id)
                    .limit(100)
                ).scalars()
            ]

    @router.get("/assessments/{assessment_id}", response_model=Assessment)
    def get_assessment(assessment_id: UUID, actor: Identity = actor_dependency) -> dict[str, Any]:
        try:
            with engine.connect() as connection:
                return require_access(connection, assessment_id, actor.subject).model_dump(
                    mode="json"
                )
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error

    @router.post(
        "/assessments/{assessment_id}/scopes", response_model=ScopeVersion, status_code=201
    )
    def create_scope(
        assessment_id: UUID, body: ScopeCreate, request: Request, actor: Identity = actor_dependency
    ) -> JSONResponse:
        def apply(connection: Connection) -> dict[str, Any]:
            require_access(connection, assessment_id, actor.subject)
            # Lock the assessment to serialize scope revision creation on PostgreSQL.
            connection.execute(
                select(assessments.c.id)
                .where(assessments.c.id == str(assessment_id))
                .with_for_update()
            ).one()
            latest = (
                connection.execute(
                    select(func.max(scope_versions.c.revision)).where(
                        scope_versions.c.assessment_id == str(assessment_id)
                    )
                ).scalar()
                or 0
            )
            if body.revision != latest + 1:
                raise HTTPException(409, "Scope revision must follow the current revision")
            if any(
                not target.strip() or len(target) > 500 or any(ord(c) < 32 for c in target)
                for target in body.targets + body.exclusions
            ):
                raise HTTPException(422, "Invalid target identifier")
            scope = ScopeVersion(
                assessment_id=assessment_id, **body.model_dump(exclude={"schema_version"})
            )
            insert_record(connection, "scope_versions", scope)
            result = scope.model_dump(mode="json")
            record_request(connection, assessment_id, actor, "scope.created", scope.id, result)
            return result

        return mutation(engine, request, actor, body.model_dump(mode="json"), apply)

    @router.get("/assessments/{assessment_id}/scopes/{scope_id}", response_model=ScopeVersion)
    def read_scope(
        assessment_id: UUID, scope_id: UUID, actor: Identity = actor_dependency
    ) -> dict[str, Any]:
        try:
            with engine.connect() as connection:
                require_access(connection, assessment_id, actor.subject)
                return get_record(connection, "scope_versions", assessment_id, scope_id)
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error

    def create_workflow(
        kind: str, assessment_id: UUID, body: Any, request: Request, actor: Identity
    ) -> JSONResponse:
        payload = body.model_dump(mode="json")

        def apply(connection: Connection) -> dict[str, Any]:
            require_access(connection, assessment_id, actor.subject)
            if kind in {"plans", "imports"}:
                current_scope(connection, assessment_id, body.scope_id, body.scope_revision)
            if kind in {"jobs", "approvals"}:
                plan = resource(connection, assessment_id, "plans", body.plan_id)
                if plan["revision"] != body.plan_revision:
                    raise HTTPException(409, "Stale plan revision")
                current_scope(
                    connection,
                    assessment_id,
                    UUID(plan["request"]["scope_id"]),
                    plan["request"]["scope_revision"],
                )
            if kind == "imports":
                get_record(connection, "evidence_references", assessment_id, body.evidence_id)
            if kind == "plans" and (
                body.revision != 1 or any(len(step) > 1000 for step in body.steps)
            ):
                raise HTTPException(
                    422, "Create a new draft at revision 1; steps are bounded to 1000 characters"
                )
            states = {
                "plans": "draft",
                "jobs": "blocked",
                "imports": "pending-ingestion",
                "approvals": "pending-review",
                "reports": "blocked",
            }
            reasons = {"jobs": "execution-not-enabled", "reports": "report-renderer-not-enabled"}
            value = WorkflowResource.model_validate(
                dict(
                    id=uuid4(),
                    assessment_id=assessment_id,
                    kind=kind,
                    state=states[kind],
                    reason=reasons.get(kind),
                    mode="recorded-import" if kind == "imports" else "request-only",
                    request=payload,
                )
            ).model_dump(mode="json")
            connection.execute(
                resources.insert().values(
                    id=value["id"], assessment_id=str(assessment_id), kind=kind, payload=value
                )
            )
            record_request(
                connection, assessment_id, actor, f"{kind}.requested", UUID(value["id"]), value
            )
            return value

        return mutation(engine, request, actor, payload, apply, 202)

    @router.post(
        "/assessments/{assessment_id}/plans", response_model=WorkflowResource, status_code=202
    )
    def plan(
        assessment_id: UUID, body: PlanCreate, request: Request, actor: Identity = actor_dependency
    ) -> JSONResponse:
        return create_workflow("plans", assessment_id, body, request, actor)

    @router.post(
        "/assessments/{assessment_id}/jobs", response_model=WorkflowResource, status_code=202
    )
    def job(
        assessment_id: UUID, body: JobCreate, request: Request, actor: Identity = actor_dependency
    ) -> JSONResponse:
        return create_workflow("jobs", assessment_id, body, request, actor)

    @router.post(
        "/assessments/{assessment_id}/imports", response_model=WorkflowResource, status_code=202
    )
    def imported(
        assessment_id: UUID,
        body: ImportCreate,
        request: Request,
        actor: Identity = actor_dependency,
    ) -> JSONResponse:
        return create_workflow("imports", assessment_id, body, request, actor)

    @router.post(
        "/assessments/{assessment_id}/approvals", response_model=WorkflowResource, status_code=202
    )
    def approval(
        assessment_id: UUID,
        body: ApprovalCreate,
        request: Request,
        actor: Identity = actor_dependency,
    ) -> JSONResponse:
        return create_workflow("approvals", assessment_id, body, request, actor)

    @router.post(
        "/assessments/{assessment_id}/reports", response_model=WorkflowResource, status_code=202
    )
    def report(
        assessment_id: UUID,
        body: ReportCreate,
        request: Request,
        actor: Identity = actor_dependency,
    ) -> JSONResponse:
        return create_workflow("reports", assessment_id, body, request, actor)

    @router.get(
        "/assessments/{assessment_id}/resources/{kind}/{resource_id}",
        response_model=WorkflowResource,
    )
    def read_workflow(
        assessment_id: UUID, kind: str, resource_id: UUID, actor: Identity = actor_dependency
    ) -> dict[str, Any]:
        try:
            with engine.connect() as connection:
                require_access(connection, assessment_id, actor.subject)
                return resource(connection, assessment_id, kind, resource_id)
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error

    @router.post("/assessments/{assessment_id}/assets", response_model=Asset, status_code=201)
    def asset(
        assessment_id: UUID, body: AssetCreate, request: Request, actor: Identity = actor_dependency
    ) -> JSONResponse:
        def apply(connection: Connection) -> dict[str, Any]:
            require_access(connection, assessment_id, actor.subject)
            value = Asset(
                assessment_id=assessment_id, **body.model_dump(exclude={"schema_version"})
            )
            insert_record(connection, "assets", value)
            result = value.model_dump(mode="json")
            record_request(connection, assessment_id, actor, "asset.recorded", value.id, result)
            return result

        return mutation(engine, request, actor, body.model_dump(mode="json"), apply)

    @router.post("/assessments/{assessment_id}/runs", response_model=ToolRun, status_code=201)
    def run(
        assessment_id: UUID, body: RunCreate, request: Request, actor: Identity = actor_dependency
    ) -> JSONResponse:
        def apply(connection: Connection) -> dict[str, Any]:
            require_access(connection, assessment_id, actor.subject)
            scope = get_record(connection, "scope_versions", assessment_id, body.scope_id)
            current_scope(connection, assessment_id, body.scope_id, scope["revision"])
            value = ToolRun(
                assessment_id=assessment_id,
                state="recorded",
                **body.model_dump(exclude={"schema_version"}),
            )
            insert_record(connection, "tool_runs", value)
            result = value.model_dump(mode="json")
            record_request(
                connection, assessment_id, actor, "run.recorded-import", value.id, result
            )
            return result

        return mutation(engine, request, actor, body.model_dump(mode="json"), apply)

    @router.post(
        "/assessments/{assessment_id}/runs/{run_id}/evidence",
        response_model=EvidenceReference,
        status_code=201,
    )
    def evidence(
        assessment_id: UUID,
        run_id: UUID,
        body: EvidenceCreate,
        request: Request,
        actor: Identity = actor_dependency,
    ) -> JSONResponse:
        def apply(connection: Connection) -> dict[str, Any]:
            require_access(connection, assessment_id, actor.subject)
            get_record(connection, "tool_runs", assessment_id, run_id)
            value = EvidenceReference(
                assessment_id=assessment_id,
                run_id=run_id,
                **body.model_dump(exclude={"schema_version"}),
            )
            insert_record(connection, "evidence_references", value)
            result = value.model_dump(mode="json")
            record_request(
                connection, assessment_id, actor, "evidence.reference-created", value.id, result
            )
            return result

        return mutation(engine, request, actor, body.model_dump(mode="json"), apply)

    @router.get(
        "/assessments/{assessment_id}/evidence/{evidence_id}", response_model=EvidenceReference
    )
    def evidence_reference(
        assessment_id: UUID, evidence_id: UUID, actor: Identity = actor_dependency
    ) -> dict[str, Any]:
        try:
            with engine.connect() as connection:
                require_access(connection, assessment_id, actor.subject)
                return get_record(connection, "evidence_references", assessment_id, evidence_id)
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error

    @router.get("/assessments/{assessment_id}/findings/{finding_id}", response_model=Finding)
    def finding(
        assessment_id: UUID, finding_id: UUID, actor: Identity = actor_dependency
    ) -> dict[str, Any]:
        try:
            with engine.connect() as connection:
                require_access(connection, assessment_id, actor.subject)
                return get_record(connection, "findings", assessment_id, finding_id)
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error

    @router.get("/assessments/{assessment_id}/findings", response_model=list[Finding])
    def list_findings(
        assessment_id: UUID, actor: Identity = actor_dependency
    ) -> list[dict[str, Any]]:
        try:
            with engine.connect() as connection:
                require_access(connection, assessment_id, actor.subject)
                return [
                    dict(value)
                    for value in connection.execute(
                        select(findings.c.payload)
                        .where(findings.c.assessment_id == str(assessment_id))
                        .order_by(findings.c.id)
                        .limit(100)
                    ).scalars()
                ]
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error

    @router.get("/assessments/{assessment_id}/events")
    def progress(
        assessment_id: UUID,
        last_event_id: int = Header(default=0, ge=0),
        actor: Identity = actor_dependency,
    ) -> StreamingResponse:
        try:
            with engine.connect() as connection:
                require_access(connection, assessment_id, actor.subject)
                rows = read_events(connection, assessment_id, last_event_id, limit=100)
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error

        def frames() -> Iterator[str]:
            for row in rows:
                yield f"id: {row['sequence']}\nevent: audit\ndata: {json.dumps(row['payload'], separators=(',', ':'))}\n\n"
            yield "retry: 2000\n: batch-end; reconnect with last received ID\n\n"

        return StreamingResponse(
            frames(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    @router.get("/assessments/{assessment_id}/audit/checkpoint")
    def anchor(assessment_id: UUID, actor: Identity = actor_dependency) -> JSONResponse:
        try:
            with engine.connect() as connection:
                require_access(connection, assessment_id, actor.subject)
                value = checkpoint(connection, assessment_id, config.app_secret.get_secret_value())
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error
        return JSONResponse(
            value,
            headers={
                "Cache-Control": "no-store",
                "Content-Disposition": f'attachment; filename="audit-{assessment_id}.json"',
            },
        )

    return router

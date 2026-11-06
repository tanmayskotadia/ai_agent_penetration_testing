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
    AssetRiskContextCreate,
    EvidenceCreate,
    ImportCreate,
    JobCreate,
    PlanCreate,
    PlanIntake,
    PlanReviewCreate,
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
from aegistrace.planning_intake import build_intake_plan
from aegistrace.repository import get_record, insert_record, require_access
from aegistrace.result_schema import revisions
from aegistrace.schema_v1 import assessments, assets, findings, scope_versions
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


def plan_digest(plan: dict[str, Any]) -> str:
    content = {
        "id": plan["id"],
        "revision": plan["revision"],
        "request": {key: value for key, value in plan["request"].items() if key != "review_digest"},
    }
    return hashlib.sha256(
        json.dumps(content, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


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
            actor_kind="service" if actor.principal_kind == "service" else "human",
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

    @router.get("/assessments/{assessment_id}/scopes", response_model=list[ScopeVersion])
    def list_scopes(
        assessment_id: UUID, actor: Identity = actor_dependency
    ) -> list[dict[str, Any]]:
        with engine.connect() as connection:
            require_access(connection, assessment_id, actor.subject)
            return [
                dict(row)
                for row in connection.execute(
                    select(scope_versions.c.payload)
                    .where(scope_versions.c.assessment_id == str(assessment_id))
                    .order_by(scope_versions.c.revision)
                ).scalars()
            ]

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
                if plan["state"] != "draft":
                    raise HTTPException(409, "Blocked plans cannot be scheduled or approved")
                reviews = connection.execute(
                    select(resources.c.payload).where(
                        resources.c.assessment_id == str(assessment_id),
                        resources.c.kind == "plan-reviews",
                    )
                ).scalars()
                if any(
                    item["request"].get("plan_id") == str(body.plan_id)
                    and item["request"].get("decision") == "reject"
                    for item in reviews
                ):
                    raise HTTPException(409, "Rejected plan cannot be scheduled or approved")
                if not plan.get("request", {}).get("scope_id"):
                    raise HTTPException(409, "Plan has no bound scope revision")
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
        "/assessments/{assessment_id}/plans/intake",
        response_model=WorkflowResource,
        status_code=202,
    )
    def intake_plan(
        assessment_id: UUID,
        body: PlanIntake,
        request: Request,
        actor: Identity = actor_dependency,
    ) -> JSONResponse:
        """Persist an explainable import-only plan revision; never executes tools."""
        conversation_id = body.conversation_id or uuid4()
        request_payload = body.model_dump(mode="json") | {"conversation_id": str(conversation_id)}

        def apply(connection: Connection) -> dict[str, Any]:
            require_access(connection, assessment_id, actor.subject)
            connection.execute(
                select(assessments.c.id)
                .where(assessments.c.id == str(assessment_id))
                .with_for_update()
            ).one()
            scope: dict[str, Any] | None = None
            if body.scope_id is not None and body.scope_revision is not None:
                scope = current_scope(connection, assessment_id, body.scope_id, body.scope_revision)
            prior_results: list[dict[str, Any]] = []
            for revision_id in body.prior_result_revision_ids:
                revision_payload = connection.execute(
                    select(revisions.c.payload).where(
                        revisions.c.id == str(revision_id),
                        revisions.c.assessment_id == str(assessment_id),
                    )
                ).scalar_one_or_none()
                if revision_payload is None:
                    raise HTTPException(422, "Prior result revision is not part of this assessment")
                prior_revision = dict(revision_payload)
                prior_run = get_record(
                    connection, "tool_runs", assessment_id, UUID(prior_revision["run_id"])
                )
                prior_scope = get_record(
                    connection, "scope_versions", assessment_id, UUID(prior_run["scope_id"])
                )
                same_scope = bool(
                    scope is not None
                    and prior_scope["id"] == scope["id"]
                    and prior_scope["revision"] == scope["revision"]
                )
                prior_results.append(
                    {
                        "id": str(revision_id),
                        "tool": prior_revision["tool"],
                        "state": prior_revision["state"],
                        "same_scope": same_scope,
                    }
                )
            previous_values = connection.execute(
                select(resources.c.payload).where(
                    resources.c.assessment_id == str(assessment_id),
                    resources.c.kind == "plans",
                )
            ).scalars()
            previous = [
                dict(value)
                for value in previous_values
                if value.get("request", {}).get("conversation_id") == str(conversation_id)
            ]
            prior = max(previous, key=lambda item: int(item.get("revision", 0)), default=None)
            revision = int(prior["revision"]) + 1 if prior else 1
            proposal = build_intake_plan(
                body.message,
                scope=scope,
                constraints=body.constraints,
                prior_results=prior_results,
            )
            stored_request = request_payload | {
                "scope_id": str(body.scope_id) if body.scope_id else None,
                "scope_revision": body.scope_revision,
                "conversation_id": str(conversation_id),
                "supersedes_plan_id": prior["id"] if prior else None,
                "proposal": proposal,
            }
            proposal_blockers = proposal.get("blockers")
            blockers = proposal_blockers if isinstance(proposal_blockers, list) else []
            value = WorkflowResource.model_validate(
                {
                    "id": uuid4(),
                    "assessment_id": assessment_id,
                    "kind": "plans",
                    "revision": revision,
                    "state": "blocked" if blockers else "draft",
                    "reason": ",".join(str(item) for item in blockers) or None,
                    "mode": "request-only",
                    "request": stored_request,
                }
            ).model_dump(mode="json")
            value["request"]["review_digest"] = plan_digest(value)
            connection.execute(
                resources.insert().values(
                    id=value["id"], assessment_id=str(assessment_id), kind="plans", payload=value
                )
            )
            record_request(
                connection, assessment_id, actor, "plan.intake-created", UUID(value["id"]), value
            )
            return value

        return mutation(engine, request, actor, request_payload, apply, 202)

    @router.post(
        "/assessments/{assessment_id}/plans/{plan_id}/reviews",
        response_model=WorkflowResource,
        status_code=201,
    )
    def review_plan(
        assessment_id: UUID,
        plan_id: UUID,
        body: PlanReviewCreate,
        request: Request,
        actor: Identity = actor_dependency,
    ) -> JSONResponse:
        def apply(connection: Connection) -> dict[str, Any]:
            require_access(connection, assessment_id, actor.subject)
            if actor.principal_kind != "human" or actor.role not in {"reviewer", "admin"}:
                raise HTTPException(403, "A human reviewer is required")
            connection.execute(
                select(assessments.c.id)
                .where(assessments.c.id == str(assessment_id))
                .with_for_update()
            ).one()
            try:
                plan = resource(connection, assessment_id, "plans", plan_id)
            except LookupError as error:
                raise HTTPException(404, "Plan not found") from error
            if body.plan_revision != plan["revision"] or body.plan_digest != plan_digest(plan):
                raise HTTPException(409, "Plan revision or digest changed")
            scoped = plan["request"]
            if not scoped.get("scope_id"):
                raise HTTPException(409, "Plan has no bound scope")
            current_scope(
                connection, assessment_id, UUID(scoped["scope_id"]), scoped["scope_revision"]
            )
            plans = connection.execute(
                select(resources.c.payload).where(
                    resources.c.assessment_id == str(assessment_id), resources.c.kind == "plans"
                )
            ).scalars()
            conversation = scoped.get("conversation_id")
            if conversation and any(
                item.get("request", {}).get("conversation_id") == conversation
                and item["revision"] > plan["revision"]
                for item in plans
            ):
                raise HTTPException(409, "Plan has been superseded")
            if body.decision == "approve" and plan["state"] != "draft":
                raise HTTPException(409, "Blocked plan cannot be approved")
            prior_reviews = connection.execute(
                select(resources.c.payload).where(
                    resources.c.assessment_id == str(assessment_id),
                    resources.c.kind == "plan-reviews",
                )
            ).scalars()
            if any(item["request"].get("plan_id") == str(plan_id) for item in prior_reviews):
                raise HTTPException(409, "Plan already reviewed; create a new plan revision")
            value = WorkflowResource.model_validate(
                dict(
                    id=uuid4(),
                    assessment_id=assessment_id,
                    kind="plan-reviews",
                    state="reviewed",
                    mode="request-only",
                    reason="recorded-decision-only; execution-not-authorized",
                    request=body.model_dump(mode="json")
                    | {
                        "plan_id": str(plan_id),
                        "reviewer": actor.subject,
                        "information_kind": "human reviewer decision",
                        "reviewed_at": datetime.now(UTC).isoformat(),
                        "authorizes_execution": False,
                    },
                )
            ).model_dump(mode="json")
            connection.execute(
                resources.insert().values(
                    id=value["id"],
                    assessment_id=str(assessment_id),
                    kind="plan-reviews",
                    payload=value,
                )
            )
            record_request(
                connection, assessment_id, actor, "plan.reviewed", UUID(value["id"]), value
            )
            return value

        return mutation(
            engine,
            request,
            actor,
            body.model_dump(mode="json") | {"plan_id": str(plan_id)},
            apply,
            201,
        )

    @router.get("/assessments/{assessment_id}/plan-reviews", response_model=list[WorkflowResource])
    def list_plan_reviews(
        assessment_id: UUID, actor: Identity = actor_dependency
    ) -> list[dict[str, Any]]:
        try:
            with engine.connect() as connection:
                require_access(connection, assessment_id, actor.subject)
                return [
                    dict(value)
                    for value in connection.execute(
                        select(resources.c.payload).where(
                            resources.c.assessment_id == str(assessment_id),
                            resources.c.kind == "plan-reviews",
                        )
                    ).scalars()
                ]
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error

    @router.get("/assessments/{assessment_id}/plans", response_model=list[WorkflowResource])
    def list_plans(assessment_id: UUID, actor: Identity = actor_dependency) -> list[dict[str, Any]]:
        try:
            with engine.connect() as connection:
                require_access(connection, assessment_id, actor.subject)
                return [
                    dict(value)
                    for value in connection.execute(
                        select(resources.c.payload).where(
                            resources.c.assessment_id == str(assessment_id),
                            resources.c.kind == "plans",
                        )
                    ).scalars()
                ]
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error

    @router.get("/assessments/{assessment_id}/assets")
    def list_assets(
        assessment_id: UUID, actor: Identity = actor_dependency
    ) -> list[dict[str, Any]]:
        try:
            with engine.connect() as connection:
                require_access(connection, assessment_id, actor.subject)
                return [
                    dict(value)
                    for value in connection.execute(
                        select(assets.c.payload)
                        .where(assets.c.assessment_id == str(assessment_id))
                        .order_by(assets.c.identifier)
                    ).scalars()
                ]
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error

    @router.get("/assessments/{assessment_id}/asset-contexts")
    def list_asset_contexts(
        assessment_id: UUID, actor: Identity = actor_dependency
    ) -> list[dict[str, Any]]:
        try:
            with engine.connect() as connection:
                require_access(connection, assessment_id, actor.subject)
                rows = connection.execute(
                    select(resources.c.payload).where(
                        resources.c.assessment_id == str(assessment_id),
                        resources.c.kind == "asset-contexts",
                    )
                ).scalars()
                latest: dict[str, dict[str, Any]] = {}
                for row in rows:
                    value = dict(row)
                    asset_id = str(value["request"]["asset_id"])
                    if asset_id not in latest or value["revision"] > latest[asset_id]["revision"]:
                        latest[asset_id] = value
                return list(latest.values())
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error

    @router.post(
        "/assessments/{assessment_id}/asset-contexts",
        response_model=WorkflowResource,
        status_code=201,
    )
    def save_asset_context(
        assessment_id: UUID,
        body: AssetRiskContextCreate,
        request: Request,
        actor: Identity = actor_dependency,
    ) -> JSONResponse:
        request_payload = body.model_dump(mode="json")

        def apply(connection: Connection) -> dict[str, Any]:
            require_access(connection, assessment_id, actor.subject)
            if actor.principal_kind != "human" or actor.role not in {"reviewer", "admin"}:
                raise HTTPException(403, "Reviewer or administrator role required for risk context")
            try:
                get_record(connection, "assets", assessment_id, body.asset_id)
            except LookupError as error:
                raise HTTPException(404, "Asset not found in this assessment") from error
            connection.execute(
                select(assessments.c.id)
                .where(assessments.c.id == str(assessment_id))
                .with_for_update()
            ).one()
            existing = [
                dict(value)
                for value in connection.execute(
                    select(resources.c.payload).where(
                        resources.c.assessment_id == str(assessment_id),
                        resources.c.kind == "asset-contexts",
                    )
                ).scalars()
                if str(value["request"].get("asset_id")) == str(body.asset_id)
            ]
            prior = max(existing, key=lambda value: int(value["revision"]), default=None)
            if body.revision != (int(prior["revision"]) + 1 if prior else 1):
                raise HTTPException(409, "Context revision must follow the latest revision")
            stored = request_payload | {
                "supersedes_context_id": prior["id"] if prior else None,
                "recorded_by": actor.subject,
                "recorded_at": datetime.now(UTC).isoformat(),
                "provenance_kind": "reviewer-supplied; not independently verified",
            }
            value = WorkflowResource.model_validate(
                {
                    "id": uuid4(),
                    "assessment_id": assessment_id,
                    "kind": "asset-contexts",
                    "revision": body.revision,
                    "state": "draft",
                    "mode": "request-only",
                    "request": stored,
                }
            ).model_dump(mode="json")
            connection.execute(
                resources.insert().values(
                    id=value["id"],
                    assessment_id=str(assessment_id),
                    kind="asset-contexts",
                    payload=value,
                )
            )
            record_request(
                connection,
                assessment_id,
                actor,
                "asset.risk-context-recorded",
                UUID(value["id"]),
                value,
            )
            return value

        return mutation(engine, request, actor, request_payload, apply, 201)

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

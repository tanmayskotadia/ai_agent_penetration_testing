"""Reviewed runtime policy intake. A preflight response cannot enable execution."""

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field
from sqlalchemy import Connection, Engine

from aegistrace.auth import Identity, identity_dependency
from aegistrace.lab import Profile
from aegistrace.mutations import mutation
from aegistrace.platform_api import current_scope, record_request
from aegistrace.policy import (
    ExecutionPolicy,
    PolicyError,
    TargetRule,
    authorize,
    load_policy,
    policy_digest,
)
from aegistrace.policy_schema import policies, usage
from aegistrace.safe_parse import matches
from aegistrace.settings import Settings


class PolicyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"] = "1.0"
    scope_id: UUID
    scope_revision: int = Field(ge=1, le=2147483647)
    context: Literal["general", "hackathon"]
    authorization_source: Literal["asset-owner", "organizer"]
    authorization_reference: str = Field(min_length=1, max_length=500)
    authorization_document_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    valid_from: AwareDatetime
    valid_until: AwareDatetime
    targets: tuple[TargetRule, ...] = Field(min_length=1, max_length=200)
    allowed_networks: tuple[str, ...] = Field(min_length=1, max_length=100)
    exclusions: tuple[str, ...] = Field(default=(), max_length=200)
    allowed_profiles: tuple[Profile, ...] = Field(min_length=1)
    requests_per_second: int = Field(ge=1, le=100, strict=True)
    concurrent_jobs: int = Field(ge=1, le=8, strict=True)


class DestinationCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=1, max_length=2500)
    profile: Profile


def policy_router(engine: Engine, config: Settings) -> APIRouter:
    router = APIRouter(prefix="/api/v1/assessments/{assessment_id}/policies", tags=["scope-policy"])
    actor_dependency = Depends(identity_dependency(config))

    @router.post("", response_model=ExecutionPolicy, status_code=201)
    def create(
        assessment_id: UUID,
        body: PolicyCreate,
        request: Request,
        actor: Identity = actor_dependency,
    ) -> JSONResponse:
        if actor.role not in {"reviewer", "admin"}:
            raise HTTPException(403, "Human reviewer identity required")

        def apply(connection: Connection) -> dict[str, Any]:
            scope = current_scope(connection, assessment_id, body.scope_id, body.scope_revision)
            if (
                scope["mode"] != "live-request"
                or scope["authorization_reference"] != body.authorization_reference
            ):
                raise PolicyError(
                    "recorded imports and unmatched references cannot authorize execution"
                )
            for rule in body.targets:
                host = f"[{rule.host}]" if ":" in rule.host else rule.host
                url = f"{rule.protocol}://{host}:{rule.port}{rule.path_prefix}"
                if not any(
                    rule.host == target
                    or (rule.protocol in {"http", "https"} and matches(url, target))
                    for target in scope["targets"]
                ):
                    raise PolicyError("policy target exceeds the versioned scope")
            values = body.model_dump(exclude={"exclusions"})
            values["exclusions"] = tuple(
                dict.fromkeys(tuple(scope["exclusions"]) + body.exclusions)
            )
            policy = ExecutionPolicy(
                assessment_id=assessment_id, reviewed_by=actor.subject, **values
            )
            if scope["valid_until"] and policy.valid_until > datetime.fromisoformat(
                scope["valid_until"].replace("Z", "+00:00")
            ):
                raise PolicyError("policy outlives scope")
            value = policy.model_dump(mode="json")
            connection.execute(
                policies.insert().values(
                    id=str(policy.id),
                    assessment_id=str(assessment_id),
                    scope_id=str(policy.scope_id),
                    payload=value,
                )
            )
            connection.execute(
                usage.insert().values(
                    policy_id=str(policy.id), window_start=0, requests=0, in_flight=0
                )
            )
            record_request(connection, assessment_id, actor, "policy.reviewed", policy.id, value)
            return value

        return mutation(engine, request, actor, body.model_dump(mode="json"), apply)

    @router.post("/{policy_id}/check")
    def check(
        assessment_id: UUID,
        policy_id: UUID,
        body: DestinationCheck,
        request: Request,
        actor: Identity = actor_dependency,
    ) -> JSONResponse:
        def apply(connection: Connection) -> dict[str, Any]:
            policy = load_policy(connection, assessment_id, policy_id)
            value = authorize(
                policy, body.url, body.profile, protected_networks=config.control_plane_networks
            )
            result = {
                "policy_id": str(policy.id),
                "policy_digest": policy_digest(policy),
                "destination": value.model_dump(),
                "execution_enabled": False,
                "state": "policy-checked-not-dispatched",
            }
            record_request(connection, assessment_id, actor, "policy.preflight", policy.id, result)
            return result

        return mutation(engine, request, actor, body.model_dump(mode="json"), apply, 200)

    return router

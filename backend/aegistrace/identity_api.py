"""Human session lifecycle and explicit membership administration."""

import hashlib
import hmac
import threading
from typing import Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from sqlalchemy import Connection, Engine, select, update

from aegistrace.auth import Identity, identity_dependency
from aegistrace.identity_schema import bootstrap_state, principals, sessions
from aegistrace.identity_service import (
    PASSWORDS,
    create_principal,
    issue_session,
    login_attempt,
    set_membership,
    username_value,
    verify_password,
)
from aegistrace.mutations import mutation
from aegistrace.platform_api import record_request
from aegistrace.settings import Settings

LOGIN_SLOTS = threading.BoundedSemaphore(2)


class Login(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    username: str = Field(min_length=3, max_length=200)
    password: SecretStr = Field(min_length=12, max_length=128)


class UserCreate(Login):
    role: Literal["analyst", "reviewer", "admin", "auditor"] = "analyst"


class BootstrapCreate(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    username: str = Field(min_length=3, max_length=200)
    password: SecretStr = Field(min_length=12, max_length=128)


class MembershipUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    subject: str = Field(min_length=1, max_length=200)
    role: Literal["analyst", "reviewer", "admin", "auditor", "scanner", "reporter", "planner"]
    active: bool = True


class PasswordChange(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    old_password: SecretStr = Field(min_length=12, max_length=128)
    new_password: SecretStr = Field(min_length=12, max_length=128)


def credential_digest(config: Settings, password: SecretStr) -> str:
    return hmac.new(
        config.app_secret.get_secret_value().encode(),
        b"password-request:" + password.get_secret_value().encode(),
        hashlib.sha256,
    ).hexdigest()


def identity_router(engine: Engine, config: Settings) -> APIRouter:
    router = APIRouter(prefix="/api/v1", tags=["identity"])
    actor_dependency = Depends(identity_dependency(config))

    @router.post("/auth/bootstrap", status_code=201)
    def bootstrap(
        body: BootstrapCreate,
        request: Request,
        bootstrap_token: str | None = Header(default=None, alias="X-Bootstrap-Token"),
    ) -> JSONResponse:
        """Create the first administrator from a secret supplied by the hosted operator."""
        if config.bootstrap_token is None:
            raise HTTPException(404, "Bootstrap is disabled")
        if config.environment == "production" and request.url.scheme != "https":
            raise HTTPException(403, "HTTPS required")

        source = request.client.host if request.client else "unknown"
        try:
            with engine.begin() as connection:
                login_attempt(connection, "bootstrap", source, config.app_secret.get_secret_value())
        except ValueError as error:
            raise HTTPException(429, "Bootstrap rate limit; retry later") from error

        expected = config.bootstrap_token.get_secret_value()
        if bootstrap_token is None or not hmac.compare_digest(bootstrap_token, expected):
            raise HTTPException(404, "Bootstrap is unavailable")
        try:
            username = username_value(body.username)
        except ValueError as error:
            raise HTTPException(422, "Invalid username") from error

        def apply(connection: Connection) -> dict[str, Any]:
            # Conditional claim is atomic across API instances. The migration inserts the
            # singleton; a pre-existing principal also makes the claim impossible.
            claimed = connection.execute(
                update(bootstrap_state)
                .where(
                    bootstrap_state.c.id == 1,
                    bootstrap_state.c.consumed.is_(False),
                    ~select(principals.c.id).exists(),
                )
                .values(consumed=True)
            )
            if claimed.rowcount != 1:
                raise HTTPException(404, "Bootstrap is unavailable")
            if not LOGIN_SLOTS.acquire(blocking=False):
                raise HTTPException(429, "Bootstrap capacity; retry later")
            try:
                subject = create_principal(
                    connection, username, body.password.get_secret_value(), "admin"
                )
            finally:
                LOGIN_SLOTS.release()
            return issue_session(connection, config, subject)

        try:
            with engine.begin() as connection:
                result = apply(connection)
        except HTTPException:
            raise
        except Exception as error:
            # A duplicate username or transaction failure must not reveal database details.
            raise HTTPException(
                409, "Bootstrap could not create the initial administrator"
            ) from error
        return JSONResponse(
            result,
            status_code=201,
            headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
        )

    @router.post("/auth/login")
    def login(body: Login, request: Request) -> JSONResponse:
        if config.environment == "production" and request.url.scheme != "https":
            raise HTTPException(403, "HTTPS required")
        try:
            username = username_value(body.username)
        except ValueError as error:
            raise HTTPException(401, "Invalid credentials") from error
        try:
            # Commit throttle counters even when authentication fails.
            with engine.begin() as connection:
                login_attempt(
                    connection,
                    username,
                    request.client.host if request.client else "unknown",
                    config.app_secret.get_secret_value(),
                )
        except ValueError as error:
            raise HTTPException(429, "Login rate limit; retry later") from error
        if not LOGIN_SLOTS.acquire(blocking=False):
            raise HTTPException(429, "Login capacity; retry later")
        try:
            with engine.begin() as connection:
                subject = verify_password(connection, username, body.password.get_secret_value())
                if subject is None:
                    raise HTTPException(401, "Invalid credentials")
                value = issue_session(connection, config, subject)
        finally:
            LOGIN_SLOTS.release()
        return JSONResponse(value, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})

    @router.post("/auth/logout")
    def logout(request: Request, actor: Identity = actor_dependency) -> JSONResponse:
        def apply(connection: Connection) -> dict[str, Any]:
            if actor.session_id is None:
                raise HTTPException(409, "Managed session required")
            connection.execute(
                sessions.update()
                .where(sessions.c.id == actor.session_id, sessions.c.subject == actor.subject)
                .values(revoked=True)
            )
            return {"status": "session-revoked"}

        return mutation(engine, request, actor, {}, apply, 200, allow_readonly=True)

    @router.post("/auth/users", status_code=201)
    def user(
        body: UserCreate, request: Request, actor: Identity = actor_dependency
    ) -> JSONResponse:
        if actor.role != "admin" or actor.principal_kind != "human":
            raise HTTPException(403, "Human administrator required")

        def apply(connection: Connection) -> dict[str, Any]:
            subject = create_principal(
                connection, body.username, body.password.get_secret_value(), body.role
            )
            return {
                "subject": subject,
                "username": username_value(body.username),
                "role": body.role,
            }

        return mutation(
            engine,
            request,
            actor,
            {
                "username": body.username,
                "role": body.role,
                "credential_digest": credential_digest(config, body.password),
            },
            apply,
        )

    @router.post("/auth/password")
    def rotate(
        body: PasswordChange, request: Request, actor: Identity = actor_dependency
    ) -> JSONResponse:
        def apply(connection: Connection) -> dict[str, Any]:
            principal = (
                connection.execute(
                    select(principals).where(
                        principals.c.id == actor.subject, principals.c.kind == "human"
                    )
                )
                .mappings()
                .one_or_none()
            )
            if principal is None or not PASSWORDS.verify(
                body.old_password.get_secret_value(), principal["password_hash"]
            ):
                raise HTTPException(401, "Invalid credentials")
            connection.execute(
                principals.update()
                .where(principals.c.id == actor.subject)
                .values(
                    password_hash=PASSWORDS.hash(body.new_password.get_secret_value()),
                    epoch=principals.c.epoch + 1,
                )
            )
            connection.execute(
                sessions.update().where(sessions.c.subject == actor.subject).values(revoked=True)
            )
            return {"status": "password-rotated; sign in again"}

        return mutation(
            engine,
            request,
            actor,
            {
                "old": credential_digest(config, body.old_password),
                "new": credential_digest(config, body.new_password),
            },
            apply,
            200,
            allow_readonly=True,
        )

    @router.post("/auth/users/{subject}/revoke")
    def revoke(subject: str, request: Request, actor: Identity = actor_dependency) -> JSONResponse:
        if actor.principal_kind != "human" or (actor.role != "admin" and subject != actor.subject):
            raise HTTPException(403, "Not permitted")

        def apply(connection: Connection) -> dict[str, Any]:
            if (
                connection.execute(
                    select(principals.c.id).where(principals.c.id == subject)
                ).first()
                is None
            ):
                raise LookupError("not found")
            connection.execute(
                principals.update()
                .where(principals.c.id == subject)
                .values(epoch=principals.c.epoch + 1)
            )
            connection.execute(
                sessions.update().where(sessions.c.subject == subject).values(revoked=True)
            )
            return {"status": "sessions-revoked"}

        return mutation(
            engine, request, actor, {"subject": subject}, apply, 200, allow_readonly=True
        )

    @router.post("/assessments/{assessment_id}/members")
    def membership(
        assessment_id: UUID,
        body: MembershipUpdate,
        request: Request,
        actor: Identity = actor_dependency,
    ) -> JSONResponse:
        if actor.role != "admin" or actor.principal_kind != "human":
            raise HTTPException(403, "Assessment administrator required")

        def apply(connection: Connection) -> dict[str, Any]:
            set_membership(connection, assessment_id, body.subject, body.role, body.active)
            value = body.model_dump()
            record_request(
                connection, assessment_id, actor, "membership.updated", assessment_id, value
            )
            return value

        return mutation(engine, request, actor, body.model_dump(), apply, 200)

    return router

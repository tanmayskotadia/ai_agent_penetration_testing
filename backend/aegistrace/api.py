from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID, uuid4

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from starlette.exceptions import HTTPException as StarletteHTTPException

from aegistrace.api_contracts import ApiError
from aegistrace.audit import AuditEvent, request_context
from aegistrace.capabilities import Capability, capability_snapshot
from aegistrace.db import make_engine
from aegistrace.evidence_api import evidence_router
from aegistrace.http_limits import BodyLimitMiddleware
from aegistrace.identity_api import identity_router
from aegistrace.ingestion import ingestion_router
from aegistrace.log_safety import protect_handlers
from aegistrace.platform_api import platform_router
from aegistrace.policy_api import policy_router
from aegistrace.settings import Settings


def create_app(settings: Settings | None = None) -> FastAPI:
    config = settings or Settings()  # type: ignore[call-arg]
    protect_handlers(
        (
            config.app_secret.get_secret_value(),
            config.evidence_key.get_secret_value() if config.evidence_key else "",
        )
    )
    engine = make_engine(config)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        engine.dispose()

    app = FastAPI(title="AegisTrace", version="0.1.0", lifespan=lifespan)
    app.state.engine = engine
    app.include_router(evidence_router(engine, config))
    app.include_router(platform_router(engine, config))
    app.include_router(ingestion_router(engine, config))
    app.include_router(policy_router(engine, config))
    app.include_router(identity_router(engine, config))
    app.add_middleware(BodyLimitMiddleware)

    def contracts() -> dict[str, Any]:
        if app.openapi_schema is None:
            schema = get_openapi(title=app.title, version=app.version, routes=app.routes)
            components = schema.setdefault("components", {}).setdefault("schemas", {})
            components["AuditEvent"] = AuditEvent.model_json_schema()
            components["ApiError"] = ApiError.model_json_schema()
            capability_schema = Capability.model_json_schema()
            capability_schema.pop("$defs", None)
            components["Capability"] = capability_schema
            for path, methods in schema["paths"].items():
                if not path.startswith("/api/v1/"):
                    continue
                for method, operation in methods.items():
                    if method not in {"get", "post", "put", "patch", "delete"}:
                        continue
                    for code in ["401", "403", "404", "409", "413", "422", "503"]:
                        operation.setdefault("responses", {})[code] = {
                            "description": "Typed API error",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/ApiError"}
                                }
                            },
                        }
                    if (
                        method in {"post", "put", "patch", "delete"}
                        and path != "/api/v1/auth/login"
                    ):
                        operation.setdefault("parameters", []).extend(
                            [
                                {
                                    "name": "X-Request-ID",
                                    "in": "header",
                                    "required": True,
                                    "schema": {"type": "string", "format": "uuid"},
                                },
                                {
                                    "name": "Idempotency-Key",
                                    "in": "header",
                                    "required": True,
                                    "schema": {"type": "string", "minLength": 8, "maxLength": 128},
                                },
                            ]
                        )
            app.openapi_schema = schema
        return app.openapi_schema

    app.openapi = contracts  # type: ignore[method-assign]  # FastAPI's documented schema override.

    @app.exception_handler(StarletteHTTPException)
    async def typed_error(request: Request, error: StarletteHTTPException) -> JSONResponse:
        codes = {
            401: "unauthenticated",
            403: "forbidden",
            404: "not-found",
            409: "conflict",
            413: "body-too-large",
            422: "invalid-request",
            503: "unavailable",
        }
        return JSONResponse(
            {
                "code": codes.get(error.status_code, "request-failed"),
                "message": str(error.detail),
                "request_id": request.headers.get("X-Request-ID"),
            },
            error.status_code,
            headers=error.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def invalid_input(request: Request, _: RequestValidationError) -> JSONResponse:
        return JSONResponse(
            {
                "code": "invalid-request",
                "message": "Input does not match the versioned request schema",
                "request_id": request.headers.get("X-Request-ID"),
            },
            422,
        )

    @app.middleware("http")
    async def attribution(request: Request, call_next: Any) -> Any:
        try:
            request_id = UUID(request.headers.get("X-Request-ID", str(uuid4())))
            correlation_id = UUID(request.headers.get("X-Correlation-ID", str(request_id)))
        except ValueError:
            return JSONResponse(
                {"code": "invalid-request-id", "message": "Request IDs must be UUIDs"}, 422
            )
        token = request_context.set((request_id, correlation_id))
        try:
            response = await call_next(request)
            response.headers["X-Request-ID"] = str(request_id)
            return response
        finally:
            request_context.reset(token)

    @app.get("/health/live")
    def liveness() -> dict[str, str]:
        return {"status": "alive"}

    @app.get("/health/ready")
    def readiness() -> JSONResponse:
        try:
            with engine.connect() as connection:
                revision = connection.execute(
                    text("SELECT version_num FROM alembic_version")
                ).scalar()
            if revision != "0008_identity":
                return JSONResponse({"status": "not-ready", "reason": "migrations required"}, 503)
        except SQLAlchemyError:
            return JSONResponse(
                {"status": "not-ready", "reason": "database or migrations unavailable"}, 503
            )
        return JSONResponse({"status": "ready", "database": "connected", "revision": revision})

    @app.get("/api/v1/system/status")
    def status() -> dict[str, Any]:
        return {
            "stage": "evidence-platform",
            "live_scans_enabled": False,
            "model_enabled": False,
            "authorization": "not-configured",
            "tools": capability_snapshot(),
        }

    @app.get("/api/v1/system/capabilities", response_model=list[Capability])
    def capabilities() -> list[dict[str, object]]:
        return capability_snapshot()

    return app

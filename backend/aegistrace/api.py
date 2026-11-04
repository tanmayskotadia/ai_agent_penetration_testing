from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from uuid import UUID, uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from aegistrace.audit import request_context
from aegistrace.db import make_engine
from aegistrace.evidence import evidence_router
from aegistrace.settings import Settings

TOOLS = ("Nmap", "Nessus", "Greenbone", "Nikto", "OWASP ZAP", "Burp Suite", "Metasploit")


def create_app(settings: Settings | None = None) -> FastAPI:
    config = settings or Settings()  # type: ignore[call-arg]
    engine = make_engine(config)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        yield
        engine.dispose()

    app = FastAPI(title="AegisTrace", version="0.1.0", lifespan=lifespan)
    app.include_router(evidence_router(engine, config))

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
            if revision != "0004_audit":
                return JSONResponse({"status": "not-ready", "reason": "migrations required"}, 503)
        except SQLAlchemyError:
            return JSONResponse(
                {"status": "not-ready", "reason": "database or migrations unavailable"}, 503
            )
        return JSONResponse({"status": "ready", "database": "connected", "revision": revision})

    @app.get("/api/v1/system/status")
    def status() -> dict[str, Any]:
        return {
            "stage": "foundation",
            "live_scans_enabled": False,
            "model_enabled": False,
            "authorization": "not-configured",
            "tools": [{"name": name, "status": "planned"} for name in TOOLS],
        }

    return app

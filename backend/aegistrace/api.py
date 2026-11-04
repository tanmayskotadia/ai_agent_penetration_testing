from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

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
            if revision != "0003_evidence":
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

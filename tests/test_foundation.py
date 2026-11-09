import os
import secrets
import subprocess
import sys
from pathlib import Path

import pytest
from aegistrace.api import create_app
from aegistrace.settings import Settings
from aegistrace_reports import ReportRequest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError


def test_missing_required_config_is_actionable_and_hides_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("APP_SECRET", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(ValidationError) as failure:
        Settings(_env_file=None)
    assert "app_secret" in str(failure.value)
    private = "short-sensitive-input"
    with pytest.raises(ValidationError) as invalid:
        Settings(_env_file=None, app_secret=private, database_url="sqlite:///")
    assert private not in str(invalid.value)


def test_health_is_not_fake_assessment_success(tmp_path: Path) -> None:
    settings = Settings(
        _env_file=None,
        app_secret=SecretStr(secrets.token_hex(32)),
        database_url=f"sqlite:///{tmp_path / 'not-migrated.db'}",
    )
    with TestClient(create_app(settings)) as client:
        assert client.get("/health/live").json() == {"status": "alive"}
        assert client.get("/health/ready").status_code == 503
        status = client.get("/api/v1/system/status").json()
        assert not status["live_scans_enabled"] and not status["model_enabled"]
        assert len(status["tools"]) == 7
        assert {t["status"] for t in status["tools"]} == {"planned"}
        # A built frontend mounts a static fallback (405); without it no route exists (404).
        assert client.post("/api/v1/jobs", json={"target": "unapproved.example"}).status_code in {
            404,
            405,
        }


def test_fresh_database_migrates_and_downgrades(tmp_path: Path) -> None:
    url = f"sqlite:///{tmp_path / 'fresh.db'}"
    environment = os.environ | {"DATABASE_URL": url, "APP_SECRET": secrets.token_hex(32)}
    for revision in ["upgrade", "downgrade", "upgrade"]:
        target = "base" if revision == "downgrade" else "head"
        run = subprocess.run(
            [sys.executable, "-m", "alembic", revision, target],
            env=environment,
            capture_output=True,
            text=True,
        )
        assert run.returncode == 0, run.stderr
    settings = Settings(
        _env_file=None, app_secret=SecretStr(secrets.token_hex(32)), database_url=url
    )
    with TestClient(create_app(settings)) as client:
        assert client.get("/health/ready").status_code == 200


def test_report_request_rejects_nonexistent_identity_shape() -> None:
    with pytest.raises(ValidationError):
        ReportRequest(assessment_id="fabricated-not-a-uuid")


@pytest.mark.services
def test_real_postgresql_and_redis_worker_roundtrip() -> None:
    if os.environ.get("RUN_SERVICE_TESTS") != "1":
        pytest.skip("Requires actual PostgreSQL migrations and running Redis/Celery worker")
    settings = Settings()
    assert settings.database_url.startswith("postgresql+psycopg://")
    with TestClient(create_app(settings)) as client:
        assert client.get("/health/ready").status_code == 200
    from aegistrace_workers.app import create_worker

    worker = create_worker(settings)
    result = worker.send_task("aegistrace.diagnostic.ping")
    assert result.get(timeout=20) == "foundation-pong"


def test_request_diagnostics_log_templates_without_request_data(tmp_path, caplog):
    import json
    from uuid import uuid4

    settings = Settings(
        _env_file=None,
        app_secret=SecretStr(secrets.token_hex(32)),
        database_url=f"sqlite:///{tmp_path / 'diagnostics.db'}",
    )
    caplog.set_level("INFO", logger="uvicorn.error.requests")
    request_id, correlation_id, assessment_id, export_id = (str(uuid4()) for _ in range(4))
    with TestClient(create_app(settings)) as client:
        denied = client.get(
            f"/api/v1/assessments/{assessment_id}/result-exports/{export_id}/pdf",
            params={"debug": "private-query-marker"},
            headers={"X-Request-ID": request_id, "X-Correlation-ID": correlation_id},
        )
        assert client.get("/health/live").status_code == 200
        assert client.get("/health/ready").status_code == 503
    assert denied.status_code == 401
    assert denied.headers["X-Request-ID"] == request_id
    assert denied.headers["X-Correlation-ID"] == correlation_id
    records = [
        json.loads(record.getMessage())
        for record in caplog.records
        if record.name == "uvicorn.error.requests"
    ]
    assert [record["status"] for record in records] == [401, 503]
    assert (
        records[0]["route"] == "/api/v1/assessments/{assessment_id}/result-exports/{export_id}/pdf"
    )
    assert records[0]["correlation_id"] == correlation_id
    assert records[0]["duration_ms"] >= 0
    assert records[1]["route"] == "/health/ready"
    assert all(
        value not in caplog.text for value in (assessment_id, export_id, "private-query-marker")
    )

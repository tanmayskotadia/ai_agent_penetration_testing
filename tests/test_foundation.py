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
        assert client.post("/api/v1/jobs", json={"target": "unapproved.example"}).status_code == 404


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

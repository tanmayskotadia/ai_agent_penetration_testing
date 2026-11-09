"""Restore a CI-only PostgreSQL backup and prove its assessment remains usable."""

import hashlib
import os
import re
import secrets
import subprocess
import sys
from contextlib import ExitStack
from uuid import uuid4

import pytest
from aegistrace.api import create_app
from aegistrace.audit_schema import events
from aegistrace.auth import issue_identity
from aegistrace.result_schema import exports
from aegistrace.results import content_hash
from aegistrace.schema_v1 import scope_versions
from aegistrace.settings import Settings
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.engine import make_url


@pytest.mark.services
def test_postgresql_backup_restore_preserves_report_and_evidence():
    container = os.environ.get("RESTORE_TEST_POSTGRES_CONTAINER")
    if not container:
        pytest.skip("Requires the disposable PostgreSQL container from Foundation CI")

    # This drill only accepts the local CI service and creates two disposable databases.
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert re.fullmatch(r"[a-f0-9]{64}", container)
    url = make_url(os.environ["DATABASE_URL"])
    assert (url.drivername, url.host, url.username, url.database) == (
        "postgresql+psycopg",
        "127.0.0.1",
        "aegistrace",
        "aegistrace",
    )

    from test_minimum_prototype import test_one_assessment_runs_test_only_vertical_slice

    def pg(command, *args, data=None):
        return subprocess.run(
            ["docker", "exec", "-i", container, command, "-U", "aegistrace", *args],
            input=data,
            capture_output=True,
            check=True,
            timeout=60,
        ).stdout

    def database(stack, purpose):
        name = f"recovery_{purpose}_{uuid4().hex}"
        pg("createdb", "--maintenance-db=postgres", name)
        stack.callback(pg, "dropdb", "--maintenance-db=postgres", "--force", name)
        return name

    def headers(settings, subject="t30-test-owner"):
        return {
            "Authorization": "Bearer " + issue_identity(settings, subject, "reviewer"),
            "X-Request-ID": str(uuid4()),
            "Idempotency-Key": str(uuid4()),
        }

    def checkpoints(app, assessment_id):
        with app.state.engine.connect() as connection:
            scope = (
                connection.execute(
                    select(scope_versions.c.payload).where(
                        scope_versions.c.assessment_id == assessment_id
                    )
                )
                .scalars()
                .all()
            )
            audit = connection.execute(
                select(events.c.event_id, events.c.digest)
                .where(events.c.assessment_id == assessment_id)
                .order_by(events.c.sequence)
            ).all()
        assert scope and audit
        return scope, audit

    with ExitStack() as stack:
        source_db = database(stack, "source")
        restored_db = database(stack, "target")
        settings = Settings(
            _env_file=None,
            environment="ci",
            allow_operator_tokens=True,
            database_url=url.set(database=source_db).render_as_string(hide_password=False),
            app_secret=secrets.token_hex(32),
            evidence_key=secrets.token_hex(32),
        )
        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            env=os.environ | {"DATABASE_URL": settings.database_url},
            check=True,
            timeout=60,
        )
        app = create_app(settings)
        stack.callback(app.state.engine.dispose)
        with TestClient(app) as client:
            assert client.get("/health/ready").status_code == 200
            test_one_assessment_runs_test_only_vertical_slice((client, settings))
        with app.state.engine.connect() as connection:
            frozen = connection.execute(select(exports)).mappings().one()
        assert content_hash(frozen["payload"]) == frozen["sha256"]
        expected = checkpoints(app, frozen["assessment_id"])

        archive = pg("pg_dump", "--format=custom", "--dbname", source_db)
        pg(
            "pg_restore",
            "--exit-on-error",
            "--single-transaction",
            "--dbname",
            restored_db,
            data=archive,
        )

        recovered = settings.model_copy(
            update={
                "database_url": url.set(database=restored_db).render_as_string(hide_password=False)
            }
        )
        restored_app = create_app(recovered)
        stack.callback(restored_app.state.engine.dispose)
        assert checkpoints(restored_app, frozen["assessment_id"]) == expected

        base = f"/api/v1/assessments/{frozen['assessment_id']}"
        report = f"{base}/result-exports/{frozen['id']}"
        reference = frozen["payload"]["evidence_references"][0]
        evidence = f"{base}/evidence/{reference['id']}"
        with TestClient(restored_app) as client:
            assert client.get("/health/ready").status_code == 200
            result = client.get(report, headers=headers(recovered))
            assert result.status_code == 200
            assert result.json()["sha256"] == frozen["sha256"]
            assert content_hash(result.json()["snapshot"]) == frozen["sha256"]
            pdf = client.get(report + "/pdf", headers=headers(recovered))
            assert pdf.status_code == 200
            assert frozen["sha256"].encode() in pdf.content
            assert client.get(report + "/pdf").status_code == 401
            outsider = headers(recovered, "other-assessment")
            assert client.get(report + "/pdf", headers=outsider).status_code == 404
            ticket = client.post(evidence + "/download-ticket", json={}, headers=headers(recovered))
            assert ticket.status_code == 200
            original = client.get(
                evidence + "/original",
                headers=headers(recovered) | {"X-Download-Ticket": ticket.json()["ticket"]},
            )
            assert original.status_code == 200
            assert hashlib.sha256(original.content).hexdigest() == reference["sha256"]
            assert (
                client.post(evidence + "/download-ticket", json={}, headers=outsider).status_code
                == 404
            )

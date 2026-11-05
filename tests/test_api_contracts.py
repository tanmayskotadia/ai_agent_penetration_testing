"""Runtime inputs and transactional API contracts, using test-only identifiers."""

import os
import secrets
from concurrent.futures import ThreadPoolExecutor
from uuid import uuid4

import pytest
from aegistrace.api import create_app
from aegistrace.api_schema import resources
from aegistrace.audit_schema import install_guards
from aegistrace.auth import issue_identity
from aegistrace.db import make_engine
from aegistrace.schema_v1 import metadata
from aegistrace.settings import Settings
from fastapi.testclient import TestClient
from sqlalchemy import func, select


@pytest.fixture
def api_context(tmp_path, request):
    settings = Settings(
        _env_file=None,
        app_secret=secrets.token_hex(32),
        evidence_key=secrets.token_hex(32),
        database_url=os.environ["DATABASE_URL"]
        if request.node.get_closest_marker("services")
        else f"sqlite:///{tmp_path / 'api.db'}",
    )
    engine = make_engine(settings)
    metadata.create_all(engine)
    if not request.node.get_closest_marker("services"):
        with engine.begin() as connection:
            install_guards(connection)
    with TestClient(create_app(settings)) as client:
        yield client, settings, engine
    engine.dispose()


def headers(settings, subject="owner", key=None):
    return {
        "Authorization": "Bearer " + issue_identity(settings, subject),
        "X-Request-ID": str(uuid4()),
        "Idempotency-Key": key or str(uuid4()),
    }


def assessment_scope_plan(client, settings):
    assessment = client.post(
        "/api/v1/assessments",
        json={"name": "Test-only runtime assessment"},
        headers=headers(settings),
    ).json()
    base = f"/api/v1/assessments/{assessment['id']}"
    scope = client.post(
        base + "/scopes",
        json={"revision": 1, "targets": ["test-only.invalid"]},
        headers=headers(settings),
    ).json()
    plan = client.post(
        base + "/plans",
        json={
            "scope_id": scope["id"],
            "scope_revision": 1,
            "revision": 1,
            "steps": ["Record evidence; no execution"],
        },
        headers=headers(settings),
    ).json()
    return assessment, scope, plan, base


def test_duplicate_mutations_and_changed_input_conflict(api_context):
    client, settings, engine = api_context
    fixed = headers(settings)
    first = client.post("/api/v1/assessments", json={"name": "Test only"}, headers=fixed)
    second = client.post("/api/v1/assessments", json={"name": "Test only"}, headers=fixed)
    assert first.status_code == second.status_code == 201 and first.json() == second.json()
    assert second.headers["Idempotent-Replay"] == "true"
    conflict = client.post("/api/v1/assessments", json={"name": "Changed"}, headers=fixed)
    assert conflict.status_code == 409 and conflict.json()["code"] == "conflict"
    assessment, scope, plan, base = assessment_scope_plan(client, settings)
    for kind, payload in [
        ("jobs", {"plan_id": plan["id"], "plan_revision": 1}),
        ("reports", {"format": "pdf"}),
    ]:
        fixed = headers(settings)
        a = client.post(base + "/" + kind, json=payload, headers=fixed)
        b = client.post(base + "/" + kind, json=payload, headers=fixed)
        assert a.status_code == b.status_code == 202 and a.json() == b.json()
        assert a.json()["state"] == "blocked" and a.json()["mode"] == "request-only"
        with engine.connect() as connection:
            assert (
                connection.execute(
                    select(func.count())
                    .select_from(resources)
                    .where(resources.c.assessment_id == assessment["id"], resources.c.kind == kind)
                ).scalar()
                == 1
            )


def test_stale_scope_plan_and_other_owner_denied(api_context):
    client, settings, _ = api_context
    _, _, plan, base = assessment_scope_plan(client, settings)
    assert client.get(base, headers=headers(settings, "other")).status_code == 404
    for kind in ["jobs", "approvals"]:
        body = {"plan_id": plan["id"], "plan_revision": 2}
        if kind == "approvals":
            body["action_digest"] = "a" * 64
        response = client.post(base + "/" + kind, json=body, headers=headers(settings))
        assert response.status_code == 409
    assert (
        client.post(
            base + "/scopes",
            json={"revision": 2, "targets": ["new-test-only.invalid"]},
            headers=headers(settings),
        ).status_code
        == 201
    )
    assert (
        client.post(
            base + "/jobs",
            json={"plan_id": plan["id"], "plan_revision": 1},
            headers=headers(settings),
        ).status_code
        == 409
    )


def test_plan_intake_persists_revisions_scope_checks_and_owner_access(api_context):
    client, settings, engine = api_context
    assessment = client.post(
        "/api/v1/assessments", json={"name": "Planning test only"}, headers=headers(settings)
    ).json()
    base = f"/api/v1/assessments/{assessment['id']}"
    conversation_id = str(uuid4())
    blocked = client.post(
        base + "/plans/intake",
        json={"message": "Review https://example.test", "conversation_id": conversation_id},
        headers=headers(settings),
    )
    assert blocked.status_code == 202
    assert blocked.json()["state"] == "blocked"
    assert blocked.json()["request"]["proposal"]["steps"] == []
    cannot_schedule = client.post(
        base + "/jobs",
        json={"plan_id": blocked.json()["id"], "plan_revision": 1},
        headers=headers(settings),
    )
    assert cannot_schedule.status_code == 409

    scope = client.post(
        base + "/scopes",
        json={"revision": 1, "targets": ["example.test"], "exclusions": ["admin.example.test"]},
        headers=headers(settings),
    ).json()
    created = client.post(
        base + "/plans/intake",
        json={
            "message": "Review network and web API evidence",
            "conversation_id": conversation_id,
            "scope_id": scope["id"],
            "scope_revision": scope["revision"],
        },
        headers=headers(settings),
    )
    assert created.status_code == 202
    assert created.json()["revision"] == 2
    assert created.json()["state"] == "draft"
    persisted = client.get(base + "/plans", headers=headers(settings))
    assert persisted.status_code == 200
    assert persisted.json()[-1] == created.json()
    assert client.get(base + "/plans", headers=headers(settings, "other")).status_code == 404

    client.post(
        base + "/scopes",
        json={"revision": 2, "targets": ["new.example.test"]},
        headers=headers(settings),
    )
    stale = client.post(
        base + "/plans/intake",
        json={
            "message": "Review the existing evidence",
            "conversation_id": conversation_id,
            "scope_id": scope["id"],
            "scope_revision": scope["revision"],
        },
        headers=headers(settings),
    )
    assert stale.status_code == 409
    with engine.connect() as connection:
        values = connection.execute(
            select(resources.c.payload).where(
                resources.c.assessment_id == assessment["id"], resources.c.kind == "plans"
            )
        ).scalars()
        assert len(list(values)) == 2


def test_asset_risk_context_requires_reviewer_and_provenance_revisions(api_context):
    client, settings, _ = api_context
    assessment = client.post(
        "/api/v1/assessments", json={"name": "Context test only"}, headers=headers(settings)
    ).json()
    base = f"/api/v1/assessments/{assessment['id']}"
    asset = client.post(
        base + "/assets",
        json={"identifier": "app.test.invalid", "kind": "host"},
        headers=headers(settings),
    ).json()
    payload = {
        "asset_id": asset["id"],
        "revision": 1,
        "exposure": "internet-facing",
        "exposure_reference": "test-only approved inventory row",
        "exploitability": "unknown",
        "criticality": 4,
        "criticality_reference": "test-only reviewer classification",
        "reviewer_note": "Synthetic test context; not real risk evidence.",
    }
    denied = client.post(base + "/asset-contexts", json=payload, headers=headers(settings))
    assert denied.status_code == 403
    reviewer_headers = headers(settings, key=str(uuid4())) | {
        "Authorization": "Bearer " + issue_identity(settings, "owner", "reviewer")
    }
    first = client.post(base + "/asset-contexts", json=payload, headers=reviewer_headers)
    assert first.status_code == 201 and first.json()["revision"] == 1
    next_payload = payload | {"revision": 2, "exposure": "internal"}
    second = client.post(
        base + "/asset-contexts",
        json=next_payload,
        headers=headers(settings, "owner", str(uuid4()))
        | {"Authorization": "Bearer " + issue_identity(settings, "owner", "reviewer")},
    )
    assert (
        second.status_code == 201
        and second.json()["request"]["supersedes_context_id"] == first.json()["id"]
    )
    latest = client.get(
        base + "/asset-contexts",
        headers=headers(settings, "owner")
        | {"Authorization": "Bearer " + issue_identity(settings, "owner", "reviewer")},
    )
    assert len(latest.json()) == 1 and latest.json()[0]["revision"] == 2


def test_sse_resumes_persisted_events_and_checkpoint_download(api_context):
    client, settings, _ = api_context
    _, _, _, base = assessment_scope_plan(client, settings)
    first = client.get(base + "/events", headers=headers(settings))
    assert first.status_code == 200 and "text/event-stream" in first.headers["Content-Type"]
    ids = [int(line[4:]) for line in first.text.splitlines() if line.startswith("id: ")]
    assert ids == [1, 2, 3]
    resumed = client.get(base + "/events", headers=headers(settings) | {"Last-Event-ID": "1"})
    assert "id: 1\n" not in resumed.text and "id: 2\n" in resumed.text
    assert client.get(base + "/events", headers=headers(settings, "other")).status_code == 404
    anchor = client.get(base + "/audit/checkpoint", headers=headers(settings))
    assert (
        anchor.json()["checkpoint"]["sequence"] == 3
        and "attachment" in anchor.headers["Content-Disposition"]
    )


def test_invalid_auth_version_headers_body_and_readonly_role(api_context):
    client, settings, _ = api_context
    assert client.post("/api/v1/assessments", json={"name": "Test"}).status_code == 401
    auth_only = {"Authorization": "Bearer " + issue_identity(settings, "owner")}
    assert (
        client.post("/api/v1/assessments", json={"name": "Test"}, headers=auth_only).status_code
        == 422
    )
    invalid = client.post(
        "/api/v1/assessments",
        json={"name": "Test", "schema_version": "2.0", "secret": "fake-canary-must-not-echo"},
        headers=headers(settings),
    )
    assert invalid.status_code == 422 and "fake-canary" not in invalid.text
    assert (
        client.post(
            "/api/v1/assessments", content=b"x" * 262145, headers=headers(settings)
        ).status_code
        == 413
    )
    readonly = headers(settings) | {
        "Authorization": "Bearer " + issue_identity(settings, "owner", "auditor")
    }
    assert (
        client.post("/api/v1/assessments", json={"name": "Test"}, headers=readonly).status_code
        == 403
    )


def test_concurrent_duplicate_submissions_create_one_resource(api_context):
    client, settings, _ = api_context
    fixed = headers(settings)

    def submit(_):
        return client.post(
            "/api/v1/assessments", json={"name": "Concurrent test only"}, headers=fixed
        )

    with ThreadPoolExecutor(max_workers=4) as pool:
        responses = list(pool.map(submit, range(4)))
    assert {response.status_code for response in responses} == {201}
    assert len({response.json()["id"] for response in responses}) == 1


@pytest.mark.services
def test_postgresql_api_idempotency_and_resumable_events(api_context):
    if os.environ.get("RUN_SERVICE_TESTS") != "1":
        pytest.skip("requires PostgreSQL")
    test_duplicate_mutations_and_changed_input_conflict(api_context)
    test_sse_resumes_persisted_events_and_checkpoint_download(api_context)
    test_concurrent_duplicate_submissions_create_one_resource(api_context)

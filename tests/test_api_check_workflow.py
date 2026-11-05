"""Full private API-check workflow against a disposable test-only application."""

import hashlib
import json
import time
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit
from uuid import UUID, uuid4

import pytest
from aegistrace.api_check_schema import api_checks, api_secrets
from aegistrace.api_check_service import read_secret
from aegistrace.api_check_worker import execute_check, reconcile_expired
from aegistrace.auth import issue_identity
from aegistrace.policy import PolicyError
from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
from sqlalchemy import select

pytest_plugins = ("test_ingestion",)
ORIGIN = "https://192.0.2.10"
TOKEN = "test-only-private-credential"


def prepare(context, origin=ORIGIN):
    client, config = context
    host = urlsplit(origin).hostname
    port = urlsplit(origin).port or 443

    def headers(subject="owner", role="reviewer"):
        return {
            "Authorization": "Bearer " + issue_identity(config, subject, role),
            "X-Request-ID": str(uuid4()),
            "Idempotency-Key": str(uuid4()),
        }

    def post(path, body):
        response = client.post(path, json=body, headers=headers())
        assert response.status_code in {200, 201, 202}, response.text
        return response.json()

    assessment = post(
        "/api/v1/assessments", {"name": "Disposable API workflow; not genuine scan proof"}
    )
    base = "/api/v1/assessments/" + assessment["id"]
    scope = post(
        base + "/scopes",
        {
            "revision": 1,
            "targets": [host],
            "mode": "live-request",
            "authorization_reference": "disposable-test-only",
        },
    )
    now = datetime.now(UTC)
    policy = post(
        base + "/policies",
        {
            "scope_id": scope["id"],
            "scope_revision": 1,
            "context": "general",
            "authorization_source": "asset-owner",
            "authorization_reference": "disposable-test-only",
            "authorization_document_sha256": "a" * 64,
            "valid_from": (now - timedelta(minutes=1)).isoformat(),
            "valid_until": (now + timedelta(minutes=5)).isoformat(),
            "targets": [
                {
                    "host": host,
                    "protocol": "https",
                    "port": port,
                    "pinned_addresses": [host],
                }
            ],
            "allowed_networks": [host + "/32"],
            "allowed_profiles": ["active-web"],
            "requests_per_second": 10,
            "concurrent_jobs": 1,
        },
    )
    definition = {
        "openapi": "3.1.0",
        "servers": [{"url": origin}],
        "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
        "paths": {
            "/public": {"get": {}},
            "/protected": {"get": {"security": [{"bearer": []}]}},
            "/forbidden": {"get": {"security": [{"bearer": []}]}},
            "/delete": {"delete": {}},
        },
    }
    raw = json.dumps(definition).encode()
    run = post(
        base + "/runs",
        {
            "scope_id": scope["id"],
            "tool": "OpenAPI",
            "tool_version": "3.1.0",
            "captured_at": now.isoformat(),
        },
    )
    evidence = post(
        base + "/runs/" + run["id"] + "/evidence",
        {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "pointer": "/",
            "pointer_type": "whole-file",
            "captured_at": now.isoformat(),
        },
    )
    response = client.put(
        base + "/evidence/" + evidence["id"] + "/original",
        content=raw,
        params={"expires_at": (now + timedelta(days=1)).isoformat()},
        headers=headers(),
    )
    assert response.status_code == 201, response.text
    imported = post(
        base + "/imports",
        {
            "scope_id": scope["id"],
            "scope_revision": 1,
            "tool": "OpenAPI",
            "format": "openapi-json",
            "evidence_id": evidence["id"],
        },
    )
    normalized = post(base + "/imports/" + imported["id"] + "/normalize-openapi", {})
    assert normalized["state"] == "normalized"
    secret = post(
        base + "/api-credentials",
        {
            "kind": "bearer",
            "value": TOKEN,
            "origin": origin,
            "expires_at": (now + timedelta(minutes=4)).isoformat(),
        },
    )
    check = post(
        base + "/api-checks",
        {
            "normalization_id": normalized["id"],
            "policy_id": policy["id"],
            "selected_indices": [0, 1, 2],
            "credential_ids": {"bearer": secret["id"]},
            "max_runtime_seconds": 30,
        },
    )
    assert check["state"] == "pending-review"
    return base, headers, post, secret, check


def test_full_import_secret_review_worker_coverage_and_replay(import_context):
    client, config = import_context
    base, headers, post, secret, check = prepare(import_context)
    engine = client.app.state.engine
    assessment_id = UUID(check["assessment_id"])
    check_id = UUID(check["id"])
    with engine.connect() as connection:
        row = (
            connection.execute(select(api_secrets).where(api_secrets.c.id == secret["id"]))
            .mappings()
            .one()
        )
        assert TOKEN.encode() not in row["ciphertext"]
        assert (
            read_secret(
                connection, config, assessment_id, UUID(secret["id"])
            ).value.get_secret_value()
            == TOKEN
        )
    with pytest.raises(PolicyError, match="not approved"):
        execute_check(engine, config, assessment_id, check_id)
    post(
        base + "/api-checks/" + str(check_id) + "/decision",
        {"decision": "approve", "digest": check["plan"]["digest"]},
    )
    app = FastAPI()

    @app.get("/public")
    def public():
        return {"ok": True}

    @app.get("/protected")
    def protected(authorization: str | None = Header(default=None)):
        return JSONResponse({}, status_code=200 if authorization == "Bearer " + TOKEN else 401)

    @app.get("/forbidden")
    def forbidden():
        return JSONResponse({}, status_code=403)

    with TestClient(app) as target:
        result = execute_check(
            engine,
            config,
            assessment_id,
            check_id,
            transport=lambda destination, method, values: (
                target.request(method, destination.path, headers=dict(values)).status_code
            ),
        )
    assert result["attempted_count"] == 3
    assert result["succeeded_count"] == 2
    assert result["operations"][2]["authentication"] == "rejected"
    assert result["operations"][3]["state"] == "excluded"
    assert result["execution_mode"] == "disposable-test"
    saved = client.get(base + "/api-checks/" + str(check_id), headers=headers()).json()
    assert saved["state"] == "completed" and saved["result"]["sha256"] == result["sha256"]
    exported = client.get(base + "/api-checks/" + str(check_id) + "/export", headers=headers())
    assert exported.status_code == 200 and exported.json()["result"] == result
    assert TOKEN not in exported.text
    coverage = client.get(base + "/coverage", headers=headers()).json()
    assert coverage["api_operation_checks"][0]["result"]["attempted_count"] == 3
    for output in (saved, coverage, client.get(base + "/events", headers=headers()).text):
        assert TOKEN not in json.dumps(output)
    assert (
        client.get(base + "/api-checks/" + str(check_id), headers=headers("outsider")).status_code
        == 404
    )
    with pytest.raises(PolicyError, match="already claimed"):
        execute_check(engine, config, assessment_id, check_id)
    post(base + "/api-credentials/" + secret["id"] + "/revoke", {})
    with engine.connect() as connection, pytest.raises(PolicyError):
        read_secret(connection, config, assessment_id, UUID(secret["id"]))


@pytest.mark.parametrize("reason", ["cancel", "revoked-secret", "stale-scope", "tamper", "crash"])
def test_persisted_denials_revocation_stale_scope_and_crash(import_context, reason):
    client, config = import_context
    base, headers, post, secret, check = prepare(import_context)
    engine = client.app.state.engine
    assessment_id, check_id = UUID(check["assessment_id"]), UUID(check["id"])
    post(
        base + "/api-checks/" + str(check_id) + "/decision",
        {"decision": "approve", "digest": check["plan"]["digest"]},
    )
    if reason == "cancel":
        post(
            base + "/api-checks/" + str(check_id) + "/decision",
            {"decision": "cancel", "digest": check["plan"]["digest"]},
        )
    elif reason == "revoked-secret":
        post(base + "/api-credentials/" + secret["id"] + "/revoke", {})
        result = execute_check(engine, config, assessment_id, check_id, transport=lambda *_: 200)
        assert result["attempted_count"] == 1
        assert result["operations"][1]["authentication"] == "unavailable-or-expired"
        return
    elif reason == "stale-scope":
        post(base + "/scopes", {"revision": 2, "targets": ["192.0.2.10"], "mode": "live-request"})
    else:
        with engine.begin() as connection:
            plan = dict(check["plan"])
            if reason == "tamper":
                plan["selected_indices"] = [3]
                state = "queued"
            else:
                plan.update(deadline=time.time() - 1, worker_id="crashed")
                state = "running"
            connection.execute(
                api_checks.update()
                .where(api_checks.c.id == str(check_id))
                .values(state=state, payload=plan)
            )
        if reason == "crash":
            assert reconcile_expired(engine) == 1
    with pytest.raises(PolicyError):
        execute_check(
            engine,
            config,
            assessment_id,
            check_id,
            transport=lambda *_: pytest.fail("must not dispatch"),
        )


@pytest.mark.services
def test_postgresql_api_check_workflow(import_context):
    test_full_import_secret_review_worker_coverage_and_replay(import_context)


def test_cancel_during_execution_stops_remaining_operations(import_context):
    client, config = import_context
    base, _, post, _, check = prepare(import_context)
    path = base + "/api-checks/" + check["id"] + "/decision"
    post(path, {"decision": "approve", "digest": check["plan"]["digest"]})
    calls = []

    def cancel_after_one(*_):
        calls.append(True)
        post(path, {"decision": "cancel", "digest": check["plan"]["digest"]})
        return 200

    result = execute_check(
        client.app.state.engine,
        config,
        UUID(check["assessment_id"]),
        UUID(check["id"]),
        transport=cancel_after_one,
    )
    assert len(calls) == 1 and result["attempted_count"] == 1
    assert result["operations"][1]["state"] == "untested"

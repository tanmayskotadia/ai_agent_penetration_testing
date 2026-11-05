"""Managed identity acceptance with generated disposable credentials only."""

import hashlib
import io
import logging
import os
import secrets
from uuid import UUID, uuid4

import pytest
from aegistrace.api import create_app
from aegistrace.auth import issue_identity, seal, unseal
from aegistrace.db import make_engine
from aegistrace.identity_schema import bootstrap_state, principals, sessions
from aegistrace.identity_service import create_principal, issue_session, set_membership
from aegistrace.log_safety import SafeFormatter
from aegistrace.schema_v1 import metadata
from aegistrace.settings import Settings
from fastapi.testclient import TestClient
from sqlalchemy import select


@pytest.fixture
def identity_context(tmp_path, request):
    config = Settings(
        _env_file=None,
        environment="production",
        app_secret=secrets.token_hex(32),
        database_url=os.environ["DATABASE_URL"]
        if request.node.get_closest_marker("services")
        else f"sqlite:///{tmp_path / 'identity.db'}",
    )
    engine = make_engine(config)
    metadata.create_all(engine)
    password = secrets.token_urlsafe(24)
    with engine.begin() as connection:
        admin = create_principal(connection, "admin-" + uuid4().hex, password, "admin")
    with TestClient(create_app(config), base_url="https://testserver") as client:
        yield client, engine, config, admin, password
    engine.dispose()


def headers(token):
    return {
        "Authorization": "Bearer " + token,
        "X-Request-ID": str(uuid4()),
        "Idempotency-Key": str(uuid4()),
    }


def login(context, subject=None, password=None):
    client, engine, _, admin, actual_password = context
    with engine.connect() as connection:
        username = connection.execute(
            select(principals.c.username).where(principals.c.id == (subject or admin))
        ).scalar_one()
    response = client.post(
        "/api/v1/auth/login", json={"username": username, "password": password or actual_password}
    )
    assert response.status_code == 200, response.text
    assert response.headers["Cache-Control"] == "no-store"
    return response.json()["access_token"]


def test_managed_login_ownership_membership_role_revocation_and_no_secret_response(
    identity_context,
):
    client, engine, config, admin, password = identity_context
    token = login(identity_context)
    assessment = client.post(
        "/api/v1/assessments", json={"name": "Identity test only"}, headers=headers(token)
    ).json()
    base = "/api/v1/assessments/" + assessment["id"]
    other_password = secrets.token_urlsafe(24)
    response = client.post(
        "/api/v1/auth/users",
        json={"username": "reviewer-" + uuid4().hex, "password": other_password, "role": "analyst"},
        headers=headers(token),
    )
    assert response.status_code == 201 and other_password not in response.text
    subject = response.json()["subject"]
    other = login(identity_context, subject, other_password)
    assert client.get(base, headers=headers(other)).status_code == 401
    response = client.post(
        base + "/members", json={"subject": subject, "role": "auditor"}, headers=headers(token)
    )
    assert response.status_code == 200
    assert client.get(base, headers=headers(other)).status_code == 200
    assert (
        client.post(
            base + "/scopes",
            json={"revision": 1, "targets": ["test.invalid"]},
            headers=headers(other),
        ).status_code
        == 403
    )
    client.post(
        base + "/members",
        json={"subject": subject, "role": "reviewer", "active": False},
        headers=headers(token),
    )
    assert client.get(base, headers=headers(other)).status_code == 401
    assert password not in str(assessment) and config.app_secret.get_secret_value() not in str(
        assessment
    )
    with engine.connect() as connection:
        hashed = connection.execute(
            select(principals.c.password_hash).where(principals.c.id == admin)
        ).scalar_one()
        assert hashed.startswith("$argon2") and password not in hashed
    assert client.get(base, headers={"X-User-ID": admin}).status_code == 401
    assert (
        client.get(base, headers=headers(issue_identity(config, admin, "admin"))).status_code == 401
    )


def test_rotation_logout_forged_claims_and_service_cannot_approve(identity_context):
    client, engine, config, admin, password = identity_context
    token = login(identity_context)
    assessment = client.post(
        "/api/v1/assessments", json={"name": "Session test only"}, headers=headers(token)
    ).json()
    base = "/api/v1/assessments/" + assessment["id"]
    with engine.begin() as connection:
        service = create_principal(connection, "planner-" + uuid4().hex, None, "planner", "service")
        set_membership(connection, UUID(assessment["id"]), service, "planner")
        service_token = issue_session(connection, config, service, UUID(assessment["id"]))[
            "access_token"
        ]
    assert (
        client.post(base + "/policies", json={}, headers=headers(service_token)).status_code == 403
    )
    assert (
        client.post(base + "/approvals", json={}, headers=headers(service_token)).status_code == 403
    )
    assert (
        client.get(
            base + "/evidence/" + str(uuid4()) + "/original", headers=headers(service_token)
        ).status_code
        == 403
    )
    # Even a re-signed role claim cannot override the stored live membership.
    claims = unseal(config.app_secret.get_secret_value(), "identity", service_token)
    claims["role"] = "reviewer"
    claims["principal_kind"] = "human"
    forged = seal(config.app_secret.get_secret_value(), "identity", claims)
    with engine.begin() as connection:
        connection.execute(
            sessions.update()
            .where(sessions.c.subject == service)
            .values(token_digest=hashlib.sha256(forged.encode()).hexdigest())
        )
    assert client.post(base + "/approvals", json={}, headers=headers(forged)).status_code == 403
    new_password = secrets.token_urlsafe(24)
    response = client.post(
        "/api/v1/auth/password",
        json={"old_password": password, "new_password": new_password},
        headers=headers(token),
    )
    assert response.status_code == 200 and new_password not in response.text
    assert client.get(base, headers=headers(token)).status_code == 401
    renewed = login(identity_context, password=new_password)
    assert client.post("/api/v1/auth/logout", headers=headers(renewed)).status_code == 200
    assert client.get(base, headers=headers(renewed)).status_code == 401


def test_invalid_login_rate_limit_and_expired_session(identity_context):
    client, engine, config, admin, password = identity_context
    for _ in range(10):
        response = client.post(
            "/api/v1/auth/login",
            json={"username": "unknown-user", "password": secrets.token_urlsafe(24)},
        )
        assert response.status_code == 401
    assert (
        client.post(
            "/api/v1/auth/login", json={"username": "unknown-user", "password": password}
        ).status_code
        == 429
    )
    with engine.begin() as connection:
        session = issue_session(connection, config, admin)
        connection.execute(sessions.update().where(sessions.c.subject == admin).values(expires=0))
    assert (
        client.get("/api/v1/assessments", headers=headers(session["access_token"])).status_code
        == 401
    )


def test_hosted_first_admin_bootstrap_is_secret_gated_and_single_use(tmp_path):
    token = secrets.token_urlsafe(32)
    password = secrets.token_urlsafe(24)
    config = Settings(
        _env_file=None,
        environment="production",
        app_secret=secrets.token_hex(32),
        bootstrap_token=token,
        database_url=f"sqlite:///{tmp_path / 'bootstrap.db'}",
    )
    engine = make_engine(config)
    metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(bootstrap_state.insert().values(id=1, consumed=False))

    with TestClient(create_app(config), base_url="https://testserver") as client:
        payload = {"username": "first-admin", "password": password}
        assert client.post("/api/v1/auth/bootstrap", json=payload).status_code == 404
        assert (
            client.post(
                "/api/v1/auth/bootstrap",
                json=payload,
                headers={"X-Bootstrap-Token": "incorrect-bootstrap-secret"},
            ).status_code
            == 404
        )
        response = client.post(
            "/api/v1/auth/bootstrap", json=payload, headers={"X-Bootstrap-Token": token}
        )
        assert response.status_code == 201, response.text
        assert response.headers["Cache-Control"] == "no-store"
        assert password not in response.text and token not in response.text
        session_token = response.json()["access_token"]
        assert client.get("/api/v1/assessments", headers=headers(session_token)).status_code == 200
        assert (
            client.post(
                "/api/v1/auth/bootstrap", json=payload, headers={"X-Bootstrap-Token": token}
            ).status_code
            == 404
        )

    with engine.connect() as connection:
        admin_rows = connection.execute(select(principals.c.id)).all()
        consumed = connection.execute(select(bootstrap_state.c.consumed)).scalar_one()
        assert len(admin_rows) == 1 and consumed is True
    engine.dispose()


def test_log_formatter_masks_credentials_and_exception_text():
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(SafeFormatter(logging.Formatter(), ("configured-private-canary",)))
    logger = logging.getLogger("m03-private-log-test")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        try:
            raise ValueError("password=fake-password-canary configured-private-canary")
        except ValueError:
            logger.exception("Authorization: Bearer fake-token-canary")
        assert "fake-password-canary" not in stream.getvalue()
        assert "configured-private-canary" not in stream.getvalue()
        assert "fake-token-canary" not in stream.getvalue()
    finally:
        logger.removeHandler(handler)


@pytest.mark.services
def test_postgresql_identity_session_and_membership(identity_context):
    if os.environ.get("RUN_SERVICE_TESTS") != "1":
        pytest.skip("requires PostgreSQL")
    test_managed_login_ownership_membership_role_revocation_and_no_secret_response(identity_context)

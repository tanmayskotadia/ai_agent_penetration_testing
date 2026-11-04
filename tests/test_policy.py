"""Synthetic authority/destination contracts; no target is contacted or scanned."""

import os
import secrets
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from aegistrace.api import create_app
from aegistrace.auth import issue_identity
from aegistrace.db import make_engine
from aegistrace.policy import (
    ExecutionPolicy,
    PolicyError,
    authorize,
    authorize_redirect,
    destination,
    release_policy,
    verify_peer,
)
from aegistrace.schema_v1 import metadata
from aegistrace.settings import Settings
from aegistrace_workers.policy import dispatch_preflight
from fastapi.testclient import TestClient
from pydantic import ValidationError


def policy_value():
    now = datetime.now(UTC)
    return ExecutionPolicy(
        assessment_id=uuid4(),
        scope_id=uuid4(),
        scope_revision=1,
        context="general",
        authorization_source="asset-owner",
        authorization_reference="TEST ONLY; not authority",
        authorization_document_sha256="a" * 64,
        reviewed_by="test-reviewer",
        valid_from=now - timedelta(minutes=1),
        valid_until=now + timedelta(hours=1),
        targets=(
            {
                "host": "lab.test",
                "protocol": "http",
                "port": 8080,
                "path_prefix": "/app",
                "pinned_addresses": ["192.0.2.10"],
            },
        ),
        allowed_networks=("192.0.2.0/24",),
        allowed_profiles=("discovery",),
        requests_per_second=4,
        concurrent_jobs=1,
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://lab.test@other.test:8080/app",
        "http://lab.test:8080/app/%2fadmin",
        "http://lab.test:8080/app/%252e%252e/admin",
        "http://lab.test:8080/app/../admin",
        "http://lab.test:8080/app\\admin",
        "http://lab.test:8080/app?next=outside",
        "http://lab.test:8080/app#outside",
        "http://*.test:8080/app",
        "http://0177.0.0.1:8080/app",
        "http://2130706433:8080/app",
        "http://lab.test:0/app",
    ],
)
def test_mixed_encodings_userinfo_wildcards_and_ambiguous_ports_denied(url):
    with pytest.raises(ValueError):
        authorize(policy_value(), url, "discovery", lambda *_: ("192.0.2.10",))


def test_dns_rebinding_redirects_protected_addresses_and_expiry():
    policy = policy_value()

    def good(*_):
        return ("192.0.2.10",)

    accepted = authorize(policy, "http://lab.test:8080/app/a", "discovery", good)
    verify_peer(accepted, "192.0.2.10", 8080)
    for resolver in [
        lambda *_: ("192.0.2.11",),
        lambda *_: ("169.254.169.254",),
        lambda *_: ("::ffff:192.0.2.10",),
    ]:
        with pytest.raises(ValueError):
            authorize(policy, "http://lab.test:8080/app/a", "discovery", resolver)
    with pytest.raises(PolicyError):
        authorize_redirect(
            policy, "http://lab.test:8080/app", "http://outside.test/", "discovery", good
        )
    with pytest.raises(PolicyError):
        verify_peer(accepted, "192.0.2.11", 8080)
    with pytest.raises(PolicyError):
        authorize(policy, "http://lab.test:8080/app", "active-web", good)
    with pytest.raises(PolicyError):
        authorize(policy, "http://lab.test:8080/app", "discovery", good, ("192.0.2.0/24",))
    with pytest.raises(PolicyError):
        authorize(
            policy,
            "http://lab.test:8080/app",
            "discovery",
            good,
            now=datetime.now(UTC) + timedelta(days=1),
        )
    with pytest.raises(PolicyError):
        authorize(
            policy.model_copy(update={"exclusions": ("192.0.2.10",)}),
            "http://lab.test:8080/app",
            "discovery",
            good,
        )
    ipv6 = policy.model_dump()
    ipv6["targets"] = [
        {
            "host": "2001:db8::10",
            "protocol": "https",
            "port": 443,
            "pinned_addresses": ["2001:db8::10"],
        }
    ]
    ipv6["allowed_networks"] = ("2001:db8::/64",)
    assert (
        authorize(ExecutionPolicy.model_validate(ipv6), "https://[2001:db8::10]/", "discovery").host
        == "2001:db8::10"
    )
    with pytest.raises(ValidationError):
        ExecutionPolicy.model_validate(policy.model_dump() | {"context": "hackathon"})
    assert destination("https://lab.test/").port == 443


@pytest.fixture
def policy_context(tmp_path, request):
    settings = Settings(
        _env_file=None,
        app_secret=secrets.token_hex(32),
        database_url=os.environ["DATABASE_URL"]
        if request.node.get_closest_marker("services")
        else f"sqlite:///{tmp_path / 'policy.db'}",
    )
    engine = make_engine(settings)
    metadata.create_all(engine)
    with TestClient(create_app(settings)) as client:
        yield client, engine, settings
    engine.dispose()


def seed_policy(context, scope_mode="live-request"):
    client, engine, settings = context

    def headers():
        return {
            "Authorization": "Bearer " + issue_identity(settings, "owner", "reviewer"),
            "X-Request-ID": str(uuid4()),
            "Idempotency-Key": str(uuid4()),
        }

    assessment = client.post(
        "/api/v1/assessments", json={"name": "Test only"}, headers=headers()
    ).json()
    base = "/api/v1/assessments/" + assessment["id"]
    scope = client.post(
        base + "/scopes",
        json={
            "revision": 1,
            "targets": ["192.0.2.10"],
            "mode": scope_mode,
            "authorization_reference": "TEST ONLY; not authority",
        },
        headers=headers(),
    ).json()
    body = policy_value().model_dump(mode="json", exclude={"id", "assessment_id", "reviewed_by"})
    body["scope_id"] = scope["id"]
    body["targets"] = [
        {"host": "192.0.2.10", "protocol": "http", "port": 8080, "pinned_addresses": ["192.0.2.10"]}
    ]
    response = client.post(base + "/policies", json=body, headers=headers())
    return base, headers, response


def test_runtime_api_worker_rate_race_and_stale_policy(policy_context):
    client, engine, _ = policy_context
    base, headers, response = seed_policy(policy_context)
    assert response.status_code == 201, response.text
    policy = response.json()
    assessment_id = UUID(policy["assessment_id"])
    policy_id = UUID(policy["id"])
    assert (
        client.post(
            base + "/policies/" + str(policy_id) + "/check",
            json={"url": "http://192.0.2.10:8080/", "profile": "discovery"},
            headers=headers(),
        ).json()["execution_enabled"]
        is False
    )

    def attempt(_):
        try:
            with engine.begin() as connection:
                dispatch_preflight(
                    connection, assessment_id, policy_id, "http://192.0.2.10:8080/", "discovery"
                )
            return True
        except PolicyError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sum(pool.map(attempt, range(2))) == 1
    with engine.begin() as connection:
        release_policy(connection, policy_id)
    assert (
        client.post(
            base + "/scopes",
            json={"revision": 2, "targets": ["192.0.2.10"], "mode": "live-request"},
            headers=headers(),
        ).status_code
        == 201
    )
    with engine.begin() as connection, pytest.raises(PolicyError, match="stale"):
        dispatch_preflight(
            connection, assessment_id, policy_id, "http://192.0.2.10:8080/", "discovery"
        )
    with engine.begin() as connection, pytest.raises(PolicyError, match="required"):
        dispatch_preflight(
            connection, assessment_id, uuid4(), "http://192.0.2.10:8080/", "discovery"
        )


def test_import_scope_cannot_be_promoted_by_prompt_fields(policy_context):
    _, _, response = seed_policy(policy_context, "recorded-import")
    assert response.status_code == 422


@pytest.mark.services
def test_actual_postgresql_policy_reservations(policy_context):
    if os.environ.get("RUN_SERVICE_TESTS") != "1":
        pytest.skip("requires PostgreSQL")
    test_runtime_api_worker_rate_race_and_stale_policy(policy_context)

"""Disposable application and adversarial policy tests, not genuine scan evidence."""

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from aegistrace.api_assessment import Credential, Operation, assess_operations, operation_digest
from aegistrace.openapi_parse import parse_openapi
from aegistrace.policy import ExecutionPolicy, PolicyError
from pydantic import SecretStr

ORIGIN = "https://api.example.invalid"
NOW = datetime.now(UTC)


def policy():
    return ExecutionPolicy(
        assessment_id=uuid4(),
        scope_id=uuid4(),
        scope_revision=1,
        context="general",
        authorization_source="asset-owner",
        authorization_reference="disposable test-only application",
        authorization_document_sha256="a" * 64,
        reviewed_by="test harness",
        valid_from=NOW - timedelta(minutes=1),
        valid_until=NOW + timedelta(minutes=10),
        targets=[
            {
                "host": "api.example.invalid",
                "protocol": "https",
                "port": 443,
                "pinned_addresses": ["192.0.2.10"],
            }
        ],
        allowed_networks=["192.0.2.0/24"],
        allowed_profiles=["active-web"],
        requests_per_second=2,
        concurrent_jobs=1,
    )


def credential(**updates):
    return Credential(
        kind="bearer",
        value=SecretStr("private-test-token"),
        origin=ORIGIN,
        expires_at=updates.pop("expires_at", NOW + timedelta(minutes=5)),
        **updates,
    )


def run(operations, credentials=None, transport=None, **kwargs):
    return assess_operations(
        operations,
        operation_digest(operations),
        kwargs.pop("load_policy", policy),
        lambda: credentials or {},
        explicitly_allowed_operations=kwargs.pop(
            "explicitly_allowed_operations", frozenset((op.method, op.url) for op in operations)
        ),
        transport=transport or (lambda *_: 200),
        resolver=lambda *_: ("192.0.2.10",),
        wait=lambda _: None,
        clock=lambda: NOW,
        **kwargs,
    )


def test_server_override_and_optional_security_are_not_lost():
    definition = {
        "openapi": "3.1.0",
        "servers": [{"url": ORIGIN}],
        "components": {"securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}}},
        "security": [{"bearer": []}],
        "paths": {
            "/item": {
                "servers": [{"url": "https://external.invalid"}],
                "get": {"security": [{}, {"bearer": []}]},
                "head": {"servers": [{"url": "https://override.invalid"}]},
            }
        },
    }
    result = parse_openapi(json.dumps(definition).encode(), "3.1.0")
    assert result["state"] == "normalized"
    assert ORIGIN in result["assets"]
    assert "https://external.invalid/item" in result["assets"]
    assert "https://override.invalid/item" in result["assets"]
    assert result["operations"][0]["authentication_required"] is False
    assert result["operations"][0]["security_alternatives"] == [{}, {"bearer": []}]
    definition["paths"]["/item"]["get"]["security"] = [{"bearer": "invalid"}]
    assert parse_openapi(json.dumps(definition).encode(), "3.1.0")["state"] == "quarantined"


def test_missing_expired_and_wrong_origin_credentials_never_dispatch():
    op = Operation(method="GET", url=ORIGIN + "/protected", security_alternatives=(("bearer",),))
    for credentials in (
        {},
        {"bearer": credential(expires_at=NOW)},
        {"bearer": credential().model_copy(update={"origin": "https://external.invalid"})},
    ):
        result = run((op,), credentials, lambda *_: pytest.fail("must not dispatch"))
        assert result["attempted_count"] == 0
        assert result["operations"][0]["authentication"] == "unavailable-or-expired"


def test_scope_exclusions_rebinding_and_changed_plan_block_dispatch():
    op = Operation(method="GET", url=ORIGIN + "/excluded")
    result = run(
        (op,),
        load_policy=lambda: policy().model_copy(update={"exclusions": (ORIGIN + "/excluded",)}),
    )
    assert result["attempted_count"] == 0
    with pytest.raises(PolicyError, match="unreviewed"):
        assess_operations((op,), "wrong", policy, lambda: {})
    denied = run((op,), explicitly_allowed_operations=frozenset())
    assert denied["operations"][0]["state"] == "excluded"
    external = Operation(method="GET", url="https://external.invalid/private")
    assert run((external,))["attempted_count"] == 0


def test_methods_redirects_provider_errors_and_cancellation_have_truthful_results():
    ops = (Operation(method="DELETE", url=ORIGIN + "/remove"),)
    result = run(ops, explicitly_allowed_operations=frozenset())
    assert result["operations"][0]["state"] == "excluded"
    redirected = run(ops, transport=lambda *_: 302)
    assert redirected["operations"][0]["reason"] == "redirect-not-followed"
    assert redirected["succeeded_count"] == 0
    assert run(ops, cancelled=lambda: True)["attempted_count"] == 0

    def error(*_):
        raise RuntimeError("private-test-token")

    result = run(ops, transport=error)
    assert "private-test-token" not in json.dumps(result)
    assert result["operations"][0]["state"] == "failed"


def test_policy_is_reloaded_after_wait_and_dns_rebinding_never_dispatches():
    op = Operation(method="GET", url=ORIGIN + "/public")
    original = policy()
    calls = []

    def revoked_policy():
        calls.append(True)
        if len(calls) > 1:
            raise PolicyError("revoked")
        return original

    assert run((op,), load_policy=revoked_policy)["attempted_count"] == 0
    assert len(calls) == 2
    result = assess_operations(
        (op,),
        operation_digest((op,)),
        lambda: original,
        lambda: {},
        explicitly_allowed_operations=frozenset({(op.method, op.url)}),
        resolver=lambda *_: ("192.0.2.11",),
        transport=lambda *_: pytest.fail("changed DNS must not dispatch"),
        wait=lambda _: None,
        clock=lambda: NOW,
    )
    assert result["attempted_count"] == 0


def test_queries_header_injection_and_plaintext_are_refused():
    op = Operation(method="GET", url=ORIGIN + "/private?token=do-not-copy")
    with pytest.raises(PolicyError, match="credential-bearing"):
        run((op,))
    with pytest.raises(PolicyError, match="invalid-credential-value"):
        credential().model_copy(
            update={"value": SecretStr("secret\r\nInjected: value")}
        ).request_header(NOW, ORIGIN)
    assert "private-test-token" not in repr(credential())
    op = Operation(method="GET", url="http://api.example.invalid/private")
    assert run((op,))["attempted_count"] == 0


def test_disposable_api_authentication_and_forbidden_operation_end_to_end():
    from fastapi import FastAPI, Header
    from fastapi.responses import JSONResponse
    from fastapi.testclient import TestClient

    app = FastAPI()

    @app.get("/public")
    def public():
        return {"ok": True}

    @app.get("/protected")
    def protected(authorization: str | None = Header(default=None)):
        return JSONResponse(
            {}, status_code=200 if authorization == "Bearer private-test-token" else 401
        )

    @app.get("/forbidden")
    def forbidden():
        return JSONResponse({}, status_code=403)

    with TestClient(app) as client:

        def transport(target, method, headers):
            return client.request(
                method, target.path, headers=dict(headers), follow_redirects=False
            ).status_code

        ops = tuple(
            Operation(
                method="GET",
                url=ORIGIN + path,
                security_alternatives=(("bearer",),) if path != "/public" else (),
            )
            for path in ("/public", "/protected", "/forbidden")
        )
        result = run(ops, {"bearer": credential()}, transport)
        assert result["attempted_count"] == 3
        assert result["succeeded_count"] == 2
        assert result["operations"][2]["authentication"] == "rejected"
        assert result["operations"][1]["authentication"] == "credentials-sent-unverified"
        rejected = run(
            (ops[1],),
            {"bearer": credential().model_copy(update={"value": SecretStr("wrong")})},
            transport,
        )
        assert rejected["operations"][0]["status_code"] == 401
        assert "private-test-token" not in json.dumps(result)

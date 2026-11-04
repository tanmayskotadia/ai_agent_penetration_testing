"""Synthetic human-review/claim contracts; no scanner or offensive action runs."""

import os
from concurrent.futures import ThreadPoolExecutor
from uuid import UUID

import pytest
from aegistrace.approval_schema import grants
from aegistrace.approvals import consume
from aegistrace.policy import PolicyError
from test_identity import headers as managed_headers
from test_identity import identity_context as identity_context
from test_identity import login
from test_policy import policy_context as policy_context
from test_policy import seed_policy


def prepared(context):
    client, _, _ = context
    base, headers, response = seed_policy(context)
    assert response.status_code == 201, response.text
    policy = response.json()
    plan = client.post(
        base + "/plans",
        json={
            "scope_id": policy["scope_id"],
            "scope_revision": 1,
            "revision": 1,
            "steps": ["TEST ONLY; no scan"],
        },
        headers=headers(),
    ).json()
    body = {
        "policy_id": policy["id"],
        "plan_id": plan["id"],
        "plan_revision": 1,
        "tool": "Nmap",
        "template": "nmap.connect.v1",
        "profile": "discovery",
        "destination_url": "http://192.0.2.10:8080/",
        "parameters": {"timeout_seconds": 5},
        "expected_impact": "TEST ONLY review; no execution",
        "rollback_instructions": "TEST ONLY; no changed target state",
        "max_runtime_seconds": 20,
    }
    response = client.post(base + "/action-approvals", json=body, headers=headers())
    assert response.status_code == 201, response.text
    return base, headers, response.json(), body


def review(context, base, headers, value, decision="approve"):
    response = context[0].post(
        base + "/action-approvals/" + value["id"] + "/decision",
        json={"decision": decision, "action_digest": value["action_digest"]},
        headers=headers(),
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_human_review_restart_single_use_race_and_audit(policy_context):
    client, engine, config = policy_context
    base, headers, value, _ = prepared(policy_context)
    assert value["allowed_decisions"] == ["approve", "deny"]
    reviewed = review(policy_context, base, headers, value)
    assert reviewed["state"] == "approved" and reviewed["reviewer"] == "owner"

    def attempt(_):
        try:
            with engine.begin() as connection:
                claim = consume(
                    connection,
                    config,
                    UUID(value["assessment_id"]),
                    UUID(value["id"]),
                    value["action_digest"],
                )
                assert claim["state"] == "claimed-not-executed" and claim["reviewer"] == "owner"
            return True
        except PolicyError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sum(pool.map(attempt, range(2))) == 1
    assert (
        client.get(base + "/action-approvals/" + value["id"], headers=headers()).json()["state"]
        == "consumed"
    )
    assert "approval.consumed" in client.get(base + "/events", headers=headers()).text


@pytest.mark.parametrize("case", ["denied", "revoked", "stale", "wrong-digest", "tampered"])
def test_denied_revoked_stale_changed_actions_never_claim(policy_context, case):
    client, engine, config = policy_context
    base, headers, value, _ = prepared(policy_context)
    review(policy_context, base, headers, value, "deny" if case == "denied" else "approve")
    if case == "revoked":
        review(policy_context, base, headers, value, "revoke")
    elif case == "stale":
        client.post(
            base + "/scopes",
            json={"revision": 2, "targets": ["192.0.2.10"], "mode": "live-request"},
            headers=headers(),
        )
    elif case == "tampered":
        with engine.begin() as connection:
            payload = {
                k: v
                for k, v in value.items()
                if k
                not in {
                    "state",
                    "action_digest",
                    "reviewer",
                    "allowed_decisions",
                    "execution_enabled",
                }
            }
            payload["action"]["parameters"]["timeout_seconds"] = 9
            connection.execute(
                grants.update().where(grants.c.id == value["id"]).values(payload=payload)
            )
    with engine.begin() as connection, pytest.raises(PolicyError):
        consume(
            connection,
            config,
            UUID(value["assessment_id"]),
            UUID(value["id"]),
            "f" * 64 if case == "wrong-digest" else value["action_digest"],
        )


def test_digest_review_and_duplicate_click_are_bound(policy_context):
    client, _, _ = policy_context
    base, headers, value, body = prepared(policy_context)
    assert (
        client.post(
            base + "/action-approvals", json=body | {"approved": True}, headers=headers()
        ).status_code
        == 422
    )

    route = base + "/action-approvals/" + value["id"] + "/decision"
    assert (
        client.post(
            route, json={"decision": "approve", "action_digest": "f" * 64}, headers=headers()
        ).status_code
        == 422
    )
    fixed = headers()
    first = client.post(
        route, json={"decision": "approve", "action_digest": value["action_digest"]}, headers=fixed
    )
    second = client.post(
        route, json={"decision": "approve", "action_digest": value["action_digest"]}, headers=fixed
    )
    assert first.status_code == second.status_code == 200 and first.json() == second.json()
    assert (
        client.post(
            base + "/action-approvals", json=body | {"parameters": {"shell": 1}}, headers=headers()
        ).status_code
        == 422
    )


def test_revoked_managed_reviewer_cannot_be_consumed(identity_context):
    from aegistrace.identity_schema import members
    from test_policy import policy_value

    client, engine, config, admin, _ = identity_context
    token = login(identity_context)

    def post(path, body):
        response = client.post(path, json=body, headers=managed_headers(token))
        assert response.status_code in {200, 201, 202}, response.text
        return response.json()

    assessment = post("/api/v1/assessments", {"name": "Managed reviewer test only"})
    base = "/api/v1/assessments/" + assessment["id"]
    scope = post(
        base + "/scopes",
        {
            "revision": 1,
            "targets": ["192.0.2.10"],
            "mode": "live-request",
            "authorization_reference": "TEST ONLY; not authority",
        },
    )
    body = policy_value().model_dump(mode="json", exclude={"id", "assessment_id", "reviewed_by"})
    body["scope_id"] = scope["id"]
    body["targets"] = [
        {"host": "192.0.2.10", "protocol": "http", "port": 8080, "pinned_addresses": ["192.0.2.10"]}
    ]
    policy = post(base + "/policies", body)
    plan = post(
        base + "/plans",
        {"scope_id": scope["id"], "scope_revision": 1, "revision": 1, "steps": ["TEST ONLY"]},
    )
    value = post(
        base + "/action-approvals",
        {
            "policy_id": policy["id"],
            "plan_id": plan["id"],
            "plan_revision": 1,
            "tool": "Nmap",
            "template": "nmap.connect.v1",
            "profile": "discovery",
            "destination_url": "http://192.0.2.10:8080/",
            "expected_impact": "TEST ONLY",
            "rollback_instructions": "TEST ONLY",
            "max_runtime_seconds": 10,
        },
    )
    post(
        base + "/action-approvals/" + value["id"] + "/decision",
        {"decision": "approve", "action_digest": value["action_digest"]},
    )
    with engine.begin() as connection:
        connection.execute(
            members.update()
            .where(members.c.assessment_id == assessment["id"], members.c.subject == admin)
            .values(role="auditor")
        )
    with engine.begin() as connection, pytest.raises(PolicyError):
        consume(
            connection, config, UUID(assessment["id"]), UUID(value["id"]), value["action_digest"]
        )


@pytest.mark.services
def test_postgresql_two_workers_consume_one_approval(policy_context):
    if os.environ.get("RUN_SERVICE_TESTS") != "1":
        pytest.skip("requires PostgreSQL")
    test_human_review_restart_single_use_race_and_audit(policy_context)

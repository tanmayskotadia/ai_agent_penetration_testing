"""Profile escalation/drift tests; no external scanner targets are used."""

from uuid import UUID

import pytest
from aegistrace import scan_profiles
from aegistrace.api_check_worker import execute_check
from aegistrace.approvals import ActionRequest, consume
from aegistrace.policy import PolicyError, TargetRule
from aegistrace.scan_profiles import profile_rule, validate_profile_action
from pydantic import ValidationError
from test_api_check_workflow import prepare
from test_approvals import prepared, review

pytest_plugins = ("test_policy", "test_identity", "test_ingestion")


@pytest.mark.parametrize(
    "template,tool,profile,parameters",
    [
        ("unknown", "Nmap", "discovery", {}),
        ("zap.active.v1", "OWASP ZAP", "passive-web", {}),
        ("zap.passive.v1", "OWASP ZAP", "passive-web", {"crawl": 1}),
        ("zap.passive.v1", "OWASP ZAP", "passive-web", {"max_redirects": 1}),
        ("nmap.connect.v1", "Nmap", "discovery", {"timeout_seconds": 0}),
        ("nmap.connect.v1", "Nmap", "discovery", {"timeout_seconds": 21}),
        ("zap.active.v1", "OWASP ZAP", "active-web", {"max_redirects": 4}),
        ("nikto.active.v1", "Nikto", "active-web", {"max_redirects": 1}),
    ],
)
def test_prohibited_settings_fail_closed(template, tool, profile, parameters):
    with pytest.raises(PolicyError):
        validate_profile_action(template, tool, profile, parameters, 20)


def test_unknown_profiles_wildcards_and_false_passive_claims_are_denied():
    with pytest.raises(PolicyError):
        profile_rule("crawl-as-passive")
    with pytest.raises(ValidationError):
        TargetRule(
            host="*.example.invalid", protocol="https", port=443, pinned_addresses=("192.0.2.10",)
        )
    passive = profile_rule("passive-web")
    assert passive.requests_generated is False
    assert {"crawl", "spider", "fetch", "active-scan"}.issubset(passive.prohibited_behaviors)
    assert profile_rule("active-web").requests_generated is True
    assert profile_rule("controlled-validation").impact == "disabled"


def test_nikto_active_template_is_explicitly_reviewable_but_redirects_are_off():
    rule = validate_profile_action("nikto.active.v1", "Nikto", "active-web", {}, 30)
    assert rule.explicit_human_approval_required is True
    assert rule.requests_generated is True
    action = ActionRequest.model_validate(
        {
            "policy_id": "3f7a1bf2-1273-4f8f-ad04-bb8439ab9827",
            "plan_id": "c2d33365-3ad6-4afc-a9ea-b71d12b5d802",
            "plan_revision": 1,
            "tool": "Nikto",
            "template": "nikto.active.v1",
            "profile": "active-web",
            "destination_url": "https://owned.example.test/",
            "expected_impact": "Bounded, approved web server checks",
            "rollback_instructions": "Reset the disposable test application",
            "max_runtime_seconds": 30,
        }
    )
    assert action.template == "nikto.active.v1"


def change_rules(monkeypatch, profile):
    monkeypatch.setattr(
        scan_profiles,
        "CATALOG",
        tuple(
            rule.model_copy(update={"description": rule.description + " Updated safety rule."})
            if rule.profile == profile
            else rule
            for rule in scan_profiles.CATALOG
        ),
    )


def test_generic_review_cannot_survive_profile_drift(policy_context, monkeypatch):
    _, engine, config = policy_context
    base, headers, approval, _ = prepared(policy_context)
    review(policy_context, base, headers, approval)
    change_rules(monkeypatch, "discovery")
    with engine.begin() as connection, pytest.raises(PolicyError, match="impact profile changed"):
        consume(
            connection,
            config,
            UUID(approval["assessment_id"]),
            UUID(approval["id"]),
            approval["action_digest"],
        )
    response = policy_context[0].post(
        base + "/action-approvals/" + approval["id"] + "/decision",
        json={"decision": "revoke", "action_digest": approval["action_digest"]},
        headers=headers(),
    )
    assert response.status_code == 200


def test_api_review_binds_rules_impact_reset_and_policy_limits(import_context, monkeypatch):
    client, config = import_context
    base, headers, post, _, check = prepare(import_context)
    plan = check["plan"]
    assert plan["profile"] == "active-web" and plan["impact_rules"]["requests_generated"]
    assert plan["expected_impact"] and plan["reset_instructions"]
    assert plan["execution_limits"] == {
        "requests_per_second": 10,
        "concurrent_jobs": 1,
        "max_runtime_seconds": 30,
        "max_redirects": 0,
    }
    post(
        base + "/api-checks/" + check["id"] + "/decision",
        {"decision": "approve", "digest": plan["digest"]},
    )
    change_rules(monkeypatch, "active-web")
    with pytest.raises(PolicyError, match="impact profile changed"):
        execute_check(
            client.app.state.engine,
            config,
            UUID(check["assessment_id"]),
            UUID(check["id"]),
            transport=lambda *_: pytest.fail("profile drift must prevent requests"),
        )
    post(
        base + "/api-checks/" + check["id"] + "/decision",
        {"decision": "cancel", "digest": plan["digest"]},
    )
    original = {
        "normalization_id": plan["source_normalization_id"],
        "policy_id": plan["policy_id"],
        "selected_indices": [0],
        "expected_impact": "test",
        "reset_instructions": "discard test",
    }
    for extra in ({"profile": "passive-web"}, {"crawl": True}, {"unknown_option": 1}):
        response = client.post(base + "/api-checks", json=original | extra, headers=headers())
        assert response.status_code == 422

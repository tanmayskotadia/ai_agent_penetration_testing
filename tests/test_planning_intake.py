from uuid import uuid4

from aegistrace.planning_intake import build_intake_plan


def test_missing_scope_returns_clarification_without_actions():
    result = build_intake_plan("Review https://example.test/api")

    assert result["blockers"] == ["scope-required"]
    assert result["steps"] == []
    assert result["execution"] == "never-executes; recorded-input-only"
    assert result["mentioned_targets"] == ["example.test"]


def test_scoped_network_web_intent_is_explainable_and_import_only():
    scope = {
        "id": str(uuid4()),
        "revision": 3,
        "targets": ["https://app.example.test"],
        "exclusions": ["admin.example.test"],
        "authorization_reference": "participant-supplied",
    }

    result = build_intake_plan("Review the web API and network evidence", scope=scope)

    assert result["blockers"] == []
    assert result["scope_revision"] == 3
    assert {step["tool"] for step in result["steps"] if "tool" in step} == {
        "Nmap",
        "OWASP ZAP",
        "OpenAPI",
    }
    assert all(step["mode"] == "recorded-import" for step in result["steps"])


def test_out_of_scope_mention_blocks_plan_and_active_request_never_schedules_action():
    scope = {
        "id": str(uuid4()),
        "revision": 1,
        "targets": ["example.test"],
        "exclusions": ["admin.example.test"],
        "authorization_reference": None,
    }

    result = build_intake_plan(
        "Run an active scan and exploit https://admin.example.test", scope=scope
    )

    assert "target-outside-scope" in result["blockers"]
    assert "active-validation-not-enabled" in result["blockers"]
    assert all(step["mode"] == "recorded-import" for step in result["steps"])
    assert any("action-bound human approval" in prompt for prompt in result["clarifications"])


def test_request_target_matching_is_exact_and_missing_authorization_is_disclosed():
    scope = {
        "id": str(uuid4()),
        "revision": 1,
        "targets": ["example.test"],
        "exclusions": [],
        "authorization_reference": None,
    }

    exact = build_intake_plan("Review web evidence for example.test", scope=scope)
    sibling = build_intake_plan("Review sub.example.test", scope=scope)

    assert exact["blockers"] == []
    assert "target-outside-scope" in sibling["blockers"]
    assert any("not independent proof" in prompt for prompt in exact["clarifications"])


def test_planner_skips_normalized_same_scope_imports_and_discloses_stale_results():
    scope = {
        "id": str(uuid4()),
        "revision": 2,
        "targets": ["app.example.test"],
        "exclusions": [],
        "authorization_reference": "test-only",
    }
    prior = [
        {"id": "revision-nmap", "tool": "Nmap", "state": "normalized", "same_scope": True},
        {"id": "revision-zap", "tool": "OWASP ZAP", "state": "normalized", "same_scope": False},
    ]

    result = build_intake_plan("Review network and web evidence", scope=scope, prior_results=prior)

    tools = {step.get("tool") for step in result["steps"]}
    assert "Nmap" not in tools
    assert "OWASP ZAP" in tools
    assert any("will not repeat" in item for item in result["clarifications"])
    assert any("different scope revision" in item for item in result["clarifications"])
    assert all("capability_status" in step for step in result["steps"] if "tool" in step)


def test_revoked_or_absent_capability_cannot_be_proposed_as_working():
    scope = {"id": str(uuid4()), "revision": 1, "targets": ["example.test"]}
    for registry in (
        [],
        [{"name": "Nmap", "mode": "unsupported", "guarded_containers": ["nmap-xml"]}],
    ):
        plan = build_intake_plan("Review Nmap evidence", scope=scope, capabilities=registry)
        assert "requested-tool-unavailable" in plan["blockers"]
        assert not any(step.get("tool") == "Nmap" for step in plan["steps"])


def test_intake_discloses_scope_limits_and_unavailable_explicit_tool():
    scope = {"id": str(uuid4()), "revision": 2, "targets": ["example.test"]}
    plan = build_intake_plan(
        "Review Nmap and Nessus evidence", scope=scope, constraints=["Offline only"]
    )
    assert "requested-tool-unavailable" in plan["blockers"]
    step = next(item for item in plan["steps"] if item.get("tool") == "Nmap")
    assert step["scope_id"] == scope["id"] and step["scope_revision"] == 2
    assert step["targets"] == scope["targets"] and "Offline only" in step["limits"]
    assert step["alternatives"] and step["registry_mode"] == "planned"
    assert "not observed evidence" in plan["information_kind"]

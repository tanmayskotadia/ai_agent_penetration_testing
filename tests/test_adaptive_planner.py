"""Synthetic scenarios; recorded-provider responses never count as real model acceptance."""

import json
from uuid import UUID, uuid4

import pytest
from aegistrace import adaptive_planner
from aegistrace.adaptive_planner import (
    ModelDecision,
    RejectedAlternative,
    candidate_steps,
    validate_decision,
)
from aegistrace.api_schema import resources
from aegistrace.auth import issue_identity
from aegistrace.capabilities import capability_snapshot
from aegistrace.evidence import EvidenceStore
from aegistrace.evidence_schema import objects
from aegistrace.model_provider import ModelReply, ProviderFailure
from pydantic import SecretStr
from sqlalchemy import select
from test_nmap import XML, source

pytest_plugins = ("test_ingestion",)


class RecordedProvider:
    def __init__(self, fail=False, invalid=False):
        self.contexts = []
        self.fail = fail
        self.invalid = invalid

    def generate(self, context, schema):
        self.contexts.append(context)
        if self.fail:
            raise ProviderFailure("provider-rate-limited")
        candidates = context["candidates"]
        chosen = next((v for v in candidates if v["action"] == "request-import"), candidates[0])
        value = {
            "decision": "select" if chosen["action"] == "request-import" else "request-review",
            "selected_candidate_id": chosen["id"],
            "rationale": "TEST ONLY: cited observations support reviewing the selected evidence gap.",
            "observation_ids": chosen["observation_ids"],
            "expected_information_gain": "TEST ONLY: compare independent web evidence with observed services.",
            "assumptions": ["TEST ONLY synthetic data; source service names are unverified"],
            "stop_conditions": ["Stop if approval or evidence is unavailable"],
            "rejected_alternatives": [
                {
                    "candidate_id": row["id"],
                    "reason": "TEST ONLY: defer to the selected narrower step.",
                    "observation_ids": row["observation_ids"],
                }
                for row in candidates
                if row["id"] != chosen["id"]
            ],
        }
        if self.invalid:
            value["observation_ids"] = [str(uuid4())]
        return ModelReply(
            json.dumps(value), "test-only-recorded", "test-only-response", {}, source="test-only"
        )


def prepare_case(context, raw=XML, reviewed=True):
    client, config = context
    base, headers, imported, request, _, evidence = source(context, raw=raw)
    result = client.post(
        base + "/imports/" + imported["id"] + "/normalize-nmap", json={}, headers=headers()
    )
    assert result.status_code == 201, result.text
    assessment_id = UUID(base.rsplit("/", 1)[-1])
    if reviewed:
        with client.app.state.engine.begin() as connection:
            EvidenceStore(config).redact(connection, assessment_id, UUID(evidence["id"]), "owner")
            connection.execute(
                objects.update()
                .where(objects.c.id == evidence["id"])
                .values(redaction_reviewed=True)
            )
    config.model_data_policy_reference = "TEST-ONLY-policy"
    body = {
        "scope_id": request["scope_id"],
        "scope_revision": 1,
        "conversation_id": str(uuid4()),
        "request_text": "Review current recorded evidence gaps",
        "result_revision_ids": [result.json()["result_revision_id"]],
        "allow_external_processing": True,
        "data_policy_reference": "TEST-ONLY-policy",
    }
    return client, config, base, headers, body


def test_http_and_ssh_produce_different_bounded_proposals_and_persist_reviewable_plans(
    import_context, monkeypatch
):
    provider = RecordedProvider()
    monkeypatch.setattr(adaptive_planner, "build_provider", lambda config: provider)
    for raw, expected in [
        (XML, "select"),
        (XML.replace(b'name="http"', b'name="ssh"'), "request-review"),
    ]:
        client, config, base, headers, body = prepare_case(import_context, raw=raw)
        response = client.post(base + "/reasoning/replan", json=body, headers=headers())
        assert response.status_code == 201, response.text
        value = response.json()
        assert value["request"]["proposal"]["decision"]["decision"] == expected
        assert value["request"]["proposal"]["provider"]["model_called"] is False
        assert value["request"]["proposal"]["provider"]["provider_source"] == "test-only"
        assert value["request"]["proposal"]["execution_enabled"] is False
        assert value["state"] == ("draft" if expected == "select" else "blocked")
        assert value["request"]["review_digest"]
        assert client.get(base + "/plans", headers=headers()).json()[-1] == value
        # A second request with identical evidence reuses the prior reasoning, even with a new conversation.
        before = len(provider.contexts)
        repeated = client.post(
            base + "/reasoning/replan",
            json=body | {"conversation_id": str(uuid4())},
            headers=headers(),
        )
        assert repeated.status_code == 201
        assert "unchanged-evidence" in repeated.json()["reason"]
        assert len(provider.contexts) == before
        assert all(
            "targets" not in context and "raw" not in context for context in provider.contexts
        )


@pytest.mark.parametrize(
    "mode", ["absent", "no-consent", "unreviewed", "unavailable", "invalid", "rate-limit"]
)
def test_abstention_failure_and_policy_paths(import_context, monkeypatch, mode):
    client, _, base, headers, body = prepare_case(import_context, reviewed=mode != "unreviewed")
    provider = RecordedProvider(fail=mode == "rate-limit", invalid=mode == "invalid")
    monkeypatch.setattr(adaptive_planner, "build_provider", lambda config: provider)
    if mode == "absent":
        body["result_revision_ids"] = []
    elif mode == "no-consent":
        body["allow_external_processing"] = False
    elif mode == "unavailable":
        registry = capability_snapshot()
        for row in registry:
            if row["name"] in {"OWASP ZAP", "Nikto"}:
                row["mode"] = "unsupported"
        monkeypatch.setattr(adaptive_planner, "capability_snapshot", lambda: registry)
    response = client.post(base + "/reasoning/replan", json=body, headers=headers())
    assert response.status_code == 201, response.text
    assert response.json()["state"] == "blocked"
    assert response.json()["request"]["proposal"]["steps"] == []
    if mode in {"absent", "no-consent", "unreviewed"}:
        assert not provider.contexts


def test_idempotency_step_budget_and_stale_scope_prevent_repeat_calls(import_context, monkeypatch):
    client, _, base, headers, body = prepare_case(import_context)
    provider = RecordedProvider()
    monkeypatch.setattr(adaptive_planner, "build_provider", lambda config: provider)
    key = headers()
    first = client.post(base + "/reasoning/replan", json=body, headers=key)
    replay = client.post(base + "/reasoning/replan", json=body, headers=key)
    assert first.json()["id"] == replay.json()["id"] and len(provider.contexts) == 1
    for index in range(2):
        assert (
            client.post(
                base + "/reasoning/replan",
                json=body | {"request_text": f"Review change {index}"},
                headers=headers(),
            ).status_code
            == 201
        )
    assert (
        client.post(
            base + "/reasoning/replan", json=body | {"request_text": "extra"}, headers=headers()
        ).status_code
        == 409
    )
    client.post(
        base + "/scopes", json={"revision": 2, "targets": ["192.0.2.11"]}, headers=headers()
    )
    assert (
        client.post(
            base + "/reasoning/replan",
            json=body | {"conversation_id": str(uuid4())},
            headers=headers(),
        ).status_code
        == 409
    )
    with client.app.state.engine.connect() as connection:
        plans = list(
            connection.execute(
                select(resources.c.payload).where(
                    resources.c.assessment_id == base.rsplit("/", 1)[-1],
                    resources.c.kind == "plans",
                )
            ).scalars()
        )
        assert len(plans) == 3


def test_existing_results_and_failed_evidence_only_offer_review():
    obs = str(uuid4())
    facts = [{"id": obs, "asset_id": "asset-test", "service": {"observed_name": "http"}}]
    assert (
        len(
            candidate_steps(
                facts, {"asset-test": {"OWASP ZAP", "Nikto"}}, [], capability_snapshot()
            )
        )
        == 1
    )
    candidates = candidate_steps(facts, {}, ["Nmap"], capability_snapshot())
    assert len(candidates) == 1 and candidates[0]["action"] == "request-review"
    decision = ModelDecision(
        decision="stop",
        selected_candidate_id=None,
        rationale="No further justified import",
        observation_ids=[UUID(obs)],
        expected_information_gain="No additional evidence available",
        assumptions=[],
        stop_conditions=["Await review"],
        rejected_alternatives=[
            RejectedAlternative(
                candidate_id="review-sources",
                reason="No further source investigation is justified",
                observation_ids=[UUID(obs)],
            )
        ],
    )
    validate_decision(decision, candidates, facts)
    with pytest.raises(ProviderFailure):
        validate_decision(
            decision.model_copy(update={"selected_candidate_id": "shell"}), candidates, facts
        )


def test_conflicting_port_states_require_review_and_cannot_propose_import(
    import_context, monkeypatch
):
    client, _, base, headers, body = prepare_case(
        import_context, raw=XML.replace(b'portid="81"', b'portid="80"')
    )
    provider = RecordedProvider()
    monkeypatch.setattr(adaptive_planner, "build_provider", lambda config: provider)
    response = client.post(base + "/reasoning/replan", json=body, headers=headers())
    assert response.status_code == 201, response.text
    proposal = response.json()["request"]["proposal"]
    assert response.json()["request"]["context"]["conflicts"]
    assert proposal["decision"]["decision"] == "request-review"
    assert all(row["action"] == "request-review" for row in proposal["candidates"])


def test_unconfigured_provider_never_makes_a_network_request(import_context):
    client, _, base, headers, body = prepare_case(import_context)
    response = client.post(base + "/reasoning/replan", json=body, headers=headers())
    assert response.status_code == 201
    assert response.json()["reason"] == "provider-not-configured"
    assert response.json()["request"]["proposal"]["provider"]["provider_invoked"] is False


def test_reviewer_authorization_and_assessment_budget_cannot_be_bypassed(
    import_context, monkeypatch
):
    client, config, base, headers, body = prepare_case(import_context)
    provider = RecordedProvider()
    monkeypatch.setattr(adaptive_planner, "build_provider", lambda config: provider)
    analyst = headers() | {"Authorization": "Bearer " + issue_identity(config, "owner", "analyst")}
    assert client.post(base + "/reasoning/replan", json=body, headers=analyst).status_code == 403
    other = headers() | {"Authorization": "Bearer " + issue_identity(config, "other", "reviewer")}
    assert client.post(base + "/reasoning/replan", json=body, headers=other).status_code == 404
    assert not provider.contexts
    config.model_max_assessment_calls = 1
    assert client.post(base + "/reasoning/replan", json=body, headers=headers()).status_code == 201
    assert (
        client.post(
            base + "/reasoning/replan",
            json=body | {"conversation_id": str(uuid4()), "request_text": "different intent"},
            headers=headers(),
        ).status_code
        == 409
    )
    assert len(provider.contexts) == 1


def test_known_secrets_are_removed_before_context_transmission_and_persistence(
    import_context, monkeypatch
):
    client, config, base, headers, body = prepare_case(import_context)
    config.groq_api_key = SecretStr("TEST_ONLY_PRIVATE_GROQ_CANARY")
    provider = RecordedProvider()
    monkeypatch.setattr(adaptive_planner, "build_provider", lambda config: provider)
    secret_values = [
        config.app_secret.get_secret_value(),
        config.evidence_key.get_secret_value(),
        config.groq_api_key.get_secret_value(),
    ]
    response = client.post(
        base + "/reasoning/replan",
        json=body | {"request_text": "Review evidence " + " ".join(secret_values)},
        headers=headers(),
    )
    assert response.status_code == 201, response.text
    for value in secret_values:
        assert value not in str(provider.contexts) and value not in response.text


@pytest.mark.services
def test_postgresql_bounded_adaptive_plan(import_context, monkeypatch):
    test_http_and_ssh_produce_different_bounded_proposals_and_persist_reviewable_plans(
        import_context, monkeypatch
    )

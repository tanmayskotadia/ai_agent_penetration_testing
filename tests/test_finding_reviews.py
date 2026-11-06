from datetime import UTC, datetime
from hashlib import sha256
from uuid import UUID, uuid4

import pytest
from aegistrace.auth import issue_identity
from aegistrace.domain import EvidenceReference, Observation, ToolRun
from aegistrace.finding_reviews import latest_by_observation, validate_review
from aegistrace.repository import get_record, insert_record

pytest_plugins = ("test_ingestion",)


def test_review_states_preserve_unknown_confidence_and_source_provenance():
    decision = validate_review(
        {
            "observation_id": "observation-a",
            "validation_state": "false-positive",
            "rationale": "The cited evidence shows a documented false alarm; test only.",
            "contradictory_observation_ids": [],
        },
        {"observation-a", "observation-b"},
    )
    assert decision["validation_state"] == "false-positive"
    assert decision["confidence"] is None
    assert decision["confidence_state"] == "unknown"
    assert decision["calibration_status"] == "not-calibrated"


def test_contradiction_requires_distinct_in_assessment_source_ids():
    base = {
        "observation_id": "observation-a",
        "validation_state": "contradictory",
        "rationale": "The two source observations disagree; test only.",
        "contradictory_observation_ids": ["observation-b"],
    }
    assert validate_review(base, {"observation-a", "observation-b"})[
        "contradictory_observation_ids"
    ] == ["observation-b"]
    with pytest.raises(ValueError, match="requires cited observations"):
        validate_review({**base, "contradictory_observation_ids": []}, {"observation-a"})
    with pytest.raises(ValueError, match="in this assessment"):
        validate_review(base, {"observation-a"})
    with pytest.raises(ValueError, match="self"):
        validate_review(
            {**base, "contradictory_observation_ids": ["observation-a"]}, {"observation-a"}
        )


def test_latest_reviewer_state_is_a_projection_over_append_only_history():
    values = [
        {"revision": 1, "request": {"observation_id": "a", "validation_state": "suspected"}},
        {"revision": 2, "request": {"observation_id": "a", "validation_state": "confirmed"}},
        {"revision": 3, "request": {"observation_id": "b", "validation_state": "unknown"}},
    ]
    result = latest_by_observation(values)
    assert result["a"]["validation_state"] == "confirmed"
    assert result["b"]["validation_state"] == "unknown"


def test_api_records_audited_reversible_triage_without_mutating_source_observation(import_context):
    client, settings = import_context
    token = issue_identity(settings, "triage-reviewer", "reviewer")

    def headers(role_token=token):
        return {
            "Authorization": "Bearer " + role_token,
            "X-Request-ID": str(uuid4()),
            "Idempotency-Key": str(uuid4()),
        }

    def post(path, body, role_token=token):
        response = client.post(path, json=body, headers=headers(role_token))
        assert response.status_code == 201, response.text
        return response.json()

    assessment = post("/api/v1/assessments", {"name": "T44 triage test only"})
    assessment_id = UUID(assessment["id"])
    base = f"/api/v1/assessments/{assessment_id}"
    scope = post(base + "/scopes", {"revision": 1, "targets": ["https://app.example.test"]})
    asset = post(base + "/assets", {"identifier": "https://app.example.test", "kind": "url"})
    observation_ids = []
    for suffix in ("one", "two"):
        run = ToolRun(
            assessment_id=assessment_id,
            scope_id=UUID(scope["id"]),
            tool="OWASP ZAP",
            tool_version="2.16.0",
            mode="recorded-import",
            captured_at=datetime.now(UTC),
            state="recorded",
        )
        evidence = EvidenceReference(
            assessment_id=assessment_id,
            run_id=run.id,
            sha256=sha256(suffix.encode()).hexdigest(),
            pointer="/alerts/0",
            pointer_type="json-pointer",
            captured_at=run.captured_at,
        )
        observation = Observation(
            assessment_id=assessment_id,
            asset_id=UUID(asset["id"]),
            run_id=run.id,
            evidence_id=evidence.id,
            source_key=suffix,
            title=f"Test-only source observation {suffix}",
            observed_at=run.captured_at,
            validation_state="suspected",
        )
        with client.app.state.engine.begin() as connection:
            insert_record(connection, "tool_runs", run)
            insert_record(connection, "evidence_references", evidence)
            insert_record(connection, "observations", observation)
        observation_ids.append(observation.id)

    path = base + "/finding-reviews"
    first = post(
        path,
        {
            "observation_id": str(observation_ids[0]),
            "validation_state": "contradictory",
            "contradictory_observation_ids": [str(observation_ids[1])],
            "rationale": "Handcrafted source records disagree; test only.",
        },
    )
    state = client.get(path, headers=headers()).json()
    decision = state["latest_by_observation"][str(observation_ids[0])]
    assert decision["validation_state"] == "contradictory"
    assert decision["contradictory_observation_ids"] == [str(observation_ids[1])]
    assert decision["confidence"] is None
    assert state["calibration_status"] == "not-calibrated"
    assert state["reviews"][-1]["id"] == first["id"]
    coverage = client.get(base + "/coverage", headers=headers()).json()
    ranked = coverage["observation_analytics"]["contextual_risk_ranking"]["ranked_observations"]
    reviewed = next(item for item in ranked if item["observation_id"] == str(observation_ids[0]))
    assert reviewed["priority"]["review_attention"] == "contradictory-evidence-review"
    assert reviewed["priority"]["reviewer_decision"]["rationale"]

    post(
        path,
        {
            "observation_id": str(observation_ids[0]),
            "validation_state": "false-positive",
            "expected_revision": 1,
            "rationale": "A later reviewer corrected the prior decision; test only.",
        },
    )
    state = client.get(path, headers=headers()).json()
    assert (
        state["latest_by_observation"][str(observation_ids[0])]["validation_state"]
        == "false-positive"
    )
    assert len(state["reviews"]) == 2
    assert state["revision"] == 2
    stale = client.post(
        path,
        json={
            "observation_id": str(observation_ids[0]),
            "expected_revision": 1,
            "validation_state": "confirmed",
            "rationale": "Stale reviewer view must not overwrite the later decision.",
        },
        headers=headers(),
    )
    assert stale.status_code == 409
    assert len(client.get(path, headers=headers()).json()["reviews"]) == 2

    with client.app.state.engine.begin() as connection:
        original = get_record(connection, "observations", assessment_id, observation_ids[0])
    assert original["validation_state"] == "suspected"
    assert original["evidence_id"] is not None

    analyst = client.post(
        path,
        json={
            "observation_id": str(observation_ids[0]),
            "validation_state": "confirmed",
            "rationale": "Analyst cannot make reviewer decisions.",
        },
        headers=headers(issue_identity(settings, "triage-analyst", "analyst")),
    )
    # The assessment access guard intentionally hides inaccessible assessments as 404.
    assert analyst.status_code == 404


@pytest.mark.services
def test_postgresql_triage_revision_conflicts(import_context):
    test_api_records_audited_reversible_triage_without_mutating_source_observation(import_context)

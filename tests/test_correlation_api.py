"""Correlation reviewer route integration uses synthetic observations, never scanner output."""

import hashlib
from datetime import UTC, datetime
from uuid import UUID, uuid4

from aegistrace.auth import issue_identity
from aegistrace.domain import Endpoint, EvidenceReference, Observation, ToolRun
from aegistrace.repository import get_record, insert_record

pytest_plugins = ("test_ingestion",)


def test_reviewer_can_merge_split_and_undo_without_mutating_source_observations(import_context):
    client, settings = import_context
    token = issue_identity(settings, "review-owner", "reviewer")

    def headers(role_token=token):
        return {
            "Authorization": "Bearer " + role_token,
            "X-Request-ID": str(uuid4()),
            "Idempotency-Key": str(uuid4()),
        }

    def post(path, body, role_token=token):
        if path.endswith("/correlations/reviews"):
            body = body | {
                "expected_revision": client.get(path, headers=headers()).json()["revision"]
            }
        response = client.post(path, json=body, headers=headers(role_token))
        assert response.status_code in {200, 201}, response.text
        return response.json()

    assessment = post("/api/v1/assessments", {"name": "T43 reviewer test only"})
    assessment_id = UUID(assessment["id"])
    base = f"/api/v1/assessments/{assessment_id}"
    scope = post(
        base + "/scopes",
        {"revision": 1, "targets": ["https://app.example.test"]},
    )
    asset = post(
        base + "/assets",
        {"identifier": "https://app.example.test", "kind": "url"},
    )
    endpoint_id = uuid4()
    endpoint = Endpoint(
        id=endpoint_id,
        assessment_id=assessment_id,
        asset_id=UUID(asset["id"]),
        path="/app/item",
        method="GET",
    )
    observed_values = []
    with client.app.state.engine.begin() as connection:
        insert_record(connection, "endpoints", endpoint)
        for tool, source_key in (("OWASP ZAP", "zap-1"), ("Nikto", "nikto-1")):
            run = ToolRun(
                assessment_id=assessment_id,
                scope_id=UUID(scope["id"]),
                tool=tool,
                tool_version="2.16.0" if tool == "OWASP ZAP" else "2.6.0",
                mode="recorded-import",
                captured_at=datetime.now(UTC),
                state="recorded",
            )
            evidence = EvidenceReference(
                assessment_id=assessment_id,
                run_id=run.id,
                sha256=hashlib.sha256(source_key.encode()).hexdigest(),
                pointer="/",
                pointer_type="whole-file",
                captured_at=run.captured_at,
            )
            observation = Observation(
                assessment_id=assessment_id,
                asset_id=UUID(asset["id"]),
                endpoint_id=endpoint_id,
                run_id=run.id,
                evidence_id=evidence.id,
                source_key=source_key,
                title=f"{tool}: test-only observation",
                observed_at=run.captured_at,
                cwe="CWE-79",
                parameter_names=["item"],
            )
            insert_record(connection, "tool_runs", run)
            insert_record(connection, "evidence_references", evidence)
            insert_record(connection, "observations", observation)
            observed_values.append(observation)

    candidate_snapshot = client.get(base + "/coverage", headers=headers()).json()
    candidates = candidate_snapshot["observation_analytics"]["cross_tool_candidate_groups"]
    assert len(candidates) == 1
    observation_ids = [str(value.id) for value in observed_values]
    merged = post(
        base + "/correlations/reviews",
        {
            "action": "merge",
            "observation_ids": observation_ids,
            "rationale": "Handcrafted source records share an exact endpoint and CWE; test only.",
        },
    )
    state = client.get(base + "/correlations/reviews", headers=headers()).json()
    assert state["reviewed_clusters"][0]["observation_ids"] == sorted(observation_ids)
    assert state["reviewed_clusters"][0]["occurrence_count"] == 2
    assert all(
        item["endpoint"] == {"path": "/app/item", "method": "GET"}
        for item in state["reviewed_clusters"][0]["observations"]
    )
    assert state["reviews"][-1]["id"] == merged["id"]
    stale = client.post(
        base + "/correlations/reviews",
        json={
            "action": "merge",
            "expected_revision": 0,
            "observation_ids": observation_ids,
            "rationale": "TEST ONLY stale concurrent review",
        },
        headers=headers(),
    )
    assert stale.status_code == 409

    split = post(
        base + "/correlations/reviews",
        {
            "action": "split",
            "cluster_id": state["reviewed_clusters"][0]["cluster_id"],
            "partitions": [[observation_ids[0]], [observation_ids[1]]],
            "rationale": "Test explicit separation and singleton occurrences.",
        },
    )
    separated = client.get(base + "/correlations/reviews", headers=headers()).json()
    assert separated["reviewed_clusters"] == []
    assert separated["reviewed_splits"][0]["partitions"] == [
        [observation_ids[0]],
        [observation_ids[1]],
    ]
    assert separated["reviews"][-1]["id"] == split["id"]

    post(
        base + "/correlations/reviews",
        {"action": "undo", "target_review_id": split["id"], "rationale": "Restore prior merge."},
    )
    restored = client.get(base + "/correlations/reviews", headers=headers()).json()
    assert restored["reviewed_splits"] == []
    assert restored["reviewed_clusters"][0]["observation_ids"] == sorted(observation_ids)

    with client.app.state.engine.connect() as connection:
        saved = [
            get_record(connection, "observations", assessment_id, value.id)
            for value in observed_values
        ]
    assert {value["endpoint_id"] for value in saved} == {str(endpoint_id)}
    assert {value["evidence_id"] for value in saved} == {
        str(value.evidence_id) for value in observed_values
    }
    denied = client.post(
        base + "/correlations/reviews",
        json={
            "action": "merge",
            "observation_ids": observation_ids,
            "rationale": "Analyst cannot create reviewer-only decisions.",
        },
        headers=headers(issue_identity(settings, "review-owner", "analyst")),
    )
    assert denied.status_code == 403

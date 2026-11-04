"""Shared logical admission budgets and repeated proposals; no native packet-rate claims."""

from uuid import UUID

import pytest
from aegistrace.approval_schema import grants
from aegistrace.approvals import ActionRequest
from aegistrace.jobs import publish_pending
from aegistrace.scheduler import fingerprint, queue_for
from aegistrace.scheduler_schema import admissions, buckets
from sqlalchemy import select
from test_approvals import prepared, review
from test_jobs import queued
from test_policy import policy_context as policy_context


def fresh_approval(context, base, headers, original_body, **changes):
    client, _, _ = context
    original = client.get(
        base + "/action-approvals/" + original_body["approval_id"], headers=headers()
    ).json()
    response = client.post(
        base + "/action-approvals", json=original["action"] | changes, headers=headers()
    )
    assert response.status_code == 201, response.text
    approval = response.json()
    review(context, base, headers, approval)
    return {"approval_id": approval["id"], "action_digest": approval["action_digest"]}


def test_identical_new_approval_suppresses_without_consuming_it(policy_context):
    client, engine, _ = policy_context
    base, headers, body, _, job = queued(policy_context)
    again = fresh_approval(policy_context, base, headers, body)
    result = client.post(base + "/scan-jobs", json=again, headers=headers())
    assert result.status_code == 202, result.text
    assert result.json()["id"] == job["id"] and not result.json()["new_approval_consumed"]
    assert result.json()["scheduling_reason"] == "identical work pending"
    with engine.connect() as connection:
        assert (
            connection.execute(
                select(grants.c.state).where(grants.c.id == again["approval_id"])
            ).scalar_one()
            == "approved"
        )


def test_shared_rate_budget_and_changed_parameters_do_not_reuse(policy_context):
    client, engine, _ = policy_context
    base, headers, body, _, job = queued(policy_context)
    changed = fresh_approval(policy_context, base, headers, body, parameters={"timeout_seconds": 4})
    denied = client.post(base + "/scan-jobs", json=changed, headers=headers())
    assert denied.status_code == 422 and ("rate" in denied.text or "concurrency" in denied.text)
    # Isolate the admission policy itself from T13's stricter per-policy concurrency.
    with engine.begin() as connection:
        action = ActionRequest.model_validate(
            connection.execute(
                select(grants.c.payload).where(grants.c.id == changed["approval_id"])
            ).scalar_one()["action"]
        )
        first = connection.execute(
            select(admissions.c.fingerprint).where(admissions.c.job_id == job["id"])
        ).scalar_one()
        assert fingerprint(connection, UUID(job["assessment_id"]), action)[0] != first
        connection.execute(buckets.update().values(updated_at=buckets.c.updated_at - 10))
        assert queue_for(connection, job["id"]) == "celery"


def test_cross_assessment_target_limit_overrides_preference(policy_context):
    client, engine, _ = policy_context
    base, headers, body, _, job = queued(policy_context)
    with engine.begin() as connection:
        connection.execute(buckets.update().values(updated_at=buckets.c.updated_at - 10))
    *_, second = queued(policy_context)
    assert second["assessment_id"] != job["assessment_id"]
    with engine.begin() as connection:
        connection.execute(buckets.update().values(updated_at=buckets.c.updated_at - 10))
    third_base, third_headers, value, _ = prepared(policy_context)
    review(policy_context, third_base, third_headers, value)
    response = client.post(
        third_base + "/scan-jobs",
        json={"approval_id": value["id"], "action_digest": value["action_digest"], "priority": 10},
        headers=third_headers(),
    )
    assert response.status_code == 422 and "shared target concurrency" in response.text


def test_hourly_budget_denial_does_not_consume_new_approval(policy_context, monkeypatch):
    import aegistrace.scheduler as scheduler

    monkeypatch.setattr(scheduler, "MAX_ASSESSMENT_JOBS_PER_HOUR", 1)
    client, engine, _ = policy_context
    base, headers, body, _, _ = queued(policy_context)
    changed = fresh_approval(policy_context, base, headers, body, parameters={"timeout_seconds": 3})
    response = client.post(base + "/scan-jobs", json=changed, headers=headers())
    assert response.status_code == 422 and "hourly job budget" in response.text
    with engine.connect() as connection:
        assert (
            connection.execute(
                select(grants.c.state).where(grants.c.id == changed["approval_id"])
            ).scalar_one()
            == "approved"
        )


def test_oldest_bounded_dispatch_and_no_priority_starvation(policy_context):
    _, engine, _ = policy_context
    *_, job = queued(policy_context)
    with engine.begin() as connection:
        connection.execute(buckets.update().values(updated_at=buckets.c.updated_at - 10))
        connection.execute(
            admissions.update()
            .where(admissions.c.job_id == job["id"])
            .values(priority=0, admitted_at=admissions.c.admitted_at - 20)
        )
    *_, second = queued(policy_context)
    with engine.begin() as connection:
        connection.execute(
            admissions.update().where(admissions.c.job_id == second["id"]).values(priority=10)
        )
    published = []
    assert publish_pending(engine, published.append, limit=2) == 2 and published == [
        job["id"],
        second["id"],
    ]


@pytest.mark.services
def test_postgresql_scheduler_suppression(policy_context):
    with policy_context[1].begin() as connection:
        connection.execute(buckets.update().values(updated_at=buckets.c.updated_at - 10))
    test_identical_new_approval_suppresses_without_consuming_it(policy_context)

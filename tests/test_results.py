"""Result revisions, late callbacks and frozen exports preserve reviewed history."""

from uuid import UUID, uuid4

import pytest
from aegistrace.auth import issue_identity
from aegistrace.job_schema import jobs
from aegistrace.result_schema import exports, revisions
from aegistrace.results import quarantine_late
from sqlalchemy import select
from sqlalchemy.exc import DatabaseError
from test_ingestion import import_context as import_context
from test_jobs import policy_context as policy_context
from test_jobs import queued
from test_nmap import source


def test_revision_and_export_are_frozen_and_late_callback_is_quarantined(import_context):
    client, config = import_context

    def headers():
        return {
            "Authorization": "Bearer " + issue_identity(config, "owner", "reviewer"),
            "X-Request-ID": str(uuid4()),
            "Idempotency-Key": str(uuid4()),
        }

    base, _, imported, _, run, evidence = source(import_context)
    normalized = client.post(
        base + "/imports/" + imported["id"] + "/normalize-nmap", json={}, headers=headers()
    )
    assert normalized.status_code == 201, normalized.text
    value = normalized.json()
    assert value["run_revision"] == 1 and value["result_revision_id"]
    revision = value["result_revision_id"]
    assert (
        client.get(base + "/result-revisions", headers=headers()).json()[0]["captured_at"]
        == run["captured_at"]
    )
    export = client.post(
        base + "/result-exports", json={"revision_ids": [revision]}, headers=headers()
    )
    assert export.status_code == 201, export.text
    frozen = client.get(base + "/result-exports/" + export.json()["id"], headers=headers())
    assert frozen.status_code == 200 and frozen.json()["sha256"] == export.json()["sha256"]
    assert frozen.json()["snapshot"]["complete_assessment"] is False
    assert frozen.json()["snapshot"]["report_renderer_enabled"] is False
    engine = client.app.state.engine
    with engine.begin() as connection:
        with pytest.raises(DatabaseError), connection.begin_nested():
            connection.execute(
                exports.update().where(exports.c.id == export.json()["id"]).values(sha256="0" * 64)
            )
    assert (
        client.get(base + "/result-exports/" + export.json()["id"], headers=headers()).json()[
            "sha256"
        ]
        == export.json()["sha256"]
    )


def test_late_output_keeps_canonical_result_unchanged(policy_context):
    _, engine, config = policy_context
    *_, job = queued(policy_context)
    worker = uuid4()
    with engine.begin() as connection:
        connection.execute(
            jobs.update()
            .where(jobs.c.id == job["id"])
            .values(state="unknown", worker_id=str(worker), epoch=4, lease_until=0)
        )
        first = quarantine_late(
            connection,
            config,
            UUID(job["id"]),
            worker,
            4,
            b"TEST ONLY late output; no scanner data",
        )
        second = quarantine_late(
            connection,
            config,
            UUID(job["id"]),
            worker,
            4,
            b"TEST ONLY late output; no scanner data",
        )
        assert first == second
        assert connection.execute(select(revisions)).first() is None
    assert first


@pytest.mark.services
def test_postgresql_immutable_result_export(import_context):
    test_revision_and_export_are_frozen_and_late_callback_is_quarantined(import_context)

"""Immutable labelled test-only replay; never scanner proof or current action authority."""

import socket

import pytest
from aegistrace.replay_schema import manifests, protect_replays
from sqlalchemy.exc import DatabaseError
from test_ingestion import import_context as import_context
from test_nmap import source


def test_recorded_replay_has_no_network_or_approval_side_effect(import_context, monkeypatch):
    client, config = import_context
    base, headers, imported, _, _, _ = source(import_context)
    normalized = client.post(
        base + "/imports/" + imported["id"] + "/normalize-nmap", json={}, headers=headers()
    )
    assert normalized.status_code == 201, normalized.text

    def deny(*_, **__):
        raise AssertionError("Replay must not contact targets or intelligence sources")

    monkeypatch.setattr(socket, "create_connection", deny)
    manifest = client.post(base + "/replays", json={"import_id": imported["id"]}, headers=headers())
    assert manifest.status_code == 201, manifest.text
    value = manifest.json()
    assert value["label"] == "RECORDED / TEST ONLY" and not value["network_execution_enabled"]
    assert not value["historical_decisions_are_current_authority"]
    route = base + "/replays/" + value["id"] + "/ingest"
    h = headers()
    response = client.post(route, headers=h)
    assert response.status_code == 201, response.text
    result = response.json()
    assert (
        result["run_id"] == normalized.json()["run_id"]
        and result["captured_at"] == normalized.json()["captured_at"]
    )
    assert (
        result["source_sha256"] == value["source_sha256"]
        and result["replay_manifest_sha256"] == value["manifest_sha256"]
    )
    assert not result["native_live_execution"] and result["findings_created"] == 0
    assert client.post(route, headers=h).json() == result
    assert client.get(base + "/replays/" + value["id"], headers=headers()).json() == value
    assert (
        client.post(
            base + "/replays",
            json={"import_id": imported["id"], "provenance": "reviewer-declared-capture"},
            headers=headers(),
        ).status_code
        == 422
    )
    # DB-level append-only policy, in addition to absence of update/delete endpoints.
    engine = client.app.state.engine
    with engine.begin() as connection:
        if connection.dialect.name == "sqlite":
            protect_replays(connection)
        with pytest.raises(DatabaseError), connection.begin_nested():
            connection.execute(
                manifests.update().where(manifests.c.id == value["id"]).values(sha256="0" * 64)
            )


@pytest.mark.services
def test_postgresql_immutable_replay(import_context, monkeypatch):
    test_recorded_replay_has_no_network_or_approval_side_effect(import_context, monkeypatch)

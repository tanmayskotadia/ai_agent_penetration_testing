"""Persistent controls and real harmless subprocesses, never scanner/report output."""

import hashlib
import json
import os
import secrets
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import psutil
import pytest
from aegistrace.approvals import consume
from aegistrace.control import begin_execution, finish_execution, heartbeat
from aegistrace.control_schema import executions
from aegistrace.policy import PolicyError
from aegistrace_workers.process_control import run_managed, running
from pydantic import SecretStr
from test_approvals import prepared, review
from test_policy import policy_context as policy_context


def claimed(context):
    client, engine, config = context
    base, headers, value, _ = prepared(context)
    review(context, base, headers, value)
    with engine.begin() as connection:
        claim = consume(
            connection,
            config,
            UUID(value["assessment_id"]),
            UUID(value["id"]),
            value["action_digest"],
        )
    return base, headers, value, claim


def test_stop_before_dispatch_revokes_and_resume_does_not_restore(policy_context):
    client, engine, config = policy_context
    base, headers, value, _ = prepared(policy_context)
    review(policy_context, base, headers, value)
    stopped = client.post(base + "/controls/stop", headers=headers())
    assert stopped.status_code == 200 and stopped.json()["stopped"]
    with engine.begin() as connection, pytest.raises(PolicyError):
        consume(
            connection,
            config,
            UUID(value["assessment_id"]),
            UUID(value["id"]),
            value["action_digest"],
        )
    assert (
        client.post(base + "/controls/resume", headers=headers()).json()["old_approvals_restored"]
        is False
    )
    with engine.begin() as connection, pytest.raises(PolicyError):
        consume(
            connection,
            config,
            UUID(value["assessment_id"]),
            UUID(value["id"]),
            value["action_digest"],
        )


def test_per_job_cancel_before_start_and_stop_during_worker(policy_context):
    client, engine, _ = policy_context
    base, headers, value, claim = claimed(policy_context)
    response = client.post(base + "/controls/jobs/" + claim["id"] + "/cancel", headers=headers())
    assert response.json()["state"] == "cancelled-before-start"
    with engine.begin() as connection, pytest.raises(PolicyError):
        begin_execution(connection, UUID(claim["id"]), uuid4(), "scanner", config=policy_context[2])


@pytest.mark.parametrize("kind", ["scanner", "report"])
def test_running_control_lease_cancel_confirmation_and_unknown(policy_context, kind):
    client, engine, _ = policy_context
    base, headers, _, claim = claimed(policy_context)
    worker = uuid4()
    with engine.begin() as connection:
        execution = begin_execution(
            connection, UUID(claim["id"]), worker, kind, config=policy_context[2]
        )
    response = client.post(base + "/controls/stop", headers=headers()).json()
    assert response["running_cancel_requests"] == 1 and not response["termination_confirmed"]
    with engine.begin() as connection:
        assert heartbeat(connection, UUID(claim["id"]), worker, execution["epoch"])
        assert (
            finish_execution(connection, UUID(claim["id"]), worker, execution["epoch"], True)
            == "terminated"
        )
    assert client.post(base + "/controls/resume", headers=headers()).status_code == 200


def test_disconnected_worker_is_unknown_and_blocks_resume(policy_context):
    client, engine, _ = policy_context
    base, headers, _, claim = claimed(policy_context)
    worker = uuid4()
    with engine.begin() as connection:
        execution = begin_execution(
            connection, UUID(claim["id"]), worker, "scanner", config=policy_context[2]
        )
        connection.execute(
            executions.update().where(executions.c.claim_id == claim["id"]).values(lease_until=0)
        )
    response = client.post(base + "/controls/stop", headers=headers()).json()
    assert response["unknown_disconnected"] == 1 and not response["termination_confirmed"]
    repeated = client.post(base + "/controls/stop", headers=headers()).json()
    assert repeated["unknown_disconnected"] == 1 and not repeated["termination_confirmed"]
    assert client.get(base + "/controls", headers=headers()).json()["jobs"][0]["state"] == "unknown"
    assert client.post(base + "/controls/resume", headers=headers()).status_code == 422
    with engine.begin() as connection, pytest.raises(PolicyError):
        finish_execution(connection, UUID(claim["id"]), worker, execution["epoch"], True)


def test_reset_required_blocks_resume_without_reviewed_evidence(policy_context):
    client, engine, _ = policy_context
    base, headers, _, claim = claimed(policy_context)
    worker = uuid4()
    with engine.begin() as connection:
        execution = begin_execution(
            connection, UUID(claim["id"]), worker, "scanner", config=policy_context[2]
        )
        connection.execute(
            executions.update()
            .where(executions.c.claim_id == claim["id"])
            .values(reset_required=True)
        )
        assert (
            finish_execution(connection, UUID(claim["id"]), worker, execution["epoch"], True)
            == "reset-required"
        )
    client.post(base + "/controls/stop", headers=headers())
    assert client.post(base + "/controls/resume", headers=headers()).status_code == 422
    assert (
        client.post(
            base + "/controls/jobs/" + claim["id"] + "/evidence",
            json={"evidence_id": str(uuid4()), "attestation": "reset-reviewed"},
            headers=headers(),
        ).status_code
        == 404
    )


def test_real_process_tree_termination_and_latency(tmp_path):
    marker = tmp_path / "owned-pids.json"
    source = "import subprocess,sys,time,json,os; child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']); open(sys.argv[1],'w').write(json.dumps([os.getpid(),child.pid])); time.sleep(60)"
    started = time.monotonic()
    result = run_managed((sys.executable, "-c", source, str(marker)), 5, lambda: marker.exists())
    assert result.state == "terminated" and result.termination_confirmed
    assert result.elapsed_seconds < 3 and time.monotonic() - started < 4
    for pid in json.loads(marker.read_text()):
        try:
            assert not running(psutil.Process(pid))
        except psutil.NoSuchProcess:
            pass


def test_deadline_control_failure_and_secret_free_child_environment(monkeypatch):
    monkeypatch.setenv("APP_SECRET", "test-secret-must-not-reach-child")
    result = run_managed(
        (sys.executable, "-c", "import os;assert 'APP_SECRET' not in os.environ"), 2, lambda: False
    )
    assert result.exit_code == 0
    timed = run_managed((sys.executable, "-c", "import time;time.sleep(60)"), 0.2, lambda: False)
    assert timed.reason == "deadline" and timed.termination_confirmed
    calls = 0

    def broken_control():
        nonlocal calls
        calls += 1
        if calls > 1:
            raise ConnectionError("test control disconnection")
        return False

    failed = run_managed((sys.executable, "-c", "import time;time.sleep(60)"), 2, broken_control)
    assert failed.reason == "control-unavailable" and failed.termination_confirmed


@pytest.mark.services
def test_postgresql_stop_and_disconnected_worker(policy_context):
    if os.environ.get("RUN_SERVICE_TESTS") != "1":
        pytest.skip("requires PostgreSQL")
    test_disconnected_worker_is_unknown_and_blocks_resume(policy_context)


def test_api_stop_terminates_real_owned_process_through_worker_lease(policy_context, tmp_path):
    client, engine, config = policy_context
    base, headers, _, claim = claimed(policy_context)
    claim_id = UUID(claim["id"])
    worker = uuid4()
    marker = tmp_path / "supervised-process.pid"
    source = "import os,sys,time;open(sys.argv[1],'w').write(str(os.getpid()));time.sleep(60)"

    def execute():
        with engine.begin() as connection:
            execution = begin_execution(connection, claim_id, worker, "scanner", config)

        def cancelled():
            with engine.begin() as connection:
                return heartbeat(connection, claim_id, worker, execution["epoch"])

        result = run_managed((sys.executable, "-c", source, str(marker)), 4, cancelled)
        with engine.begin() as connection:
            state = finish_execution(
                connection, claim_id, worker, execution["epoch"], result.termination_confirmed
            )
        return result, state

    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(execute)
        deadline = time.monotonic() + 3
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        assert marker.exists(), "test process did not start"
        started = time.monotonic()
        stopped = client.post(base + "/controls/stop", headers=headers())
        assert stopped.status_code == 200
        result, state = future.result(timeout=4)
        assert result.termination_confirmed and state == "terminated"
        assert time.monotonic() - started < 3
    assert (
        client.get(base + "/controls", headers=headers()).json()["jobs"][0]["state"] == "terminated"
    )


def test_reset_attestation_requires_existing_private_original(policy_context):
    client, engine, config = policy_context
    config.evidence_key = SecretStr(secrets.token_hex(32))
    base, headers, approval, claim = claimed(policy_context)
    worker = uuid4()
    with engine.begin() as connection:
        execution = begin_execution(connection, UUID(claim["id"]), worker, "scanner", config)
        # Synthetic state-changing-job flag; no actual target was changed.
        connection.execute(
            executions.update()
            .where(executions.c.claim_id == claim["id"])
            .values(reset_required=True)
        )
        finish_execution(connection, UUID(claim["id"]), worker, execution["epoch"], True)

    def post(path, body):
        response = client.post(path, json=body, headers=headers())
        assert response.status_code in {200, 201, 202}, response.text
        return response.json()

    now = datetime.now(UTC).isoformat()
    run = post(
        base + "/runs",
        {
            "scope_id": approval["scope_id"],
            "tool": "Nmap",
            "tool_version": "TEST ONLY",
            "captured_at": now,
        },
    )
    raw = b"TEST ONLY human reset attestation; not actual target-cleanup proof"
    evidence = post(
        base + "/runs/" + run["id"] + "/evidence",
        {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "pointer": "/",
            "pointer_type": "whole-file",
            "captured_at": now,
        },
    )
    uploaded = client.put(
        base + "/evidence/" + evidence["id"] + "/original",
        content=raw,
        params={"expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat()},
        headers=headers(),
    )
    assert uploaded.status_code == 201
    result = post(
        base + "/controls/jobs/" + claim["id"] + "/evidence",
        {"evidence_id": evidence["id"], "attestation": "reset-reviewed"},
    )
    assert result["state"] == "reset-attested" and "human-reviewed" in result["basis"]

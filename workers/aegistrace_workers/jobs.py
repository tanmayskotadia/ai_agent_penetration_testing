"""Internal durable worker for action-bound web scans; runtime stays disabled by default."""

import hashlib
import os
import tempfile
import time
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from aegistrace.api_schema import resources
from aegistrace.approval_schema import claims, grants
from aegistrace.auth import Identity
from aegistrace.db import make_engine
from aegistrace.domain import EvidenceReference, ToolRun
from aegistrace.evidence import EvidenceStore
from aegistrace.jobs import append_output, finish_job, job_heartbeat, start_job
from aegistrace.platform_api import record_request
from aegistrace.policy import (
    Destination,
    ExecutionPolicy,
    PolicyError,
    authorize,
    load_policy,
)
from aegistrace.policy import destination as parse_destination
from aegistrace.repository import insert_record
from aegistrace.settings import Settings
from sqlalchemy import Connection, Engine, select

from aegistrace_workers.adapters.scoped_proxy import ProxyPolicy, ScopedEgressProxy
from aegistrace_workers.adapters.web_scanners import (
    PinnedBinary,
    discover_version,
    execute_json_artifact,
    validate_har_input,
)
from aegistrace_workers.command_builder import RegisteredExecutable, build_command


def _executables(
    config: Settings, selected_tool: str
) -> dict[str, RegisteredExecutable]:
    values: dict[str, RegisteredExecutable] = {}
    for tool, path_value, sha256 in (
        ("OWASP ZAP", config.zap_executable_path, config.zap_executable_sha256),
        ("Nikto", config.nikto_executable_path, config.nikto_executable_sha256),
    ):
        if tool != selected_tool:
            continue
        if path_value is None and sha256 is None:
            continue
        if path_value is None or sha256 is None:
            raise ValueError("scanner path and digest must be configured together")
        binary = PinnedBinary(Path(path_value), sha256)
        version = discover_version(binary, tool)  # type: ignore[arg-type]
        values[tool] = RegisteredExecutable(binary.path, binary.sha256, version.version)
    return values


def _authorized_destination(
    connection: Connection,
    assessment_id: UUID,
    claim: Mapping[str, Any],
    config: Settings,
) -> tuple[ExecutionPolicy, Destination]:
    action = claim["action"]
    policy = load_policy(connection, assessment_id, UUID(action["policy_id"]))
    return policy, authorize(
        policy,
        action["destination_url"],
        action["profile"],
        protected_networks=config.control_plane_networks,
    )


def _run_web_job(
    config: Settings, engine: Engine, job_uuid: UUID, job: Mapping[str, Any], worker_id: UUID
) -> str:
    if not config.web_scanner_candidate_enabled or not config.web_scanner_egress_gate_reference:
        with engine.begin() as connection:
            return finish_job(connection, job_uuid, worker_id, job["epoch"], "blocked", True)
    claim_id = UUID(job["claim_id"])
    with engine.connect() as connection:
        claim_row = (
            connection.execute(select(claims.c.payload).where(claims.c.id == str(claim_id)))
            .mappings()
            .one()
        )
        claim = dict(claim_row["payload"])
        policy, destination = _authorized_destination(
            connection, UUID(job["assessment_id"]), claim, config
        )
    if claim["action"]["template"] not in {
        "zap.passive.v1",
        "zap.active.v1",
        "nikto.active.v1",
    }:
        with engine.begin() as connection:
            return finish_job(connection, job_uuid, worker_id, job["epoch"], "blocked", True)
    included_paths = (destination.path,)
    excluded_paths = tuple(
        rule.path
        for value in policy.exclusions
        if "://" in value
        for rule in (parse_destination(value),)
        if (rule.host, rule.protocol, rule.port)
        == (destination.host, destination.protocol, destination.port)
    )
    remaining = datetime.fromisoformat(claim["deadline"]).timestamp() - time.time()
    if remaining <= 0:
        raise PolicyError("job claim deadline expired")
    runtime = min(int(claim["action"]["max_runtime_seconds"]), max(1, int(remaining)))
    last_cancel_check = [0.0]
    cancellation_state = [False]

    def cancelled() -> bool:
        current = time.monotonic()
        if current - last_cancel_check[0] >= 0.5:
            cancellation_state[0] = _cancel_requested(engine, job_uuid, worker_id, job["epoch"])
            last_cancel_check[0] = current
        return cancellation_state[0]

    proxy_policy = ProxyPolicy(
        destination=destination,
        included_paths=included_paths,
        excluded_paths=excluded_paths,
        deadline=time.monotonic() + runtime,
        cancelled=cancelled,
    )
    executables = _executables(config, claim["action"]["tool"])
    with tempfile.TemporaryDirectory(prefix="aegistrace-web-") as temporary:
        workspace = Path(temporary)
        os.chmod(workspace, 0o700)
        try:
            template = claim["action"]["template"]
            har_filename = None
            if template == "zap.passive.v1":
                evidence_ids = claim["action"]["evidence_ids"]
                if len(evidence_ids) != 1:
                    raise ValueError("passive ZAP requires exactly one approved HAR evidence ID")
                source_evidence_id = UUID(evidence_ids[0])
                with engine.begin() as connection:
                    har = EvidenceStore(config).read_worker_input(
                        connection,
                        UUID(job["assessment_id"]),
                        source_evidence_id,
                        job_uuid,
                        worker_id,
                        job["epoch"],
                    )
                validate_har_input(har, destination, included_paths, excluded_paths)
                har_path = workspace / "source.har"
                har_path.write_bytes(har)
                os.chmod(har_path, 0o600)
                har_filename = har_path.name
                with engine.connect() as connection:
                    command = build_command(
                        connection=connection,
                        config=config,
                        claim_id=claim_id,
                        worker_id=worker_id,
                        epoch=job["epoch"],
                        executables=executables,
                        output_directory=workspace,
                        har_filename=har_filename,
                        allow_unverified_web_candidate=True,
                    )
                if command.artifact_path is None:
                    raise ValueError("web scanner command has no artifact output")
                raw, result = execute_json_artifact(
                    command.argv, command.artifact_path, command.max_runtime_seconds, cancelled
                )
            else:
                with ScopedEgressProxy(proxy_policy) as proxy:
                    with engine.connect() as connection:
                        command = build_command(
                            connection=connection,
                            config=config,
                            claim_id=claim_id,
                            worker_id=worker_id,
                            epoch=job["epoch"],
                            executables=executables,
                            output_directory=workspace,
                            proxy_url=proxy.url,
                            allow_unverified_web_candidate=True,
                        )
                    if command.artifact_path is None:
                        raise ValueError("web scanner command has no artifact output")
                    raw, result = execute_json_artifact(
                        command.argv,
                        command.artifact_path,
                        command.max_runtime_seconds,
                        cancelled,
                    )
            with engine.begin() as connection:
                digest = append_output(connection, config, job_uuid, worker_id, job["epoch"], raw)
                import_id = _record_import(
                    connection,
                    config,
                    job_uuid,
                    worker_id,
                    job,
                    claim,
                    executables[claim["action"]["tool"]].version,
                    raw,
                )
                state = finish_job(
                    connection,
                    job_uuid,
                    worker_id,
                    job["epoch"],
                    "collected",
                    result.termination_confirmed,
                    tool_version=executables[claim["action"]["tool"]].version,
                    exit_code=result.exit_code,
                )
            return f"{state}; artifact-sha256={digest}; import-id={import_id}"
        except Exception:
            with engine.begin() as connection:
                return finish_job(
                    connection,
                    job_uuid,
                    worker_id,
                    job["epoch"],
                    "failed",
                    True,
                    diagnostic_code="native-runner-failed",
                )


def _cancel_requested(engine: Engine, job_id: UUID, worker_id: UUID, epoch: int) -> bool:
    try:
        with engine.begin() as connection:
            return job_heartbeat(connection, job_id, worker_id, epoch)
    except Exception:
        return True


def _record_import(
    connection: Connection,
    config: Settings,
    job_id: UUID,
    worker_id: UUID,
    job: Mapping[str, Any],
    claim: Mapping[str, Any],
    tool_version: str,
    raw: bytes,
) -> UUID:
    """Create a durable encrypted run/evidence/import under the active job fence."""
    if len(raw) > 2 * 1024 * 1024:
        raise ValueError("scanner artifact exceeds durable evidence limit")
    assessment_id = UUID(job["assessment_id"])
    action = claim["action"]
    approval = (
        connection.execute(select(grants.c.payload).where(grants.c.id == claim["approval_id"]))
        .mappings()
        .one()
    )
    scope_id = UUID(approval["payload"]["scope_id"])
    scope_revision = approval["payload"]["scope_revision"]
    if type(scope_revision) is not int:
        raise ValueError("approval scope revision is invalid")
    run = ToolRun(
        assessment_id=assessment_id,
        scope_id=scope_id,
        tool=action["tool"],
        tool_version=tool_version,
        mode="live",
        captured_at=datetime.now(UTC),
        state="completed",
    )
    evidence_id = uuid4()
    evidence = EvidenceReference(
        assessment_id=assessment_id,
        run_id=run.id,
        sha256=hashlib.sha256(raw).hexdigest(),
        pointer="/",
        pointer_type="whole-file",
        captured_at=run.captured_at,
        id=evidence_id,
    )
    insert_record(connection, "tool_runs", run)
    insert_record(connection, "evidence_references", evidence)
    EvidenceStore(config).put_worker_output(
        connection,
        assessment_id,
        evidence_id,
        job_id,
        worker_id,
        job["epoch"],
        raw,
        datetime.now(UTC) + timedelta(days=30),
    )
    import_id = uuid4()
    format_name = "zap-alerts-json" if action["tool"] == "OWASP ZAP" else "nikto-json"
    payload = {
        "id": str(import_id),
        "assessment_id": str(assessment_id),
        "kind": "imports",
        "revision": 1,
        "state": "pending-ingestion",
        "reason": None,
        "mode": "recorded-import",
        "request": {
            "schema_version": "1.0",
            "scope_id": str(scope_id),
            "scope_revision": scope_revision,
            "tool": action["tool"],
            "format": format_name,
            "evidence_id": str(evidence_id),
        },
    }
    connection.execute(
        resources.insert().values(
            id=str(import_id),
            assessment_id=str(assessment_id),
            kind="imports",
            payload=payload,
        )
    )
    record_request(
        connection,
        assessment_id,
        Identity(
            subject=f"scanner-worker:{worker_id}",
            role="scanner",
            principal_kind="service",
            expires=int(time.time()) + 1,
        ),
        "scanner.artifact-import-created",
        import_id,
        {
            "run_id": str(run.id),
            "evidence_id": str(evidence_id),
            "sha256": evidence.sha256,
            "tool": action["tool"],
            "tool_version": tool_version,
            "retention_days": 30,
        },
    )
    return import_id


def consume_job(config: Settings, job_id: str) -> str:
    job_uuid = UUID(job_id)
    worker_id = uuid4()
    engine = make_engine(config)
    try:
        with engine.begin() as connection:
            job = start_job(connection, config, job_uuid, worker_id)
        if job is None:
            return "not-started; duplicate-or-authority-invalid"
        try:
            return _run_web_job(config, engine, job_uuid, job, worker_id)
        except Exception:
            try:
                with engine.begin() as connection:
                    return finish_job(
                        connection,
                        job_uuid,
                        worker_id,
                        job["epoch"],
                        "failed",
                        True,
                        diagnostic_code="native-runner-failed",
                    )
            except (PolicyError, ValueError):
                return "failed; reconciliation-required"
    finally:
        engine.dispose()

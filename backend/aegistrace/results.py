"""Append-only evidence revisions, frozen JSON exports and fenced late-output quarantine."""

import hashlib
import json
import secrets
import time
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import Connection, func, select

from aegistrace.api_schema import resources
from aegistrace.auth import Identity
from aegistrace.domain import ReportSnapshot
from aegistrace.evidence import EvidenceStore
from aegistrace.job_progress import append_progress
from aegistrace.jobs import job_event, lock_job
from aegistrace.platform_api import record_request
from aegistrace.policy import PolicyError
from aegistrace.report_content import build_vapt_content
from aegistrace.repository import insert_record, require_access
from aegistrace.result_schema import exports, late_outputs, revisions
from aegistrace.schema_v1 import (
    approvals,
    assets,
    decisions,
    findings,
    observations,
    occurrences,
    scope_versions,
    tool_runs,
)
from aegistrace.settings import Settings


def content_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def record_revision(connection: Connection, snapshot: dict[str, Any]) -> dict[str, Any]:
    """Called inside normalization's assessment-locked transaction, not from model output."""
    # Serialize revision number allocation per run on PostgreSQL; SQLite is already a writer lock.
    connection.execute(
        tool_runs.update()
        .where(tool_runs.c.id == snapshot["run_id"])
        .values(scope_id=tool_runs.c.scope_id)
    )
    run_payload = connection.execute(
        select(tool_runs.c.payload).where(tool_runs.c.id == snapshot["run_id"])
    ).scalar_one()
    key = content_hash(
        {
            name: snapshot[name]
            for name in ["source_sha256", "parser_revision", "asset_mapping", "state", "code"]
        }
    )
    prior = connection.execute(
        select(revisions.c.payload).where(
            revisions.c.run_id == snapshot["run_id"], revisions.c.input_key == key
        )
    ).scalar_one_or_none()
    if prior is not None:
        return dict(prior)
    number = (
        connection.execute(
            select(func.coalesce(func.max(revisions.c.revision), 0)).where(
                revisions.c.run_id == snapshot["run_id"]
            )
        ).scalar_one()
        + 1
    )
    payload = {
        "id": str(uuid4()),
        "assessment_id": snapshot["assessment_id"],
        "run_id": snapshot["run_id"],
        "tool": run_payload["tool"],
        "tool_version": run_payload["tool_version"],
        "revision": number,
        "input_key": key,
        "normalization_id": snapshot["id"],
        "created_at": datetime.now(UTC).isoformat(),
        "captured_at": snapshot["captured_at"],
        "mode": snapshot["mode"],
        "information_kind": "observed-evidence",
        "state": snapshot["state"],
        "parser_code": snapshot["code"],
        "evidence_id": snapshot["evidence_id"],
        "source_sha256": snapshot["source_sha256"],
        "parser_revision": snapshot["parser_revision"],
        "observation_ids": snapshot["observation_ids"],
        "asset_ids": snapshot["asset_ids"],
        "service_ids": snapshot["service_ids"],
        "assessment_coverage": "unknown; source records only",
        "complete_assessment": False,
        "warnings": snapshot["limitations"]
        + (
            []
            if snapshot["state"] == "normalized"
            else ["Partial/quarantined input cannot establish complete coverage"]
        ),
    }
    connection.execute(
        revisions.insert().values(
            id=payload["id"],
            assessment_id=payload["assessment_id"],
            run_id=payload["run_id"],
            revision=number,
            input_key=key,
            payload=payload,
        )
    )
    return payload


def freeze_export(
    connection: Connection, assessment_id: UUID, ids: tuple[UUID, ...], actor: Identity
) -> dict[str, Any]:
    require_access(connection, assessment_id, actor.subject)
    if actor.principal_kind != "human" or actor.role not in {"reviewer", "admin"}:
        raise PolicyError("human reviewer required to freeze export")
    values = []
    for revision_id in dict.fromkeys(ids):
        value = connection.execute(
            select(revisions.c.payload).where(
                revisions.c.id == str(revision_id), revisions.c.assessment_id == str(assessment_id)
            )
        ).scalar_one_or_none()
        if value is None:
            raise LookupError("revision not found")
        values.append(value)
    from aegistrace.coverage import assessment_coverage

    coverage = assessment_coverage(connection, assessment_id)
    limitations = [
        "The report content is complete as a section contract; assessment completeness and live coverage are not established",
        "Recorded/imported sources retain original capture times",
        "Later results require a new reviewed export",
    ]
    observation_ids = list(
        dict.fromkeys(
            observation_id
            for value in values
            for observation_id in value.get("observation_ids", [])
        )
    )
    observation_rows = (
        connection.execute(
            select(observations.c.payload)
            .where(
                observations.c.assessment_id == str(assessment_id),
                observations.c.id.in_(observation_ids[:1000]),
            )
            .order_by(observations.c.id)
        )
        .scalars()
        .all()
        if observation_ids
        else []
    )
    selected_observations = [dict(value) for value in observation_rows]
    selected_asset_ids = list(
        dict.fromkeys(str(value["asset_id"]) for value in selected_observations)
    )
    selected_assets = (
        [
            dict(value)
            for value in connection.execute(
                select(assets.c.payload)
                .where(
                    assets.c.assessment_id == str(assessment_id),
                    assets.c.id.in_(selected_asset_ids),
                )
                .order_by(assets.c.id)
            ).scalars()
        ]
        if selected_asset_ids
        else []
    )
    selected_run_ids = list(dict.fromkeys(str(value["run_id"]) for value in values))
    selected_runs = [
        dict(value)
        for value in connection.execute(
            select(tool_runs.c.payload)
            .where(
                tool_runs.c.assessment_id == str(assessment_id),
                tool_runs.c.id.in_(selected_run_ids),
            )
            .order_by(tool_runs.c.id)
        ).scalars()
    ]
    run_tools = {str(value["id"]): str(value["tool"]) for value in selected_runs}
    selected_observations = [
        dict(value) | {"source_tool": run_tools.get(str(value.get("run_id")), "unknown")}
        for value in selected_observations
    ]
    selected_scope_ids = list(dict.fromkeys(str(value["scope_id"]) for value in selected_runs))
    selected_scopes = (
        [
            dict(value)
            for value in connection.execute(
                select(scope_versions.c.payload)
                .where(
                    scope_versions.c.assessment_id == str(assessment_id),
                    scope_versions.c.id.in_(selected_scope_ids),
                )
                .order_by(scope_versions.c.revision)
            ).scalars()
        ]
        if selected_scope_ids
        else []
    )
    context_resources = (
        connection.execute(
            select(resources.c.payload)
            .where(
                resources.c.assessment_id == str(assessment_id),
                resources.c.kind == "asset-contexts",
            )
            .limit(1001)
        )
        .scalars()
        .all()
    )
    selected_contexts: dict[str, dict[str, Any]] = {}
    for item in context_resources[:1000]:
        context = dict(item)
        request_context = context.get("request", {})
        asset_id = str(request_context.get("asset_id", ""))
        prior = selected_contexts.get(asset_id)
        if asset_id in selected_asset_ids and (
            prior is None or context["revision"] > prior["revision"]
        ):
            selected_contexts[asset_id] = context
    from aegistrace.correlation import correlate_observations

    correlations = correlate_observations(
        selected_observations,
        run_tools,
        asset_context={key: value.get("request", {}) for key, value in selected_contexts.items()},
    )
    selected_observation_ids = {str(value["id"]) for value in selected_observations}
    active_reviewed_clusters = coverage.get("observation_analytics", {}).get(
        "reviewed_clusters", []
    )
    correlations["reviewed_clusters"] = [
        group
        for group in active_reviewed_clusters
        if set(group.get("observation_ids", [])) <= selected_observation_ids
    ]
    correlations["reviewed_cluster_count"] = len(correlations["reviewed_clusters"])
    correlations["reviewed_splits"] = [
        group
        for group in coverage.get("observation_analytics", {}).get("reviewed_splits", [])
        if set(group.get("observation_ids", [])) <= selected_observation_ids
    ]
    reviewed_split_members = {
        tuple(sorted(group.get("observation_ids", []))): group
        for group in correlations["reviewed_splits"]
    }
    for candidate in correlations["cross_tool_candidate_groups"]:
        split = reviewed_split_members.get(tuple(sorted(candidate.get("observation_ids", []))))
        if split is not None:
            candidate["review_state"] = "reviewer-split"
            candidate["reviewer_rationale"] = split.get("rationale")
    correlations["review_state"] = coverage.get("observation_analytics", {}).get(
        "review_state", "no-reviewer-overrides"
    )
    omitted_review_groups = [
        group
        for group in [
            *active_reviewed_clusters,
            *coverage.get("observation_analytics", {}).get("reviewed_splits", []),
        ]
        if set(group.get("observation_ids", [])).intersection(selected_observation_ids)
        and not set(group.get("observation_ids", [])) <= selected_observation_ids
    ]
    if omitted_review_groups:
        limitations.append(
            "Some current reviewer correlation clusters reference observations outside the selected frozen revisions and are omitted from this report."
        )
    selected_findings = [
        dict(value)
        for value in connection.execute(
            select(findings.c.payload)
            .where(findings.c.assessment_id == str(assessment_id))
            .order_by(findings.c.id)
            .limit(1000)
        ).scalars()
    ]
    selected_occurrences = [
        dict(value)
        for value in connection.execute(
            select(occurrences.c.payload)
            .where(occurrences.c.assessment_id == str(assessment_id))
            .order_by(occurrences.c.id)
            .limit(1000)
        ).scalars()
    ]
    selected_decisions = [
        dict(value)
        for value in connection.execute(
            select(decisions.c.payload)
            .where(decisions.c.assessment_id == str(assessment_id))
            .order_by(decisions.c.id)
            .limit(1000)
        ).scalars()
    ]
    selected_approvals = [
        dict(value)
        for value in connection.execute(
            select(approvals.c.payload)
            .where(approvals.c.assessment_id == str(assessment_id))
            .order_by(approvals.c.id)
            .limit(1000)
        ).scalars()
    ]
    snapshot_truncated = len(observation_ids) > 1000 or len(context_resources) > 1000
    if snapshot_truncated:
        limitations.append(
            "Frozen content row limit reached; omitted rows make this export incomplete"
        )
    payload = {
        "format": "frozen-result-json-v1",
        "created_at": datetime.now(UTC).isoformat(),
        "assessment_id": str(assessment_id),
        "result_revisions": values,
        "coverage_snapshot": coverage,
        "capabilities": coverage["capabilities"],
        "complete_assessment": False,
        "report_renderer_enabled": True,
        "limitations": limitations,
        "scope_snapshots": selected_scopes,
        "scope": selected_scopes[-1] if selected_scopes else None,
        "assets": selected_assets,
        "tool_runs": selected_runs,
        "observations": selected_observations,
        "findings": selected_findings,
        "occurrences": selected_occurrences,
        "decisions": selected_decisions,
        "approvals": selected_approvals,
        "reviewer_asset_contexts": list(selected_contexts.values()),
        "correlation": correlations,
        "source_snapshot_truncated": snapshot_truncated,
    }
    payload["content"] = build_vapt_content(payload)
    source_digest = content_hash(payload)
    snapshot = ReportSnapshot(
        assessment_id=assessment_id,
        created_at=datetime.now(UTC),
        source_digest=source_digest,
        source_ids=list(
            dict.fromkeys(
                [UUID(v["evidence_id"]) for v in values]
                + [UUID(value) for value in coverage["source_evidence_ids"]]
            )
        ),
        limitations=limitations,
    )
    insert_record(connection, "report_snapshots", snapshot)
    connection.execute(
        exports.insert().values(
            id=str(snapshot.id),
            assessment_id=str(assessment_id),
            sha256=source_digest,
            payload=payload,
        )
    )
    record_request(
        connection,
        assessment_id,
        actor,
        "results.export-frozen",
        snapshot.id,
        {"source_digest": source_digest, "revision_ids": [str(value) for value in ids]},
    )
    return {"id": str(snapshot.id), "sha256": source_digest, "snapshot": payload}


def quarantine_late(
    connection: Connection, config: Settings, job_id: UUID, worker_id: UUID, epoch: int, raw: bytes
) -> str:
    """Trusted collector-only; no public arbitrary output callback exists."""
    job = lock_job(connection, job_id)
    if job["worker_id"] != str(worker_id) or job["epoch"] != epoch:
        raise PolicyError("foreign job output fence")
    if job["state"] == "running" and job["lease_until"] > time.time():
        raise PolicyError("current output must use the normal fenced collection path")
    if not raw or len(raw) > 2097152 or config.evidence_key is None:
        raise PolicyError("bounded encrypted late output required")
    digest = hashlib.sha256(raw).hexdigest()
    existing = connection.execute(
        select(late_outputs.c.id).where(
            late_outputs.c.job_id == str(job_id), late_outputs.c.sha256 == digest
        )
    ).scalar_one_or_none()
    if existing:
        return str(existing)
    total = connection.execute(
        select(func.coalesce(func.sum(late_outputs.c.size), 0)).where(
            late_outputs.c.job_id == str(job_id)
        )
    ).scalar_one()
    if total + len(raw) > 2097152:
        raise PolicyError("late output quota exceeded")
    artifact_id = uuid4()
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(bytes.fromhex(config.evidence_key.get_secret_value())).encrypt(
        nonce, raw, f"aegistrace:late:{job_id}:{artifact_id}".encode()
    )
    connection.execute(
        late_outputs.insert().values(
            id=str(artifact_id),
            job_id=str(job_id),
            sha256=digest,
            size=len(raw),
            nonce=nonce,
            ciphertext=ciphertext,
            key_id=config.evidence_key_id,
            expires_at=time.time() + 3600,
            state="quarantined-late",
            worker_id=str(worker_id),
            epoch=epoch,
        )
    )
    job_event(
        connection,
        job,
        "late-output-quarantined",
        {"artifact_id": str(artifact_id), "sha256": digest, "canonical_state_changed": False},
    )
    append_progress(
        connection,
        job,
        "late-output-quarantined",
        str(job["state"]),
        worker_id=worker_id,
        epoch=epoch,
        diagnostic_code="late-output-quarantined",
    )
    return str(artifact_id)


def review_late(
    connection: Connection,
    config: Settings,
    assessment_id: UUID,
    job_id: UUID,
    artifact_id: UUID,
    decision: str,
    evidence_id: UUID | None,
    actor: Identity,
) -> dict[str, Any]:
    require_access(connection, assessment_id, actor.subject)
    if actor.principal_kind != "human" or actor.role not in {"reviewer", "admin"}:
        raise PolicyError("human reviewer required")
    job = lock_job(connection, job_id)
    if job["assessment_id"] != str(assessment_id):
        raise LookupError("not found")
    artifact = (
        connection.execute(
            select(late_outputs).where(
                late_outputs.c.id == str(artifact_id), late_outputs.c.job_id == str(job_id)
            )
        )
        .mappings()
        .one_or_none()
    )
    if artifact is None:
        raise LookupError("not found")
    if artifact["state"] != "quarantined-late" or artifact["expires_at"] <= time.time():
        raise PolicyError("artifact already reviewed or expired")
    if decision == "include":
        if evidence_id is None:
            raise PolicyError("include requires a retained private canonical evidence reference")
        raw = EvidenceStore(config).read(connection, assessment_id, evidence_id, actor.subject)
        if hashlib.sha256(raw).hexdigest() != artifact["sha256"]:
            raise PolicyError("review evidence hash mismatch")
    elif decision != "reject":
        raise ValueError("invalid review decision")
    state = "reviewed-new-import-required" if decision == "include" else "rejected"
    connection.execute(
        late_outputs.update()
        .where(late_outputs.c.id == str(artifact_id))
        .values(state=state, evidence_id=str(evidence_id) if evidence_id else None)
    )
    value = {
        "artifact_id": str(artifact_id),
        "state": state,
        "old_job_state": job["state"],
        "published_export_changed": False,
    }
    record_request(connection, assessment_id, actor, "job.late-output-reviewed", artifact_id, value)
    append_progress(
        connection,
        job,
        "late-output-reviewed",
        str(job["state"]),
        diagnostic_code="late-output-reviewed",
    )
    return value

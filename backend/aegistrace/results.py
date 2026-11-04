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

from aegistrace.auth import Identity
from aegistrace.domain import ReportSnapshot
from aegistrace.evidence import EvidenceStore
from aegistrace.jobs import job_event, lock_job
from aegistrace.platform_api import record_request
from aegistrace.policy import PolicyError
from aegistrace.repository import insert_record, require_access
from aegistrace.result_schema import exports, late_outputs, revisions
from aegistrace.schema_v1 import tool_runs
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
    limitations = [
        "Immutable source-result export, not a rendered VAPT report",
        "Recorded/imported sources retain original capture times",
        "Later results require a new reviewed export",
    ]
    payload = {
        "format": "frozen-result-json-v1",
        "created_at": datetime.now(UTC).isoformat(),
        "assessment_id": str(assessment_id),
        "result_revisions": values,
        "complete_assessment": False,
        "report_renderer_enabled": False,
        "limitations": limitations,
    }
    source_digest = content_hash(payload)
    snapshot = ReportSnapshot(
        assessment_id=assessment_id,
        created_at=datetime.now(UTC),
        source_digest=source_digest,
        source_ids=[UUID(v["evidence_id"]) for v in values],
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
    return value

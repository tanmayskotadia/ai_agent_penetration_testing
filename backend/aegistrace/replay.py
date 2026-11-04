"""Recorded ingestion only; historical decisions never grant execution authority."""

import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import Connection, Engine, select

from aegistrace.api_schema import resources
from aegistrace.auth import Identity, identity_dependency
from aegistrace.evidence import EvidenceStore
from aegistrace.mutations import mutation
from aegistrace.native_intake import normalize_import
from aegistrace.normalization_schema import normalizations
from aegistrace.platform_api import record_request, resource
from aegistrace.replay_schema import manifests
from aegistrace.repository import get_record, require_access
from aegistrace.settings import Settings


class ReplayCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    import_id: UUID
    provenance: Literal["test-only", "reviewer-declared-capture"] = "test-only"
    capture_reference: str | None = Field(default=None, max_length=300)
    rights_basis: str | None = Field(default=None, max_length=300)
    authorization_reference: str | None = Field(default=None, max_length=300)
    historical_decision_ids: tuple[UUID, ...] = Field(default=(), max_length=50)

    @model_validator(mode="after")
    def declared_source(self) -> "ReplayCreate":
        if self.provenance != "test-only" and not all(
            [self.capture_reference, self.rights_basis, self.authorization_reference]
        ):
            raise ValueError("capture, rights and authorization references required")
        return self


def digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def signed_manifest(
    connection: Connection,
    config: Settings,
    assessment_id: UUID,
    manifest_id: UUID,
    actor: Identity,
) -> dict[str, Any]:
    require_access(connection, assessment_id, actor.subject)
    row = (
        connection.execute(
            select(manifests).where(
                manifests.c.id == str(manifest_id), manifests.c.assessment_id == str(assessment_id)
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise LookupError("manifest not found")
    source_digest = digest(row["payload"])
    signature = hmac.new(
        config.app_secret.get_secret_value().encode(), source_digest.encode(), hashlib.sha256
    ).hexdigest()
    if source_digest != row["sha256"] or not hmac.compare_digest(signature, row["signature"]):
        raise ValueError("manifest integrity/key validation failed")
    return dict(row["payload"]) | {"manifest_sha256": source_digest}


def create_manifest(
    connection: Connection,
    config: Settings,
    assessment_id: UUID,
    body: ReplayCreate,
    actor: Identity,
) -> dict[str, Any]:
    require_access(connection, assessment_id, actor.subject)
    if actor.principal_kind != "human" or actor.role not in {"reviewer", "admin"}:
        raise ValueError("human provenance reviewer required")
    imported = resource(connection, assessment_id, "imports", body.import_id)
    snapshot = connection.execute(
        select(normalizations.c.payload).where(
            normalizations.c.import_id == str(body.import_id),
            normalizations.c.assessment_id == str(assessment_id),
        )
    ).scalar_one_or_none()
    if snapshot is None or snapshot["state"] not in {"normalized", "partial"}:
        raise ValueError("source needs a usable candidate normalization snapshot")
    evidence_id = UUID(snapshot["evidence_id"])
    raw = EvidenceStore(config).read(connection, assessment_id, evidence_id, actor.subject)
    if hashlib.sha256(raw).hexdigest() != snapshot["source_sha256"]:
        raise ValueError("source hash changed")
    for decision_id in body.historical_decision_ids:
        get_record(connection, "decisions", assessment_id, decision_id)
    value = {
        "id": str(uuid4()),
        "assessment_id": str(assessment_id),
        "created_at": datetime.now(UTC).isoformat(),
        "created_by": actor.subject,
        "mode": "recorded-replay",
        "provenance": body.provenance,
        "label": "RECORDED / TEST ONLY"
        if body.provenance == "test-only"
        else "RECORDED / reviewer-declared capture; authenticity unverified",
        "source_import_id": str(body.import_id),
        "import_request": imported["request"],
        "asset_mapping": snapshot.get("asset_mapping", {}),
        "evidence_id": snapshot["evidence_id"],
        "source_sha256": snapshot["source_sha256"],
        "run_id": snapshot["run_id"],
        "tool_version": snapshot["tool_version"],
        "captured_at": snapshot["captured_at"],
        "parser_revision": snapshot["parser_revision"],
        "historical_decision_ids": [str(item) for item in body.historical_decision_ids],
        "historical_decisions_are_current_authority": False,
        "provenance_attestation": body.model_dump(
            mode="json", exclude={"historical_decision_ids", "import_id"}
        ),
        "network_execution_enabled": False,
    }
    source_digest = digest(value)
    signature = hmac.new(
        config.app_secret.get_secret_value().encode(), source_digest.encode(), hashlib.sha256
    ).hexdigest()
    connection.execute(
        manifests.insert().values(
            id=value["id"],
            assessment_id=str(assessment_id),
            sha256=source_digest,
            signature=signature,
            payload=value,
        )
    )
    record_request(
        connection,
        assessment_id,
        actor,
        "replay.manifest-created",
        UUID(value["id"]),
        {"manifest_sha256": source_digest, "provenance": body.provenance},
    )
    return value | {"manifest_sha256": source_digest}


def replay_router(engine: Engine, config: Settings) -> APIRouter:
    router = APIRouter(
        prefix="/api/v1/assessments/{assessment_id}/replays", tags=["recorded-replay"]
    )
    actor_dependency = Depends(identity_dependency(config))

    @router.post("", status_code=201)
    def create(
        assessment_id: UUID,
        body: ReplayCreate,
        request: Request,
        actor: Identity = actor_dependency,
    ) -> JSONResponse:
        return mutation(
            engine,
            request,
            actor,
            body.model_dump(mode="json"),
            lambda connection: create_manifest(connection, config, assessment_id, body, actor),
        )

    @router.get("/{manifest_id}")
    def read(
        assessment_id: UUID, manifest_id: UUID, actor: Identity = actor_dependency
    ) -> dict[str, Any]:
        try:
            with engine.connect() as connection:
                return signed_manifest(connection, config, assessment_id, manifest_id, actor)
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error
        except ValueError as error:
            raise HTTPException(409, "Manifest integrity unavailable") from error

    @router.post("/{manifest_id}/ingest")
    def ingest(
        assessment_id: UUID, manifest_id: UUID, request: Request, actor: Identity = actor_dependency
    ) -> JSONResponse:
        def apply(connection: Connection) -> dict[str, Any]:
            value = signed_manifest(connection, config, assessment_id, manifest_id, actor)
            imported_id = uuid4()
            payload = {
                "schema_version": "1.0",
                "id": str(imported_id),
                "assessment_id": str(assessment_id),
                "kind": "imports",
                "revision": 1,
                "state": "pending-ingestion",
                "reason": None,
                "mode": "recorded-import",
                "request": value["import_request"],
            }
            connection.execute(
                resources.insert().values(
                    id=str(imported_id),
                    assessment_id=str(assessment_id),
                    kind="imports",
                    payload=payload,
                )
            )
            result = normalize_import(
                connection, config, assessment_id, imported_id, value["asset_mapping"], actor
            )
            if (
                result["source_sha256"] != value["source_sha256"]
                or result["parser_revision"] != value["parser_revision"]
            ):
                raise ValueError("source/parser changed; create a newly reviewed manifest")
            result.update(
                replay_manifest_id=str(manifest_id),
                replay_manifest_sha256=value["manifest_sha256"],
                replay_label=value["label"],
                historical_decision_ids=value["historical_decision_ids"],
                historical_decisions_are_current_authority=False,
            )
            record_request(
                connection,
                assessment_id,
                actor,
                "replay.ingested",
                manifest_id,
                {"normalization_id": result["id"], "mode": "recorded-replay"},
            )
            return result

        return mutation(engine, request, actor, {}, apply)

    return router

"""Authenticated quarantine boundary for recorded native containers, not tool adapters."""

from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import Field, StringConstraints
from sqlalchemy import Connection, Engine, select

from aegistrace.api_contracts import ApiContract
from aegistrace.auth import Identity, identity_dependency
from aegistrace.evidence import EvidenceStore
from aegistrace.ingestion_schema import inspections
from aegistrace.mutations import mutation
from aegistrace.native_intake import normalize_import
from aegistrace.platform_api import current_scope, record_request, resource
from aegistrace.repository import get_record, require_access
from aegistrace.safe_parse import canonical, isolated_inspection, mapped_assets
from aegistrace.settings import Settings

AssetString = Annotated[str, StringConstraints(min_length=1, max_length=500)]


class InspectionRequest(ApiContract):
    asset_mapping: dict[AssetString, AssetString] = Field(default_factory=dict, max_length=200)


class InspectionResult(ApiContract):
    import_id: UUID
    evidence_id: UUID
    source_sha256: str
    mode: Literal["recorded-import"] = "recorded-import"
    state: Literal["quarantined", "container-validated"]
    code: str
    assets: list[str]
    out_of_scope_assets: list[str]
    parsed_records: int
    findings_created: Literal[0] = 0
    normalizer_enabled: Literal[False] = False
    diagnostics: list[str]


def ingestion_router(engine: Engine, config: Settings) -> APIRouter:
    router = APIRouter(prefix="/api/v1/assessments/{assessment_id}/imports", tags=["ingestion"])
    actor_dependency = Depends(identity_dependency(config))

    @router.post("/{import_id}/normalize-nmap")
    def normalize(
        assessment_id: UUID,
        import_id: UUID,
        body: InspectionRequest,
        request: Request,
        actor: Identity = actor_dependency,
    ) -> JSONResponse:
        return mutation(
            engine,
            request,
            actor,
            body.model_dump(mode="json"),
            lambda connection: normalize_import(
                connection, config, assessment_id, import_id, body.asset_mapping, actor
            ),
        )

    @router.post("/{import_id}/inspect", response_model=InspectionResult)
    def inspect_import(
        assessment_id: UUID,
        import_id: UUID,
        body: InspectionRequest,
        request: Request,
        actor: Identity = actor_dependency,
    ) -> JSONResponse:
        def apply(connection: Connection) -> dict[str, Any]:
            require_access(connection, assessment_id, actor.subject)
            existing = connection.execute(
                select(inspections.c.result).where(
                    inspections.c.import_id == str(import_id),
                    inspections.c.assessment_id == str(assessment_id),
                )
            ).scalar_one_or_none()
            if existing is not None:
                raise HTTPException(
                    409, "Import already inspected; create a new import request for revised mapping"
                )
            submitted = resource(connection, assessment_id, "imports", import_id)["request"]
            scope = current_scope(
                connection, assessment_id, UUID(submitted["scope_id"]), submitted["scope_revision"]
            )
            evidence_id = UUID(submitted["evidence_id"])
            evidence = get_record(connection, "evidence_references", assessment_id, evidence_id)
            run = get_record(connection, "tool_runs", assessment_id, UUID(evidence["run_id"]))
            if config.evidence_key is None:
                raise HTTPException(503, "Evidence encryption key unavailable")
            raw = EvidenceStore(config).read(connection, assessment_id, evidence_id, actor.subject)
            parsed: dict[str, Any]
            if (
                run["scope_id"] != submitted["scope_id"]
                or run["tool"] != submitted["tool"]
                or run["mode"] != "recorded-import"
            ):
                parsed = {
                    "state": "quarantined",
                    "code": "source-metadata-mismatch",
                    "assets": [],
                    "parsed_records": 0,
                }
            else:
                parsed = isolated_inspection(
                    raw, submitted["tool"], submitted["format"], run["tool_version"]
                )
            _, excluded = mapped_assets(
                parsed["assets"], scope["targets"], scope["exclusions"], body.asset_mapping
            )
            if any(
                canonical(source) != source or source not in parsed["assets"]
                for source in body.asset_mapping
            ):
                raise HTTPException(
                    422, "Mapping keys must match extracted canonical source assets"
                )
            if excluded:
                parsed.update(state="quarantined", code="out-of-scope-assets")
            result = InspectionResult(
                import_id=import_id,
                evidence_id=evidence_id,
                source_sha256=evidence["sha256"],
                state=parsed["state"],
                code=parsed["code"],
                assets=parsed["assets"],
                out_of_scope_assets=excluded,
                parsed_records=parsed["parsed_records"],
                diagnostics=[
                    "Original preserved privately; no normalized findings created",
                    "Container inspection is not authenticity verification or a working native adapter",
                ],
            )
            value = result.model_dump(mode="json")
            connection.execute(
                inspections.insert().values(
                    import_id=str(import_id),
                    assessment_id=str(assessment_id),
                    evidence_id=str(evidence_id),
                    result=value,
                )
            )
            record_request(connection, assessment_id, actor, "import.inspected", import_id, value)
            return value

        return mutation(engine, request, actor, body.model_dump(mode="json"), apply, 200)

    @router.get("/{import_id}/inspection", response_model=InspectionResult)
    def get_inspection(
        assessment_id: UUID, import_id: UUID, actor: Identity = actor_dependency
    ) -> dict[str, Any]:
        try:
            with engine.connect() as connection:
                require_access(connection, assessment_id, actor.subject)
                value = connection.execute(
                    select(inspections.c.result).where(
                        inspections.c.import_id == str(import_id),
                        inspections.c.assessment_id == str(assessment_id),
                    )
                ).scalar_one_or_none()
                if value is None:
                    raise LookupError("not found")
                return dict(value)
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error

    return router

"""Offline OpenAPI definition catalog; never fetches server URLs or sends credentials."""

from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from sqlalchemy import Connection, select

from aegistrace.auth import Identity
from aegistrace.domain import Asset, Endpoint
from aegistrace.evidence import EvidenceStore
from aegistrace.normalization_schema import normalizations
from aegistrace.platform_api import current_scope, record_request, resource
from aegistrace.repository import get_record, insert_record, require_access
from aegistrace.results import record_revision
from aegistrace.safe_parse import canonical, isolated_inspection, mapped_assets
from aegistrace.schema_v1 import assessments, assets, endpoints
from aegistrace.settings import Settings


def normalize_openapi_import(
    connection: Connection,
    config: Settings,
    assessment_id: UUID,
    import_id: UUID,
    mapping: dict[str, str],
    actor: Identity,
) -> dict[str, Any]:
    require_access(connection, assessment_id, actor.subject)
    connection.execute(
        assessments.update()
        .where(assessments.c.id == str(assessment_id))
        .values(owner_id=assessments.c.owner_id)
    )
    if connection.execute(
        select(normalizations.c.id).where(normalizations.c.import_id == str(import_id))
    ).first():
        raise ValueError("import already normalized; create a new import for a new snapshot")
    submitted = resource(connection, assessment_id, "imports", import_id)["request"]
    scope = current_scope(
        connection, assessment_id, UUID(submitted["scope_id"]), submitted["scope_revision"]
    )
    evidence_id = UUID(submitted["evidence_id"])
    evidence = get_record(connection, "evidence_references", assessment_id, evidence_id)
    run = get_record(connection, "tool_runs", assessment_id, UUID(evidence["run_id"]))
    if (
        submitted["tool"] != "OpenAPI"
        or submitted["format"] != "openapi-json"
        or run["tool"] != "OpenAPI"
        or run["mode"] != "recorded-import"
        or run["scope_id"] != submitted["scope_id"]
    ):
        raise ValueError("source metadata mismatch or unsupported API definition import")
    raw = EvidenceStore(config).read(connection, assessment_id, evidence_id, actor.subject)
    parsed = isolated_inspection(raw, "OpenAPI", "openapi-json-normalize-v1", run["tool_version"])
    if any(canonical(source) != source or source not in parsed["assets"] for source in mapping):
        raise ValueError("mapping keys must be canonical extracted API URLs")
    if any(urlsplit(source).query or urlsplit(target).query for source, target in mapping.items()):
        raise ValueError("query-bearing URLs cannot be stored in aliases")
    _, excluded = mapped_assets(parsed["assets"], scope["targets"], scope["exclusions"], mapping)
    if excluded:
        parsed.update(state="quarantined", code="out-of-scope-assets", operations=[])
    asset_ids: list[str] = []
    endpoint_ids: list[str] = []
    operations = []
    if parsed["state"] == "normalized":
        for operation in parsed["operations"]:
            mapped = canonical(mapping.get(operation["url"], operation["url"]))
            parts = urlsplit(mapped)
            identifier = f"{parts.scheme}://{parts.netloc}"
            asset_row = connection.execute(
                select(assets.c.id).where(
                    assets.c.assessment_id == str(assessment_id), assets.c.identifier == identifier
                )
            ).scalar_one_or_none()
            asset_id = UUID(asset_row) if asset_row else uuid4()
            if asset_row is None:
                insert_record(
                    connection,
                    "assets",
                    Asset(
                        id=asset_id,
                        assessment_id=assessment_id,
                        identifier=identifier,
                        kind="application",
                    ),
                )
            asset_ids.append(str(asset_id))
            path = parts.path or "/"
            endpoint_row = connection.execute(
                select(endpoints.c.id).where(
                    endpoints.c.assessment_id == str(assessment_id),
                    endpoints.c.asset_id == str(asset_id),
                    endpoints.c.path == path,
                    endpoints.c.method == operation["method"],
                )
            ).scalar_one_or_none()
            endpoint_id = UUID(endpoint_row) if endpoint_row else uuid4()
            if endpoint_row is None:
                insert_record(
                    connection,
                    "endpoints",
                    Endpoint(
                        id=endpoint_id,
                        assessment_id=assessment_id,
                        asset_id=asset_id,
                        path=path,
                        method=operation["method"],
                    ),
                )
            endpoint_ids.append(str(endpoint_id))
            operations.append(
                {
                    "endpoint_id": str(endpoint_id),
                    "method": operation["method"],
                    "path": path,
                    "url": mapped,
                    "authentication_required": operation["authentication_required"],
                    "security_schemes": operation["security_schemes"],
                    "security_alternatives": operation["security_alternatives"],
                    "source_pointer": operation["pointer"],
                }
            )
    value = {
        "id": str(uuid4()),
        "assessment_id": str(assessment_id),
        "import_id": str(import_id),
        "run_id": run["id"],
        "evidence_id": str(evidence_id),
        "source_sha256": evidence["sha256"],
        "parser_revision": "openapi-v1",
        "mode": "recorded-import",
        "source_kind": "api-definition",
        "authenticity": "not-verified",
        "native_live_execution": False,
        "tool_version": run["tool_version"],
        "captured_at": run["captured_at"],
        "asset_ids": sorted(set(asset_ids)),
        "endpoint_ids": sorted(set(endpoint_ids)),
        "operations": operations,
        "security_scheme_names": parsed.get("security_schemes", []),
        "tested_operations": 0,
        "coverage_state": "definition-only-untested",
        "state": parsed["state"],
        "code": parsed["code"],
        "out_of_scope_assets": excluded,
        "findings_created": 0,
        "limitations": [
            "OpenAPI definitions are parsed offline; server URLs and external references are never fetched",
            "Authentication scheme names are catalogued but no credentials are accepted, stored or replayed",
            "A definition establishes intended API surface only; it does not prove endpoint reachability, scan execution or authentication coverage",
            "Specification source and version are user-declared and authenticity is not verified",
        ],
    }
    revision = record_revision(connection, value)
    value.update(result_revision_id=revision["id"], run_revision=revision["revision"])
    connection.execute(
        normalizations.insert().values(
            id=value["id"],
            assessment_id=str(assessment_id),
            import_id=str(import_id),
            evidence_id=str(evidence_id),
            payload=value,
        )
    )
    record_request(
        connection,
        assessment_id,
        actor,
        "import.openapi-catalogued",
        UUID(value["id"]),
        {
            key: value[key]
            for key in ["id", "evidence_id", "source_sha256", "state", "code", "parser_revision"]
        },
    )
    return value

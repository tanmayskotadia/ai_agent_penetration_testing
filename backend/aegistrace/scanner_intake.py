"""Offline-only normalization for Nessus, Greenbone and Burp exports."""

import html
from datetime import datetime
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from sqlalchemy import Connection, select

from aegistrace.auth import Identity
from aegistrace.domain import Asset, Observation, Service
from aegistrace.evidence import EvidenceStore
from aegistrace.log_safety import safe_log_text
from aegistrace.normalization_schema import normalizations
from aegistrace.platform_api import current_scope, record_request, resource
from aegistrace.repository import get_record, insert_record, require_access
from aegistrace.results import record_revision
from aegistrace.safe_parse import canonical, isolated_inspection, mapped_assets
from aegistrace.schema_v1 import assessments, assets, observations, services
from aegistrace.settings import Settings

_IMPORTS = {
    "Nessus": ("nessus-xml", "nessus-normalize-v1", "nessus-v1"),
    "Greenbone": ("greenbone-xml", "greenbone-normalize-v1", "greenbone-v1"),
    "Burp Suite": ("burp-xml", "burp-normalize-v1", "burp-v1"),
}


def normalize_scanner_import(
    connection: Connection,
    config: Settings,
    assessment_id: UUID,
    import_id: UUID,
    mapping: dict[str, str],
    actor: Identity,
    tool: str,
) -> dict[str, Any]:
    if tool not in _IMPORTS:
        raise ValueError("unsupported offline import")
    format_name, parser_format, parser_revision = _IMPORTS[tool]
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
        submitted["tool"] != tool
        or submitted["format"] != format_name
        or run["tool"] != tool
        or run["mode"] != "recorded-import"
        or run["scope_id"] != submitted["scope_id"]
    ):
        raise ValueError("source metadata mismatch or unsupported offline normalizer")
    raw = EvidenceStore(config).read(connection, assessment_id, evidence_id, actor.subject)
    inspected = isolated_inspection(raw, tool, format_name, run["tool_version"])
    parsed = (
        isolated_inspection(raw, tool, parser_format, run["tool_version"])
        if inspected["state"] == "container-validated"
        else inspected
    )
    if parsed.get("state") not in {"normalized", "partial"}:
        parsed = {
            "state": "quarantined",
            "code": parsed.get("code", "malformed-or-unsupported"),
            "assets": [],
            "observations": [],
            "parsed_records": 0,
        }
    if any(canonical(source) != source or source not in parsed["assets"] for source in mapping):
        raise ValueError("mapping keys must be canonical extracted source assets")
    _, excluded = mapped_assets(parsed["assets"], scope["targets"], scope["exclusions"], mapping)
    if excluded:
        parsed.update(state="quarantined", code="out-of-scope-assets", observations=[])

    secret_values = (
        config.app_secret.get_secret_value(),
        config.evidence_key.get_secret_value() if config.evidence_key else "",
    )
    asset_ids: list[str] = []
    service_ids: list[str] = []
    observation_ids: list[str] = []
    safe_observations = []
    captured_at = datetime.fromisoformat(run["captured_at"])
    if parsed["state"] == "normalized":
        for source_item in parsed["observations"]:
            source_asset = source_item["asset"]
            mapped = canonical(mapping.get(source_asset, source_asset))
            parts = urlsplit(mapped)
            is_url = parts.scheme in {"http", "https"}
            identifier = f"{parts.scheme}://{parts.netloc}" if is_url else mapped
            asset_kind: Literal["host", "url"] = "url" if is_url else "host"
            asset_row = connection.execute(
                select(assets.c.id).where(
                    assets.c.assessment_id == str(assessment_id),
                    assets.c.identifier == identifier,
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
                        kind=asset_kind,
                    ),
                )
            asset_ids.append(str(asset_id))
            source_service = source_item.get("service")
            safe_service = (
                html.escape(safe_log_text(str(source_service), secret_values))[:200]
                if source_service
                else None
            )
            source_severity = source_item.get("source_severity")
            safe_severity = (
                html.escape(safe_log_text(str(source_severity), secret_values))[:100]
                if source_severity
                else None
            )
            port, protocol = source_item.get("port"), source_item.get("protocol")
            service_id = None
            if isinstance(port, int) and protocol in {"tcp", "udp"}:
                service_row = connection.execute(
                    select(services.c.id).where(
                        services.c.assessment_id == str(assessment_id),
                        services.c.asset_id == str(asset_id),
                        services.c.payload["port"].as_integer() == port,
                        services.c.payload["protocol"].as_string() == protocol,
                    )
                ).scalar_one_or_none()
                if service_row is None:
                    service = Service(
                        assessment_id=assessment_id,
                        asset_id=asset_id,
                        port=port,
                        protocol=protocol,
                        observed_name=safe_service,
                    )
                    insert_record(connection, "services", service)
                    service_row = str(service.id)
                service_id = str(service_row)
                service_ids.append(service_id)
            source_pointer = source_item["pointer"]
            source_key = f"{evidence_id}:{source_pointer}:{source_item.get('source_key', '')}"
            title = html.escape(safe_log_text(str(source_item.get("title", "")), secret_values))[
                :500
            ]
            observation = Observation(
                assessment_id=assessment_id,
                asset_id=asset_id,
                run_id=UUID(run["id"]),
                evidence_id=evidence_id,
                service_id=UUID(service_id) if service_id is not None else None,
                source_key=source_key,
                title=title or f"{tool} source observation",
                observed_at=captured_at,
                source_severity=safe_severity,
                cvss_score=source_item.get("cvss_score"),
                cvss_vector=source_item.get("cvss_vector"),
                cvss_version=source_item.get("cvss_version"),
                cve=(source_item.get("cves") or [None])[0],
                cwe=source_item.get("cwe"),
                validation_state="suspected",
            )
            observed_row = connection.execute(
                select(observations.c.id).where(
                    observations.c.assessment_id == str(assessment_id),
                    observations.c.run_id == run["id"],
                    observations.c.source_key == source_key,
                )
            ).scalar_one_or_none()
            if observed_row is None:
                insert_record(connection, "observations", observation)
                observed_row = str(observation.id)
            observation_ids.append(str(observed_row))
            safe_observations.append(
                {
                    **source_item,
                    "asset": identifier,
                    "title": title,
                    "service": safe_service,
                    "source_severity": safe_severity,
                    "observation_id": str(observed_row),
                    "asset_id": str(asset_id),
                    "service_id": service_id,
                    "evidence_id": str(evidence_id),
                    "information_kind": "observed-evidence",
                    "validation_state": "suspected",
                }
            )
    value = {
        "id": str(uuid4()),
        "assessment_id": str(assessment_id),
        "import_id": str(import_id),
        "run_id": run["id"],
        "evidence_id": str(evidence_id),
        "source_sha256": evidence["sha256"],
        "parser_revision": parser_revision,
        "asset_mapping": mapping,
        "mode": "recorded-import",
        "information_kind": "observed-evidence",
        "authenticity": "not-verified",
        "native_live_execution": False,
        "tool_version": run["tool_version"],
        "captured_at": run["captured_at"],
        "asset_ids": sorted(set(asset_ids)),
        "service_ids": sorted(set(service_ids)),
        "observation_ids": observation_ids,
        "state": parsed["state"],
        "code": parsed["code"],
        "observations": safe_observations,
        "out_of_scope_assets": excluded,
        "findings_created": 0,
        "limitations": parsed.get("limitations", [])
        + [
            "Original export remains encrypted source evidence; parser does not claim authenticity",
            "No live tool/API invocation, edition check, license check or feed check is performed",
            "Imported severity/CVSS remain source claims; observations require human review",
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
        f"import.{parser_revision}-normalized",
        UUID(value["id"]),
        {
            key: value[key]
            for key in ["id", "evidence_id", "source_sha256", "state", "code", "parser_revision"]
        },
    )
    return value

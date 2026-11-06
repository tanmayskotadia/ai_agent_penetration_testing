"""Recorded OWASP ZAP evidence normalization; never starts or controls a scanner."""

import html
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from sqlalchemy import Connection, select

from aegistrace.auth import Identity
from aegistrace.domain import Asset, Endpoint, Observation
from aegistrace.evidence import EvidenceStore
from aegistrace.log_safety import safe_log_text
from aegistrace.normalization_schema import normalizations
from aegistrace.platform_api import current_scope, record_request, resource
from aegistrace.repository import get_record, insert_record, require_access
from aegistrace.results import record_revision
from aegistrace.safe_parse import canonical, isolated_inspection, mapped_assets
from aegistrace.schema_v1 import assessments, assets, endpoints, observations
from aegistrace.settings import Settings


def normalize_web_import(
    connection: Connection,
    config: Settings,
    assessment_id: UUID,
    import_id: UUID,
    mapping: dict[str, str],
    actor: Identity,
    tool: str,
    format_name: str,
    parser_format: str,
    parser_revision: str,
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
        submitted["tool"] != tool
        or submitted["format"] != format_name
        or run["tool"] != tool
        or run["mode"] not in {"recorded-import", "live"}
        or (run["mode"] == "live" and run["state"] != "completed")
        or run["scope_id"] != submitted["scope_id"]
    ):
        raise ValueError("source metadata mismatch or unsupported candidate normalizer")
    raw = EvidenceStore(config).read(connection, assessment_id, evidence_id, actor.subject)
    parse_timeout = 10.0 if tool == "OWASP ZAP" else 3.0
    parsed = isolated_inspection(
        raw, tool, parser_format, run["tool_version"], timeout=parse_timeout
    )
    if any(canonical(source) != source or source not in parsed["assets"] for source in mapping):
        raise ValueError("mapping keys must be canonical extracted source URLs")
    if any(urlsplit(source).query or urlsplit(target).query for source, target in mapping.items()):
        raise ValueError(
            "query-bearing URLs cannot be stored in aliases; query data remains in encrypted source evidence"
        )
    _, excluded = mapped_assets(parsed["assets"], scope["targets"], scope["exclusions"], mapping)
    if excluded:
        parsed.update(state="quarantined", code="out-of-scope-assets", alerts=[])
    secret_values = (
        config.app_secret.get_secret_value(),
        config.evidence_key.get_secret_value() if config.evidence_key else "",
    )
    asset_ids: list[str] = []
    endpoint_ids: list[str] = []
    observation_ids: list[str] = []
    safe_alerts = []
    if parsed["state"] == "normalized":
        for alert in parsed["alerts"]:
            safe_name = (
                html.escape(safe_log_text(alert["name"], secret_values))[:500]
                or f"Unlabelled {tool} observation"
            )
            safe_risk = html.escape(safe_log_text(alert["risk"], secret_values))[:100]
            safe_alert = {
                **alert,
                "plugin_id": html.escape(safe_log_text(alert["plugin_id"], secret_values))[:100],
                "alert_ref": html.escape(safe_log_text(alert["alert_ref"], secret_values))[:100],
                "confidence_label": html.escape(
                    safe_log_text(alert["confidence_label"], secret_values)
                )[:100],
                "name": safe_name,
                "risk": safe_risk,
            }
            for instance in alert["instances"]:
                source_uri = instance["uri"]
                mapped = canonical(mapping.get(source_uri, source_uri))
                parts = urlsplit(mapped)
                identifier = f"{parts.scheme}://{parts.netloc}"
                endpoint_path = parts.path or "/"
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
                            kind="url",
                        ),
                    )
                asset_ids.append(str(asset_id))
                endpoint_rows = connection.execute(
                    select(endpoints.c.id, endpoints.c.payload).where(
                        endpoints.c.assessment_id == str(assessment_id),
                        endpoints.c.asset_id == str(asset_id),
                    )
                ).mappings()
                endpoint_row = next(
                    (
                        row["id"]
                        for row in endpoint_rows
                        if row["payload"].get("path") == endpoint_path
                        and row["payload"].get("method") == instance["method"]
                    ),
                    None,
                )
                endpoint_id = UUID(endpoint_row) if endpoint_row else uuid4()
                if endpoint_row is None:
                    insert_record(
                        connection,
                        "endpoints",
                        Endpoint(
                            id=endpoint_id,
                            assessment_id=assessment_id,
                            asset_id=asset_id,
                            path=endpoint_path,
                            method=instance["method"],
                        ),
                    )
                endpoint_ids.append(str(endpoint_id))
                source_key = f"{evidence_id}:{alert['pointer']}:{instance['pointer']}"
                observation = Observation(
                    assessment_id=assessment_id,
                    asset_id=asset_id,
                    run_id=UUID(run["id"]),
                    evidence_id=evidence_id,
                    endpoint_id=endpoint_id,
                    parameter_names=instance.get("parameter_names", []),
                    source_key=source_key,
                    title=f"{tool}: {safe_name}",
                    observed_at=datetime.fromisoformat(run["captured_at"]),
                    source_severity=safe_risk or None,
                    cve=alert.get("cve"),
                    cwe=alert.get("cwe"),
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
                observation_ids.append(observed_row)
            safe_alerts.append(
                {
                    **safe_alert,
                    "instances": [
                        {
                            **instance,
                            "uri": f"{urlsplit(canonical(mapping.get(instance['uri'], instance['uri']))).scheme}://{urlsplit(canonical(mapping.get(instance['uri'], instance['uri']))).netloc}{urlsplit(canonical(mapping.get(instance['uri'], instance['uri']))).path or '/'}",
                        }
                        for instance in alert["instances"]
                    ],
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
        "mode": run["mode"],
        "information_kind": "observed-evidence",
        "authenticity": "not-verified",
        "native_live_execution": run["mode"] == "live" and run["state"] == "completed",
        "tool_version": run["tool_version"],
        "captured_at": run["captured_at"],
        "asset_ids": sorted(set(asset_ids)),
        "endpoint_ids": sorted(set(endpoint_ids)),
        "service_ids": [],
        "observation_ids": observation_ids,
        "state": parsed["state"],
        "code": parsed["code"],
        "alerts": safe_alerts if parsed["state"] == "normalized" else [],
        "out_of_scope_assets": excluded,
        "findings_created": 0,
        "limitations": [
            "Normalization itself is offline; run mode records whether the source artifact came from a completed native run or a recorded import",
            "Candidate parser requires genuine version-matched fixtures and an authorized demonstration for acceptance",
            "Source risk and confidence labels are preserved as scanner text; confidence is not a calibrated probability",
            "Imported alert does not prove exploitability or vulnerability confirmation",
            "Request and response bodies, query strings and parameter values remain in encrypted original evidence",
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
        f"import.{tool.lower().replace(' ', '-')}-normalized",
        UUID(value["id"]),
        {
            key: value[key]
            for key in ["id", "evidence_id", "source_sha256", "state", "code", "parser_revision"]
        },
    )
    return value


def normalize_zap_import(
    connection: Connection,
    config: Settings,
    assessment_id: UUID,
    import_id: UUID,
    mapping: dict[str, str],
    actor: Identity,
) -> dict[str, Any]:
    return normalize_web_import(
        connection,
        config,
        assessment_id,
        import_id,
        mapping,
        actor,
        "OWASP ZAP",
        "zap-alerts-json",
        "zap-alerts-normalize-v1",
        "zap-v1",
    )


def normalize_nikto_import(
    connection: Connection,
    config: Settings,
    assessment_id: UUID,
    import_id: UUID,
    mapping: dict[str, str],
    actor: Identity,
) -> dict[str, Any]:
    return normalize_web_import(
        connection,
        config,
        assessment_id,
        import_id,
        mapping,
        actor,
        "Nikto",
        "nikto-json",
        "nikto-json-normalize-v1",
        "nikto-v1",
    )

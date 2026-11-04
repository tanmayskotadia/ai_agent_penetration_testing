"""Candidate normalization of privately imported bytes with canonical source links."""

import html
from datetime import datetime
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Connection, select

from aegistrace.auth import Identity
from aegistrace.domain import Asset, Observation, Service
from aegistrace.evidence import EvidenceStore
from aegistrace.log_safety import safe_log_text
from aegistrace.normalization_schema import normalizations
from aegistrace.platform_api import current_scope, record_request, resource
from aegistrace.repository import get_record, insert_record, require_access
from aegistrace.safe_parse import canonical, isolated_inspection, mapped_assets
from aegistrace.schema_v1 import assessments, assets, observations, services
from aegistrace.settings import Settings


def normalize_import(
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
        submitted["tool"] != "Nmap"
        or submitted["format"] != "nmap-xml"
        or run["tool"] != "Nmap"
        or run["mode"] != "recorded-import"
        or run["scope_id"] != submitted["scope_id"]
    ):
        raise ValueError("source metadata mismatch or unsupported candidate normalizer")
    raw = EvidenceStore(config).read(connection, assessment_id, evidence_id, actor.subject)
    parsed = isolated_inspection(raw, "Nmap", "nmap-normalize-v1", run["tool_version"])
    if any(canonical(source) != source or source not in parsed["assets"] for source in mapping):
        raise ValueError("mapping keys must be canonical extracted source addresses")
    _, excluded = mapped_assets(parsed["assets"], scope["targets"], scope["exclusions"], mapping)
    if excluded:
        parsed.update(state="quarantined", code="out-of-scope-assets", hosts=[])
    sanitized = []
    for host in parsed.get("hosts", []):
        values = dict(host)
        values["ports"] = []
        for port in host["ports"]:
            entry = dict(port)
            entry["service"] = {
                key: html.escape(
                    safe_log_text(
                        str(value),
                        (
                            config.app_secret.get_secret_value(),
                            config.evidence_key.get_secret_value() if config.evidence_key else "",
                        ),
                    )
                )[:200]
                if value is not None
                else None
                for key, value in port["service"].items()
            }
            values["ports"].append(entry)
        sanitized.append(values)
    parsed["hosts"] = sanitized
    asset_ids, service_ids, observation_ids = [], [], []
    if parsed["state"] in {"normalized", "partial"}:
        for host in sanitized:
            for source in host["addresses"]:
                identifier = canonical(mapping.get(source, source))
                existing = connection.execute(
                    select(assets.c.id).where(
                        assets.c.assessment_id == str(assessment_id),
                        assets.c.identifier == identifier,
                    )
                ).scalar_one_or_none()
                asset_id = UUID(existing) if existing else uuid4()
                if existing is None:
                    insert_record(
                        connection,
                        "assets",
                        Asset(
                            id=asset_id,
                            assessment_id=assessment_id,
                            identifier=identifier,
                            kind="host",
                        ),
                    )
                asset_ids.append(str(asset_id))
                for port in host["ports"]:
                    if port["state"] == "open":
                        service_id = connection.execute(
                            select(services.c.id).where(
                                services.c.assessment_id == str(assessment_id),
                                services.c.asset_id == str(asset_id),
                                services.c.payload["port"].as_integer() == port["port"],
                                services.c.payload["protocol"].as_string() == port["protocol"],
                            )
                        ).scalar_one_or_none()
                        if service_id is None:
                            service = Service(
                                assessment_id=assessment_id,
                                asset_id=asset_id,
                                port=port["port"],
                                protocol=port["protocol"],
                                observed_name=port["service"].get("name"),
                            )
                            insert_record(connection, "services", service)
                            service_id = str(service.id)
                        service_ids.append(service_id)
                    observation = Observation(
                        assessment_id=assessment_id,
                        asset_id=asset_id,
                        run_id=UUID(run["id"]),
                        evidence_id=evidence_id,
                        source_key=f"{evidence_id}:{asset_id}:{source}:{port['pointer']}",
                        title=f"Nmap {port['protocol']}/{port['port']}: {port['state']}",
                        observed_at=datetime.fromisoformat(run["captured_at"]),
                        validation_state="unknown",
                    )
                    observed_id = connection.execute(
                        select(observations.c.id).where(
                            observations.c.assessment_id == str(assessment_id),
                            observations.c.run_id == run["id"],
                            observations.c.source_key == observation.source_key,
                        )
                    ).scalar_one_or_none()
                    if observed_id is None:
                        insert_record(connection, "observations", observation)
                        observed_id = str(observation.id)
                    observation_ids.append(observed_id)
    value = {
        "id": str(uuid4()),
        "assessment_id": str(assessment_id),
        "import_id": str(import_id),
        "run_id": run["id"],
        "evidence_id": str(evidence_id),
        "source_sha256": evidence["sha256"],
        "parser_revision": "nmap-v1",
        "asset_mapping": mapping,
        "mode": "recorded-import",
        "information_kind": "observed-evidence",
        "authenticity": "not-verified",
        "native_live_execution": False,
        "tool_version": run["tool_version"],
        "captured_at": run["captured_at"],
        "asset_ids": sorted(set(asset_ids)),
        "service_ids": service_ids,
        "observation_ids": observation_ids,
        "state": parsed["state"],
        "code": parsed["code"],
        "hosts": parsed["hosts"],
        "out_of_scope_assets": excluded,
        "findings_created": 0,
        "limitations": [
            "Candidate parser; genuine fixture/runner verification pending",
            "Open ports and service guesses are not vulnerabilities",
            "Source service confidence is not calibrated probability",
        ],
    }
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
        "import.nmap-normalized",
        UUID(value["id"]),
        {
            key: value[key]
            for key in ["id", "evidence_id", "source_sha256", "state", "code", "parser_revision"]
        },
    )
    return value

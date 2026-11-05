"""Shared evidence-derived coverage for the workspace and frozen report exports."""

import hashlib
import json
import time
from collections import Counter
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import Connection, Table, func, select

from aegistrace.api_check_schema import api_checks, api_secrets
from aegistrace.approval_schema import claims
from aegistrace.capabilities import capability_snapshot
from aegistrace.correlation import correlate_observations
from aegistrace.job_schema import jobs
from aegistrace.normalization_schema import normalizations
from aegistrace.result_schema import exports
from aegistrace.schema_v1 import assessments, assets, endpoints, observations, tool_runs

ROW_LIMIT = 1000


def effective_job_state(row: dict[str, Any], *, native: bool) -> str:
    state = str(row["state"])
    deadline = row.get("lease_until") if native else row.get("payload", {}).get("deadline")
    if state in {"running", "cancel-requested"} and (
        deadline is None or float(deadline) <= time.time()
    ):
        return "unknown"
    return state


def snapshot_digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def _valid_outcome(op: Any, catalog: dict[str, Any], source_ids: list[str]) -> bool:
    if not isinstance(op, dict):
        return False
    endpoint_id = str(op.get("endpoint_id", ""))
    endpoint = catalog.get(endpoint_id)
    if endpoint is None or endpoint_id not in source_ids or op.get("method") != endpoint["method"]:
        return False
    attempted, state, status = op.get("attempted"), op.get("state"), op.get("status_code")
    if type(attempted) is not bool:
        return False
    if state in {"blocked", "excluded", "untested"}:
        return not attempted and status is None
    if state == "succeeded":
        return attempted and type(status) is int and 200 <= status < 300
    if state == "failed":
        return attempted and (
            status is None
            or type(status) is int
            and 100 <= status <= 599
            and not 200 <= status < 300
        )
    return False


def _rows(
    connection: Connection, table: Table, assessment_id: UUID
) -> tuple[list[dict[str, Any]], bool, int]:
    condition = table.c.assessment_id == str(assessment_id)
    total = connection.execute(
        select(func.count()).select_from(table).where(condition)
    ).scalar_one()
    rows = (
        connection.execute(select(table).where(condition).order_by(table.c.id).limit(ROW_LIMIT))
        .mappings()
        .all()
    )
    return [dict(row) for row in rows], total > ROW_LIMIT, int(total)


def operation_coverage(
    check_rows: list[dict[str, Any]],
    endpoint_rows: list[dict[str, Any]],
    sources: list[dict[str, Any]],
) -> dict[str, Any]:
    definitions = {
        row["id"]: row
        for row in sources
        if row.get("source_kind") == "api-definition" and row.get("state") == "normalized"
    }
    ids = {str(value) for row in definitions.values() for value in row.get("endpoint_ids", [])}
    catalog = {str(row["id"]): row for row in endpoint_rows if str(row["id"]) in ids}
    latest: dict[str, dict[str, tuple[tuple[float, str], dict[str, Any]]]] = {
        "live-request": {},
        "disposable-test": {},
    }
    rejected = []
    ever_attempted: dict[str, set[str]] = {mode: set() for mode in latest}
    for check in check_rows:
        result = check.get("result")
        if not result:
            continue
        source = definitions.get(check["payload"].get("source_normalization_id"))
        try:
            valid = (
                check["state"] in {"completed", "cancelled", "unknown"}
                and source is not None
                and result.get("sha256")
                == snapshot_digest({k: v for k, v in result.items() if k != "sha256"})
                and result.get("check_id") == check["id"]
                and result.get("source_normalization_id") == source["id"]
                and result.get("source_evidence_id") == source["evidence_id"]
                and result.get("execution_mode") in latest
            )
            if not valid or source is None:
                rejected.append(check["id"])
                continue
            outcomes = result.get("operations")
            if (
                not isinstance(outcomes, list)
                or len(outcomes) > 200
                or not all(
                    _valid_outcome(op, catalog, source.get("endpoint_ids", [])) for op in outcomes
                )
            ):
                rejected.append(check["id"])
                continue
            mode = result["execution_mode"]
            order = (float(result["completed_at"]), str(check["id"]))
            for op in result.get("operations", []):
                endpoint_id = str(op.get("endpoint_id", ""))
                endpoint = catalog.get(endpoint_id)
                if (
                    endpoint is None
                    or endpoint_id not in source.get("endpoint_ids", [])
                    or op.get("method") != endpoint["method"]
                ):
                    continue
                if (
                    op.get("state")
                    not in {"succeeded", "failed", "blocked", "excluded", "untested"}
                    or type(op.get("attempted")) is not bool
                ):
                    continue
                value = {
                    **{
                        key: op.get(key)
                        for key in ("state", "attempted", "status_code", "authentication", "reason")
                    },
                    "endpoint_id": endpoint_id,
                    "asset_id": endpoint["asset_id"],
                    "method": endpoint["method"],
                    "path": endpoint["path"],
                    "check_id": check["id"],
                    "check_state": check["state"],
                    "source_evidence_id": source["evidence_id"],
                    "source_normalization_id": source["id"],
                    "result_sha256": result["sha256"],
                    "execution_mode": mode,
                }
                prior = latest[mode].get(endpoint_id)
                if op["attempted"]:
                    ever_attempted[mode].add(endpoint_id)
                if prior is None or order > prior[0]:
                    latest[mode][endpoint_id] = (order, value)
        except (KeyError, TypeError, ValueError):
            rejected.append(check["id"])
    output: dict[str, Any] = {
        "denominator": "declared OpenAPI endpoint/method inventory only",
        "identity_verification": "not-established",
        "invalid_or_unverifiable_result_ids": sorted(set(rejected)),
    }
    for mode, values in latest.items():
        operations = []
        for endpoint_id, endpoint in sorted(catalog.items()):
            operations.append(
                values[endpoint_id][1]
                if endpoint_id in values
                else {
                    "endpoint_id": endpoint_id,
                    "asset_id": endpoint["asset_id"],
                    "method": endpoint["method"],
                    "path": endpoint["path"],
                    "state": "untested",
                    "attempted": False,
                    "status_code": None,
                    "authentication": "not-attempted",
                    "check_id": None,
                    "execution_mode": mode,
                }
            )
        counts = Counter(row["state"] for row in operations)
        for row in operations:
            row["ever_attempted"] = row["endpoint_id"] in ever_attempted[mode]
        attempted = sum(bool(row["attempted"]) for row in operations)
        state = (
            "no-endpoint-inventory"
            if not operations
            else "definition-only-untested"
            if not attempted
            else "declared-operations-attempted"
            if attempted == len(operations)
            else "partial-operation-coverage"
        )
        output[mode] = {
            "coverage_state": state,
            "declared_operation_count": len(operations),
            "attempted_count": attempted,
            "ever_attempted_count": len(ever_attempted[mode]),
            "state_counts": {
                name: counts[name]
                for name in ("succeeded", "failed", "blocked", "excluded", "untested")
            },
            "authentication_counts": dict(
                sorted(Counter(str(row["authentication"]) for row in operations).items())
            ),
            "operations": operations,
        }
    return output


def assessment_coverage(connection: Connection, assessment_id: UUID) -> dict[str, Any]:
    """Caller enforces ownership. Truncated snapshots cannot establish full coverage."""
    connection.execute(
        select(assessments.c.id).where(assessments.c.id == str(assessment_id)).with_for_update()
    ).first()
    loaded = {
        table.name: _rows(connection, table, assessment_id)
        for table in (
            tool_runs,
            assets,
            endpoints,
            observations,
            normalizations,
            api_checks,
            jobs,
            claims,
        )
    }
    truncated = sorted(name for name, (_, cut, _) in loaded.items() if cut)
    run_rows = [row["payload"] for row in loaded[tool_runs.name][0]]
    endpoint_rows = [row["payload"] for row in loaded[endpoints.name][0]]
    observation_rows = [row["payload"] for row in loaded[observations.name][0]]
    source_rows = [row["payload"] for row in loaded[normalizations.name][0]]
    check_rows, job_rows = loaded[api_checks.name][0], loaded[jobs.name][0]
    run_tools = {str(row["id"]): str(row["tool"]) for row in run_rows}
    claim_tools = {
        row["id"]: row["payload"].get("action", {}).get("tool") for row in loaded[claims.name][0]
    }
    registry = capability_snapshot()
    operations = operation_coverage(check_rows, endpoint_rows, source_rows)
    secret_rows = (
        connection.execute(
            select(api_secrets.c.id, api_secrets.c.revoked, api_secrets.c.expires_at)
            .where(api_secrets.c.assessment_id == str(assessment_id))
            .order_by(api_secrets.c.id)
            .limit(ROW_LIMIT + 1)
        )
        .mappings()
        .all()
    )
    if len(secret_rows) > ROW_LIMIT:
        truncated.append(api_secrets.name)
    credential_states = {
        row["id"]: "revoked"
        if row["revoked"]
        else "expired"
        if row["expires_at"] <= time.time()
        else "available"
        for row in secret_rows[:ROW_LIMIT]
    }
    credential_health = [
        {
            "check_id": row["id"],
            "credential_id": credential_id,
            "scheme": scheme,
            "state": credential_states.get(credential_id, "unknown"),
        }
        for row in check_rows
        for scheme, credential_id in row["payload"].get("credential_ids", {}).items()
    ]
    tools = []
    for capability in registry:
        name = str(capability["name"])
        sources = [row for row in source_rows if run_tools.get(str(row.get("run_id"))) == name]
        tool_jobs = [row for row in job_rows if claim_tools.get(row["claim_id"]) == name]
        tools.append(
            {
                "name": name,
                "capability": capability,
                "source_run_count": sum(row["tool"] == name for row in run_rows),
                "recorded_import_count": sum(
                    row["tool"] == name and row["mode"] == "recorded-import" for row in run_rows
                ),
                "normalization_states": dict(
                    sorted(Counter(str(row["state"]) for row in sources).items())
                ),
                "job_states": dict(
                    sorted(
                        Counter(effective_job_state(row, native=True) for row in tool_jobs).items()
                    )
                ),
                "source_records": [
                    {
                        key: row.get(key)
                        for key in (
                            "id",
                            "run_id",
                            "evidence_id",
                            "mode",
                            "state",
                            "authenticity",
                            "captured_at",
                            "code",
                        )
                    }
                    for row in sources
                ],
            }
        )
    normalized = {
        run_tools.get(str(row.get("run_id")))
        for row in source_rows
        if row.get("state") == "normalized"
    }
    verified = {str(row["name"]) for row in registry if row["mode"] in {"import-only", "live"}}
    reviewed = {
        run_tools.get(str(row.get("run_id")))
        for row in source_rows
        if row.get("state") == "normalized" and row.get("authenticity") == "reviewer-verified"
    }
    core = {"Nmap", "OWASP ZAP", "Nikto"}
    gaps = []
    if not normalized & {"Nmap", "Nessus", "Greenbone"}:
        gaps.append("No normalized network-scanner source observed in this snapshot")
    if not normalized & {"OWASP ZAP", "Nikto", "Burp Suite"}:
        gaps.append("No normalized web-scanner source observed in this snapshot")
    if not verified:
        gaps.append("No scanner integration has current verified live/import-only status")
    if operations["invalid_or_unverifiable_result_ids"]:
        gaps.append("Unverifiable API result records are excluded; inspect the reported check IDs")
    gaps.append(
        "Authenticated identity and hidden endpoint coverage are not established by HTTP status codes"
    )
    if truncated:
        gaps.append("Snapshot row limit reached; omitted rows prevent complete coverage claims")
    analytics = correlate_observations(observation_rows, run_tools)
    summary = (
        connection.execute(
            select(exports.c.id).where(exports.c.assessment_id == str(assessment_id)).limit(1)
        ).first()
        is not None
    )
    definition_ids = {
        item
        for row in source_rows
        if row.get("source_kind") == "api-definition" and row.get("state") == "normalized"
        for item in row.get("endpoint_ids", [])
    }
    alerts = {
        item
        for row in source_rows
        if row.get("parser_revision") in {"zap-v1", "nikto-v1"} and row.get("state") == "normalized"
        for item in row.get("endpoint_ids", [])
    }
    snapshot: dict[str, Any] = {
        "schema_version": "2.0",
        "assessment_id": str(assessment_id),
        "captured_at": datetime.now(UTC).isoformat(),
        "snapshot_complete": not truncated,
        "row_limit_per_collection": ROW_LIMIT,
        "truncated_collections": truncated,
        "source_run_count": loaded[tool_runs.name][2],
        "source_runs_by_tool": dict(sorted(Counter(str(row["tool"]) for row in run_rows).items())),
        "asset_count": loaded[assets.name][2],
        "endpoint_catalog_count": loaded[endpoints.name][2],
        "openapi_defined_endpoint_count": len(definition_ids),
        "endpoints_with_imported_web_alerts": len(alerts),
        "observed_record_count": loaded[observations.name][2],
        "observation_analytics": analytics,
        "coverage_state": "bounded-snapshot-incomplete"
        if truncated
        else operations["live-request"]["coverage_state"],
        "coverage_limitations": [
            "Imports establish source observations, not every attempted endpoint",
            "HTTP success is not authenticated identity, vulnerability confirmation or full assessment coverage",
            "Live-request and disposable-test outcomes are counted separately; hidden endpoints remain unknown",
            "Capability status comes from registry evidence, not imported files or installed tool names",
        ],
        "capabilities": registry,
        "tool_evidence": tools,
        "operation_coverage": operations,
        "gaps": gaps,
        "source_evidence_ids": sorted(
            {str(row["evidence_id"]) for row in source_rows if row.get("evidence_id")}
        ),
        "native_job_states": dict(
            sorted(Counter(effective_job_state(row, native=True) for row in job_rows).items())
        ),
        "api_credential_states": dict(sorted(Counter(credential_states.values()).items())),
        "api_check_credential_health": credential_health,
        "api_job_states": dict(
            sorted(Counter(effective_job_state(row, native=False) for row in check_rows).items())
        ),
        "api_operation_checks": [
            {
                "check_id": row["id"],
                "state": row["state"],
                "status": effective_job_state(row, native=False),
                "result": None
                if row["id"] in operations["invalid_or_unverifiable_result_ids"]
                else row["result"],
                "result_integrity": "unavailable"
                if row["id"] in operations["invalid_or_unverifiable_result_ids"]
                else "source-linked"
                if row["result"]
                else "no-result",
            }
            for row in check_rows
        ],
        "prototype_gate": {
            "three_verified_network_and_web_imports": {
                "passed": not truncated and core.issubset(verified & reviewed),
                "evidence": sorted(normalized & core),
            },
            "authorized_lab_demonstration": {"passed": False, "evidence": None},
            "authenticated_api_session_coverage": {
                "passed": False,
                "evidence": operations["live-request"]["authentication_counts"],
                "limitation": "Identity verification remains unknown",
            },
            "full_endpoint_attempt_coverage": {
                "passed": False,
                "evidence": operations["live-request"]["attempted_count"],
                "limitation": "Declared inventory does not establish the full hidden surface",
            },
            "cross_tool_deduplication_and_ranking": {
                "passed": False,
                "implementation_available": True,
                "evidence": {
                    "candidate_groups": analytics["candidate_group_count"],
                    "ranking_method": analytics["ranking_method"],
                },
            },
            "downloadable_pdf_report": {
                "passed": False,
                "summary_export_available": summary,
                "evidence": "Frozen evidence summaries only; professional report acceptance remains pending",
            },
            "live_execution_safety": {
                "passed": False,
                "evidence": "Reviewed API worker controls are implemented; full demonstration acceptance is separate",
            },
        },
    }
    snapshot["snapshot_sha256"] = snapshot_digest(snapshot)
    return snapshot

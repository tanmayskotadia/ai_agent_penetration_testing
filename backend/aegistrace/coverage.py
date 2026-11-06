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
from aegistrace.api_schema import resources
from aegistrace.approval_schema import claims
from aegistrace.capabilities import capability_snapshot
from aegistrace.correlation import correlate_observations
from aegistrace.correlation_review import materialize_clusters, materialize_splits
from aegistrace.finding_review_api import _history
from aegistrace.finding_reviews import latest_by_observation
from aegistrace.job_schema import jobs
from aegistrace.normalization_schema import normalizations
from aegistrace.report_content import VaptReportContent
from aegistrace.result_schema import exports
from aegistrace.schema_v1 import (
    assessments,
    assets,
    endpoints,
    observations,
    scope_versions,
    services,
    tool_runs,
)

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
    protected_endpoint_ids = {
        str(operation["endpoint_id"])
        for row in definitions.values()
        for operation in row.get("operations", [])
        if operation.get("authentication_required") is True
        and operation.get("endpoint_id") is not None
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
    authentication_values = {
        str(operation.get("authentication"))
        for values in (latest["live-request"],)
        for _, item in values.values()
        for operation in [item]
    }
    identity_verification = (
        "verified"
        if "identity-verified" in authentication_values
        else "credentials-sent-unverified"
        if "credentials-sent-unverified" in authentication_values
        else "not-established"
    )
    output: dict[str, Any] = {
        "denominator": "declared OpenAPI endpoint/method inventory only",
        "identity_verification": identity_verification,
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
            "protected_session_coverage": {
                "declared_protected_count": len(protected_endpoint_ids),
                "attempted_with_credentials_count": sum(
                    row["endpoint_id"] in protected_endpoint_ids
                    and row["attempted"] is True
                    and row["authentication"] == "credentials-sent-unverified"
                    for row in operations
                ),
                "successful_response_count": sum(
                    row["endpoint_id"] in protected_endpoint_ids
                    and row["attempted"] is True
                    and row["authentication"] == "credentials-sent-unverified"
                    and row["state"] == "succeeded"
                    for row in operations
                ),
                "identity_verification": identity_verification,
            },
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
            services,
            normalizations,
            api_checks,
            jobs,
            claims,
            scope_versions,
        )
    }
    truncated = sorted(name for name, (_, cut, _) in loaded.items() if cut)
    run_rows = [row["payload"] for row in loaded[tool_runs.name][0]]
    endpoint_rows = [row["payload"] for row in loaded[endpoints.name][0]]
    service_rows = [row["payload"] for row in loaded[services.name][0]]
    observation_rows = [row["payload"] for row in loaded[observations.name][0]]
    source_rows = [row["payload"] for row in loaded[normalizations.name][0]]
    check_rows, job_rows = loaded[api_checks.name][0], loaded[jobs.name][0]
    run_tools = {str(row["id"]): str(row["tool"]) for row in run_rows}
    endpoint_context = {
        str(row["id"]): {"path": str(row["path"]), "method": str(row["method"])}
        for row in endpoint_rows
    }
    service_context = {
        str(row["id"]): {
            "port": row["port"],
            "protocol": str(row["protocol"]),
            "observed_name": row.get("observed_name"),
        }
        for row in service_rows
    }
    rendered_observations = [
        dict(value)
        | {
            "source_tool": run_tools.get(str(value.get("run_id")), "unknown"),
            "endpoint": endpoint_context.get(str(value.get("endpoint_id"))),
            "service": service_context.get(str(value.get("service_id"))),
        }
        for value in observation_rows
    ]
    scope_rows = [row["payload"] for row in loaded[scope_versions.name][0]]
    scope_by_id = {str(row["id"]): row for row in scope_rows}
    source_review_rows = (
        connection.execute(
            select(resources.c.payload)
            .where(
                resources.c.assessment_id == str(assessment_id),
                resources.c.kind == "source-reviews",
            )
            .order_by(resources.c.id)
            .limit(ROW_LIMIT + 1)
        )
        .scalars()
        .all()
    )
    if len(source_review_rows) > ROW_LIMIT:
        truncated.append("source-reviews")
    source_by_id = {str(row["id"]): row for row in source_rows}
    latest_source_reviews: dict[str, dict[str, Any]] = {}
    for raw_review in source_review_rows[:ROW_LIMIT]:
        review = dict(raw_review)
        request = review.get("request", {})
        source_id = str(request.get("normalization_id", ""))
        source = source_by_id.get(source_id)
        if (
            source is None
            or request.get("source_sha256") != source.get("source_sha256")
            or request.get("source_run_id") != source.get("run_id")
            or request.get("evidence_id") != source.get("evidence_id")
        ):
            continue
        prior = latest_source_reviews.get(source_id)
        if prior is None or int(review.get("revision", 0)) > int(prior.get("revision", 0)):
            latest_source_reviews[source_id] = review
    for source_id, review in latest_source_reviews.items():
        request = review["request"]
        source_by_id[source_id]["authenticity"] = (
            "reviewer-verified"
            if request.get("decision") == "verify"
            and request.get("provenance") == "genuine-permitted-capture"
            else "test-only-reviewed"
            if request.get("decision") == "verify"
            else "reviewer-rejected"
        )
        source_by_id[source_id]["source_review_id"] = review["id"]
        source_by_id[source_id]["source_review_rationale"] = request.get("rationale")
        source_by_id[source_id]["source_reviewed_by"] = request.get("reviewer")
    context_rows = (
        connection.execute(
            select(resources.c.payload)
            .where(
                resources.c.assessment_id == str(assessment_id),
                resources.c.kind == "asset-contexts",
            )
            .limit(ROW_LIMIT + 1)
        )
        .scalars()
        .all()
    )
    if len(context_rows) > ROW_LIMIT:
        truncated.append(resources.name)
    asset_context: dict[str, dict[str, Any]] = {}
    for context in context_rows[:ROW_LIMIT]:
        payload = dict(context)
        request_context = payload.get("request", {})
        asset_id = str(request_context.get("asset_id", ""))
        prior = asset_context.get(asset_id)
        if asset_id and (
            prior is None or int(payload.get("revision", 0)) > int(prior.get("revision", 0))
        ):
            asset_context[asset_id] = request_context | {"revision": payload.get("revision")}
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
                            "source_sha256",
                            "mode",
                            "state",
                            "authenticity",
                            "source_review_id",
                            "source_review_rationale",
                            "source_reviewed_by",
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
    reviewed_source_tools = {
        run_tools.get(str(row.get("run_id")))
        for row in source_rows
        if row.get("state") == "normalized" and row.get("authenticity") == "reviewer-verified"
    }
    core = {"Nmap", "OWASP ZAP", "Nikto"}
    reviewed_core_imports = core & reviewed_source_tools
    gaps = []
    if not normalized & {"Nmap", "Nessus", "Greenbone"}:
        gaps.append("No normalized network-scanner source observed in this snapshot")
    if not normalized & {"OWASP ZAP", "Nikto", "Burp Suite"}:
        gaps.append("No normalized web-scanner source observed in this snapshot")
    if not reviewed_source_tools:
        gaps.append("No normalized source has an explicit reviewer provenance decision")
    if operations["invalid_or_unverifiable_result_ids"]:
        gaps.append("Unverifiable API result records are excluded; inspect the reported check IDs")
    gaps.append(
        "Authenticated identity and hidden endpoint coverage are not established by HTTP status codes"
    )
    if truncated:
        gaps.append("Snapshot row limit reached; omitted rows prevent complete coverage claims")
    analytics = correlate_observations(
        observation_rows,
        run_tools,
        asset_context=asset_context,
        endpoint_context=endpoint_context,
        service_context=service_context,
        reviewer_decisions=latest_by_observation(_history(connection, assessment_id)),
    )
    review_rows = (
        connection.execute(
            select(resources.c.payload)
            .where(
                resources.c.assessment_id == str(assessment_id),
                resources.c.kind == "correlation-reviews",
            )
            .order_by(resources.c.id)
            .limit(ROW_LIMIT + 1)
        )
        .scalars()
        .all()
    )
    if len(review_rows) > ROW_LIMIT:
        truncated.append("correlation-reviews")
    latest_review = max(
        (dict(value) for value in review_rows[:ROW_LIMIT]),
        key=lambda value: int(value.get("revision", 0)),
        default=None,
    )
    reviewed_clusters = (
        latest_review.get("request", {}).get("reviewed_clusters", []) if latest_review else []
    )
    reviewed_splits = (
        latest_review.get("request", {}).get("reviewed_splits", []) if latest_review else []
    )
    split_members = {
        tuple(sorted(item.get("observation_ids", []))): item for item in reviewed_splits
    }
    for candidate in analytics["cross_tool_candidate_groups"]:
        decision = split_members.get(tuple(sorted(candidate.get("observation_ids", []))))
        if decision is not None:
            candidate["review_state"] = "reviewer-split"
            candidate["reviewer_rationale"] = decision.get("rationale")
    analytics["review_revision"] = int(latest_review["revision"]) if latest_review else 0
    analytics["review_state"] = (
        "reviewer-overrides-active"
        if reviewed_clusters or reviewed_splits
        else "no-reviewer-overrides"
    )
    analytics["reviewed_clusters"] = materialize_clusters(
        reviewed_clusters,
        rendered_observations,
    )
    analytics["reviewed_splits"] = materialize_splits(
        reviewed_splits,
        rendered_observations,
    )
    export_rows = (
        connection.execute(
            select(exports.c.id, exports.c.payload)
            .where(exports.c.assessment_id == str(assessment_id))
            .order_by(exports.c.id)
            .limit(ROW_LIMIT + 1)
        )
        .mappings()
        .all()
    )
    if len(export_rows) > ROW_LIMIT:
        truncated.append(exports.name)
    summary = bool(export_rows)
    report_export_ids: list[str] = []
    for export in export_rows[:ROW_LIMIT]:
        payload = export["payload"]
        if not payload.get("report_renderer_enabled") or payload.get("source_snapshot_truncated"):
            continue
        try:
            VaptReportContent.model_validate(payload.get("content", {}))
        except (TypeError, ValueError):
            continue
        report_export_ids.append(str(export["id"]))
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
    live_run_by_id = {str(run["id"]): run for run in run_rows}
    now = datetime.now(UTC)
    authorized_live_tools: set[str] = set()
    live_demo_sources: list[dict[str, str]] = []
    for source in source_rows:
        run = live_run_by_id.get(str(source.get("run_id")))
        scope = scope_by_id.get(str(run.get("scope_id"))) if run else None
        if run is None or scope is None or source.get("authenticity") != "reviewer-verified":
            continue
        try:
            valid_until = datetime.fromisoformat(str(scope.get("valid_until")))
        except (TypeError, ValueError):
            continue
        if (
            source.get("state") == "normalized"
            and run.get("mode") == "live"
            and run.get("state") == "completed"
            and scope.get("mode") == "live-request"
            and isinstance(scope.get("authorization_reference"), str)
            and bool(scope["authorization_reference"].strip())
            and valid_until > now
        ):
            tool_name = run_tools.get(str(run["id"]))
            if tool_name:
                authorized_live_tools.add(tool_name)
                live_demo_sources.append(
                    {
                        "run_id": str(run["id"]),
                        "source_id": str(source["id"]),
                        "scope_id": str(scope["id"]),
                        "tool": tool_name,
                    }
                )
    authorized_lab_demo = "Nmap" in authorized_live_tools and bool(
        authorized_live_tools & {"OWASP ZAP", "Nikto"}
    )
    live_operations = operations["live-request"]
    full_declared_endpoint_coverage = (
        not truncated
        and live_operations["declared_operation_count"] > 0
        and live_operations["attempted_count"] == live_operations["declared_operation_count"]
        and not operations["invalid_or_unverifiable_result_ids"]
    )
    cross_tool_reviews = [
        item for item in analytics["reviewed_clusters"] if len(item.get("source_tools", [])) >= 2
    ]
    ranked_observations = analytics["contextual_risk_ranking"].get("ranked_observations", [])
    cross_tool_gate = bool(cross_tool_reviews and ranked_observations and not truncated)
    protected_session = live_operations["protected_session_coverage"]
    auth_gate = (
        protected_session["declared_protected_count"] > 0
        and protected_session["attempted_with_credentials_count"]
        == protected_session["declared_protected_count"]
        and protected_session["successful_response_count"]
        == protected_session["declared_protected_count"]
        and not truncated
        and not operations["invalid_or_unverifiable_result_ids"]
    )
    live_rows = [row for row in live_operations["operations"] if row.get("check_id") is not None]
    safety_checks = sorted(
        {str(row["check_id"]) for row in live_rows if row.get("attempted") is True}
        & {
            str(row["check_id"])
            for row in live_rows
            if row.get("attempted") is False and row.get("state") in {"blocked", "excluded"}
        }
    )
    live_safety = bool(safety_checks and not operations["invalid_or_unverifiable_result_ids"])
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
        "source_reviews": [
            {
                "id": review["id"],
                "normalization_id": review["request"]["normalization_id"],
                "revision": review["revision"],
                "decision": review["request"]["decision"],
                "provenance": review["request"]["provenance"],
                "recorded_at": review["request"]["recorded_at"],
                "reviewer": review["request"]["reviewer"],
            }
            for review in latest_source_reviews.values()
        ],
        "prototype_gate": {
            "three_verified_network_and_web_imports": {
                "passed": not truncated and core.issubset(reviewed_source_tools),
                "evidence": sorted(
                    str(row["id"])
                    for row in source_rows
                    if row.get("state") == "normalized"
                    and row.get("authenticity") == "reviewer-verified"
                    and run_tools.get(str(row.get("run_id"))) in core
                ),
                "reviewed_tools": sorted(reviewed_core_imports),
                "limitation": "Reviewer source verification is a human assertion; it does not establish live tool capability or grant scan authority.",
            },
            "authorized_lab_demonstration": {
                "passed": not truncated and authorized_lab_demo,
                "evidence": live_demo_sources,
                "limitation": "Authorization references are participant supplied; retain and independently review the underlying permission evidence.",
            },
            "authenticated_api_session_coverage": {
                "passed": auth_gate,
                "evidence": {
                    "identity_verification": operations["identity_verification"],
                    "authentication_counts": live_operations["authentication_counts"],
                    "protected_session": protected_session,
                    "attempted": live_operations["attempted_count"],
                    "declared": live_operations["declared_operation_count"],
                },
                "limitation": "Credential transmission and HTTP status alone do not verify an authenticated identity.",
            },
            "full_endpoint_attempt_coverage": {
                "passed": full_declared_endpoint_coverage,
                "evidence": {
                    "attempted": live_operations["attempted_count"],
                    "declared": live_operations["declared_operation_count"],
                    "checks": live_operations["ever_attempted_count"],
                },
                "limitation": "Coverage is limited to declared OpenAPI operations; hidden or undocumented endpoints remain unknown.",
            },
            "cross_tool_deduplication_and_ranking": {
                "passed": cross_tool_gate,
                "evidence": {
                    "candidate_groups": analytics["candidate_group_count"],
                    "reviewed_cross_tool_groups": [
                        item["cluster_id"] for item in cross_tool_reviews
                    ],
                    "ranked_observation_count": len(ranked_observations),
                    "ranking_method": analytics["ranking_method"],
                },
            },
            "downloadable_pdf_report": {
                "passed": bool(report_export_ids) and not truncated,
                "summary_export_available": summary,
                "evidence": {"contract_valid_export_ids": report_export_ids},
                "limitation": "A valid frozen report contract does not substitute for visual review against genuine inputs.",
            },
            "live_execution_safety": {
                "passed": live_safety,
                "evidence": {"checks_with_attempt_and_denial": safety_checks},
                "limitation": "Safety evidence requires a valid live check that includes an attempted in-scope operation and a denied operation; it does not prove hidden-surface coverage.",
            },
        },
    }
    snapshot["snapshot_sha256"] = snapshot_digest(snapshot)
    return snapshot

"""Read-only assessment coverage and capability transparency snapshot."""

from collections import Counter
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import Engine, select

from aegistrace.api_check_schema import api_checks
from aegistrace.auth import Identity, identity_dependency
from aegistrace.capabilities import capability_snapshot
from aegistrace.correlation import correlate_observations
from aegistrace.normalization_schema import normalizations
from aegistrace.repository import require_access
from aegistrace.result_schema import exports
from aegistrace.schema_v1 import assets, endpoints, observations, tool_runs
from aegistrace.settings import Settings


def coverage_router(engine: Engine, config: Settings) -> APIRouter:
    router = APIRouter(prefix="/api/v1/assessments/{assessment_id}/coverage", tags=["coverage"])
    actor_dependency = Depends(identity_dependency(config))

    @router.get("")
    def snapshot(assessment_id: UUID, actor: Identity = actor_dependency) -> dict[str, Any]:
        try:
            with engine.connect() as connection:
                require_access(connection, assessment_id, actor.subject)
                run_rows = (
                    connection.execute(
                        select(tool_runs.c.payload).where(
                            tool_runs.c.assessment_id == str(assessment_id)
                        )
                    )
                    .scalars()
                    .all()
                )
                asset_rows = (
                    connection.execute(
                        select(assets.c.payload).where(assets.c.assessment_id == str(assessment_id))
                    )
                    .scalars()
                    .all()
                )
                endpoint_rows = (
                    connection.execute(
                        select(endpoints.c.payload).where(
                            endpoints.c.assessment_id == str(assessment_id)
                        )
                    )
                    .scalars()
                    .all()
                )
                observation_rows = (
                    connection.execute(
                        select(observations.c.payload).where(
                            observations.c.assessment_id == str(assessment_id)
                        )
                    )
                    .scalars()
                    .all()
                )
                normalization_rows = (
                    connection.execute(
                        select(normalizations.c.payload).where(
                            normalizations.c.assessment_id == str(assessment_id)
                        )
                    )
                    .scalars()
                    .all()
                )
                report_export = connection.execute(
                    select(exports.c.id)
                    .where(exports.c.assessment_id == str(assessment_id))
                    .limit(1)
                ).first()
                api_check_rows = (
                    connection.execute(
                        select(api_checks).where(api_checks.c.assessment_id == str(assessment_id))
                    )
                    .mappings()
                    .all()
                )
        except LookupError as error:
            raise HTTPException(404, "Resource not found") from error
        imports_by_tool = Counter(str(row.get("tool", "unknown")) for row in run_rows)
        runs_by_id = {str(row.get("id")): str(row.get("tool", "unknown")) for row in run_rows}
        analytics = correlate_observations(observation_rows, runs_by_id)
        definition_ids = {
            endpoint_id
            for value in normalization_rows
            if value.get("source_kind") == "api-definition"
            for endpoint_id in value.get("endpoint_ids", [])
        }
        alert_endpoint_ids = {
            endpoint_id
            for value in normalization_rows
            if value.get("parser_revision") in {"zap-v1", "nikto-v1"}
            for endpoint_id in value.get("endpoint_ids", [])
        }
        normalized_tools = {
            runs_by_id.get(str(value.get("run_id")), "unknown")
            for value in normalization_rows
            if value.get("state") == "normalized"
        }
        core_tools = {"Nmap", "OWASP ZAP", "Nikto"}
        registry = capability_snapshot()
        three_verified_imports = core_tools.issubset(normalized_tools) and all(
            tool.get("mode") in {"import-only", "live"}
            for tool in registry
            if tool.get("name") in core_tools
        )
        prototype_gate = {
            "three_verified_network_and_web_imports": {
                "passed": three_verified_imports,
                "evidence": sorted(normalized_tools & core_tools),
            },
            "authorized_lab_demonstration": {"passed": False, "evidence": None},
            "authenticated_api_session_coverage": {"passed": False, "evidence": None},
            "full_endpoint_attempt_coverage": {"passed": False, "evidence": None},
            "cross_tool_deduplication_and_ranking": {
                "passed": False,
                "implementation_available": True,
                "evidence": {
                    "candidate_groups": analytics["candidate_group_count"],
                    "ranking_method": analytics["ranking_method"],
                },
                "limitation": "Implementation is available; source data and reviewer acceptance are still required",
            },
            "downloadable_pdf_report": {
                "passed": False,
                "summary_export_available": report_export is not None,
                "evidence": "reviewer-frozen evidence summary is available as a PDF"
                if report_export is not None
                else None,
                "limitation": "Evidence summaries do not satisfy professional VAPT report acceptance; full report generation and review remain pending",
            },
            "live_execution_safety": {
                "passed": True,
                "evidence": "live scanning is disabled; recorded imports perform no target network requests",
            },
        }
        return {
            "assessment_id": str(assessment_id),
            "source_run_count": len(run_rows),
            "source_runs_by_tool": dict(sorted(imports_by_tool.items())),
            "asset_count": len(asset_rows),
            "endpoint_catalog_count": len(endpoint_rows),
            "openapi_defined_endpoint_count": len(definition_ids),
            "endpoints_with_imported_web_alerts": len(alert_endpoint_ids),
            "observed_record_count": len(observation_rows),
            "observation_analytics": analytics,
            "coverage_state": "coverage-not-established",
            "prototype_gate": prototype_gate,
            "coverage_limitations": [
                "Imported alert endpoints do not prove every endpoint was tested",
                "No scanner execution or authenticated-session coverage is enabled",
                "OpenAPI operations represent definition scope, not reachable or exercised endpoints",
            ],
            "capabilities": registry,
            "api_operation_checks": [
                {"check_id": row["id"], "state": row["state"], "result": row["result"]}
                for row in api_check_rows
            ],
        }

    return router

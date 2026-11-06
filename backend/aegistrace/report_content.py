"""Versioned, source-linked VAPT report content, including explicit unknowns."""

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class VaptReportContent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"] = "1.0"
    assessment_id: UUID
    created_at: str
    assessment_complete: bool = False
    executive_summary: str
    scope: dict[str, Any]
    methodology: dict[str, Any]
    assets: list[dict[str, Any]]
    tool_runs: list[dict[str, Any]]
    source_severity_distribution: dict[str, int]
    prioritized_observations: list[dict[str, Any]]
    reviewed_correlations: list[dict[str, Any]]
    reviewed_splits: list[dict[str, Any]]
    reviewed_findings: list[dict[str, Any]]
    occurrence_count: int = Field(ge=0)
    impact_and_remediation: dict[str, Any]
    approvals_and_decisions: dict[str, list[dict[str, Any]]]
    limitations: list[str]
    coverage: dict[str, Any]
    grounded_claims: list[dict[str, Any]] = Field(default_factory=list)


def build_vapt_content(source: dict[str, Any]) -> dict[str, Any]:
    """Assemble required report sections only from frozen, assessment-owned snapshots."""
    observations = source.get("observations", [])
    findings = source.get("findings", [])
    analytics = source.get("correlation", {})
    correlation = analytics.get("cross_tool_candidate_groups", [])
    reviewed_correlations = analytics.get("reviewed_clusters", [])
    reviewed_splits = analytics.get("reviewed_splits", [])
    current_scope = source.get("scope") or {}
    source_tools = sorted(
        {str(value.get("tool", "unknown")) for value in source.get("tool_runs", [])}
    )
    severity: dict[str, int] = {}
    for observation in observations:
        label = str(observation.get("source_severity") or "not-supplied").strip().casefold()
        severity[label] = severity.get(label, 0) + 1
    limitations = list(
        dict.fromkeys(
            [
                "All findings shown without a reviewer record are source observations or candidate correlations, not confirmed vulnerabilities.",
                "This export reflects selected frozen source revisions; it does not establish full target or endpoint coverage.",
                "Participant-supplied authorization references and source metadata are not independently verified.",
                "Source CVSS and severity are reproduced as reported and are not recalculated.",
                "External CVE/CWE advisory freshness, remediation correctness, and business impact have not been independently validated.",
                "No live scan is claimed by a recorded-import workflow.",
                *source.get("limitations", []),
                *source.get("coverage", {}).get("gaps", []),
            ]
        )
    )
    scope_status = "participant-supplied; not independently verified"
    content = VaptReportContent.model_validate(
        {
            "assessment_id": source["assessment_id"],
            "created_at": source["created_at"],
            "assessment_complete": False,
            "executive_summary": (
                f"Frozen reviewer report for {len(source.get('assets', []))} recorded assets, "
                f"{len(observations)} source observations, {len(correlation)} cross-tool candidate groups, "
                f"{len(reviewed_correlations)} reviewer-merged groups, "
                f"and {len(findings)} reviewer-recorded findings. Assessment coverage and authorization "
                "remain unverified; observations are not confirmations."
            ),
            "scope": {
                "scope_id": current_scope.get("id"),
                "revision": current_scope.get("revision"),
                "targets": current_scope.get("targets", []),
                "exclusions": current_scope.get("exclusions", []),
                "authorization_reference": current_scope.get("authorization_reference"),
                "authorization_status": scope_status,
                "valid_until": current_scope.get("valid_until"),
                "mode": current_scope.get("mode", "unknown"),
            },
            "methodology": {
                "tools_with_selected_sources": source_tools,
                "processing": "Recorded source import and deterministic normalization only",
                "live_scanning_claimed": False,
                "correlation": analytics.get("correlation_method", "unavailable"),
                "priority_policy": analytics.get("contextual_risk_ranking", {}).get(
                    "policy", "unavailable"
                ),
                "rules_of_engagement": "Stored scope fields are participant-supplied and are not independent authorization proof.",
            },
            "assets": source.get("assets", []),
            "tool_runs": source.get("tool_runs", []),
            "source_severity_distribution": dict(sorted(severity.items())),
            "prioritized_observations": analytics.get("contextual_risk_ranking", {}).get(
                "ranked_observations", []
            ),
            "reviewed_correlations": reviewed_correlations,
            "reviewed_splits": reviewed_splits,
            "reviewed_findings": findings,
            "occurrence_count": len(source.get("occurrences", [])),
            "impact_and_remediation": {
                "entries": [],
                "status": "not-provided; requires a reviewed source or analyst decision",
                "business_impact": "unknown",
                "remediation": "unknown",
                "references": [],
            },
            "approvals_and_decisions": {
                "approvals": source.get("approvals", []),
                "decisions": source.get("decisions", []),
            },
            "limitations": limitations,
            "coverage": source.get("coverage", {}),
            "grounded_claims": [
                {"proposal_id": proposal["proposal_id"], **claim}
                for proposal in source.get("grounded_proposals", [])
                for claim in proposal.get("claims", [])
            ],
        }
    ).model_dump(mode="json")
    return content

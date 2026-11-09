"""Versioned, source-linked VAPT report content, including explicit unknowns."""

from typing import Any, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator

from aegistrace.standards import (
    CATALOG_REVISION,
    FrozenStandardReference,
    framework_register,
    reviewer_reference,
    source_references,
)


class DetailedReportFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    record_kind: Literal["reviewer-finding", "source-observation"]
    information_kind: Literal["reviewer-decision", "observed-evidence"]
    title: str
    description: str
    validation_state: str
    source_records: list[dict[str, Any]]
    asset_ids: list[str]
    evidence_ids: list[str]
    observation_ids: list[str]
    occurrence_count: int = Field(ge=0)
    technical_impact: str
    technical_impact_basis: str
    business_impact: str
    business_impact_basis: str
    remediation: str
    remediation_basis: str
    remediation_owner: str
    verification_steps: list[str]
    references: list[str]
    standard_references: list[FrozenStandardReference]
    content_provenance: dict[str, Any]


def detailed_records(source: dict[str, Any]) -> list[dict[str, Any]]:
    observations = {
        str(value.get("id", f"unknown-{index}")): value
        for index, value in enumerate(source.get("observations", []))
    }
    reviews = {value["observation_id"]: value for value in source.get("finding_reviews", [])}
    claimed: set[str] = set()
    result: list[dict[str, Any]] = []
    entries = []
    for note in source.get("report_findings", []):
        request = note["request"]
        member_set = set(request["observation_ids"])
        if not member_set <= observations.keys() or claimed.intersection(member_set):
            raise ValueError("Report finding has missing or overlapping source observations")
        claimed.update(member_set)
        entries.append((str(request["finding_id"]), request, sorted(member_set), note))
    entries.extend((key, {}, [key], {}) for key in observations if key not in claimed)
    for identifier, note_body, members, note in entries:
        sources = [observations[key] for key in members]
        states = {
            reviews.get(key, {}).get(
                "validation_state", observations[key].get("validation_state", "unknown")
            )
            for key in members
        }
        state = next(iter(states)) if len(states) == 1 else "mixed-review-states"
        result.append(
            DetailedReportFinding(
                id=identifier,
                record_kind="reviewer-finding" if note else "source-observation",
                information_kind="reviewer-decision" if note else "observed-evidence",
                title=str(
                    note_body.get("title") or sources[0].get("title") or "Unknown source title"
                ),
                description=str(
                    note_body.get("description")
                    or "Source-reported observation: " + str(sources[0].get("title", "unknown"))
                ),
                validation_state=str(state),
                source_records=sources,
                asset_ids=sorted(
                    {str(value["asset_id"]) for value in sources if value.get("asset_id")}
                ),
                evidence_ids=sorted(
                    {str(value["evidence_id"]) for value in sources if value.get("evidence_id")}
                ),
                observation_ids=members,
                occurrence_count=len(members),
                technical_impact=note_body.get("technical_impact") or "unknown",
                technical_impact_basis=note_body.get("technical_impact_basis") or "unknown",
                business_impact=note_body.get("business_impact") or "unknown",
                business_impact_basis=note_body.get("business_impact_basis") or "unknown",
                remediation=note_body.get("remediation") or "unknown",
                remediation_basis=note_body.get("remediation_basis") or "unknown",
                remediation_owner=note_body.get("remediation_owner") or "unknown",
                verification_steps=note_body.get("verification_steps", []),
                references=note_body.get("references", []),
                standard_references=(
                    [
                        FrozenStandardReference.model_validate(
                            reviewer_reference(value, set(members))
                        )
                        for value in note_body.get("standard_references", [])
                    ]
                    + [
                        FrozenStandardReference.model_validate(value)
                        for value in source_references(sources)
                    ]
                ),
                content_provenance={
                    "record_id": note.get("id"),
                    "revision": note.get("revision"),
                    "reviewer": note_body.get("recorded_by"),
                    "recorded_at": note_body.get("recorded_at"),
                    "rationale": note_body.get("rationale"),
                    "basis": "reviewer supplied; not independently verified"
                    if note
                    else "source observation; no reviewer narrative",
                }
                | (
                    {"recommendation": note_body["recommendation_trace"]}
                    if note_body.get("recommendation_trace")
                    else {}
                ),
            ).model_dump(mode="json")
        )
    return result


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
    finding_reviews: list[dict[str, Any]]
    occurrence_count: int = Field(ge=0)
    impact_and_remediation: dict[str, Any]
    approvals_and_decisions: dict[str, list[dict[str, Any]]]
    limitations: list[str]
    coverage: dict[str, Any]
    grounded_claims: list[dict[str, Any]] = Field(default_factory=list)
    content_revision: Literal["1.3"] = "1.3"
    standards_catalog_revision: str = CATALOG_REVISION
    standards_register: list[dict[str, Any]] = Field(default_factory=list)
    standard_references: list[FrozenStandardReference] = Field(default_factory=list)
    detailed_findings: list[DetailedReportFinding] = Field(default_factory=list)
    summary_counts: dict[str, int] = Field(default_factory=dict)
    execution_summary: list[dict[str, Any]] = Field(default_factory=list)
    evidence_manifest: list[dict[str, Any]] = Field(default_factory=list)
    scope_snapshots: list[dict[str, Any]] = Field(default_factory=list)

    @model_validator(mode="after")
    def reconciled_counts(self) -> "VaptReportContent":
        if self.summary_counts:
            expected = {
                "detailed_record_count": len(self.detailed_findings),
                "reviewer_finding_count": sum(
                    value.record_kind == "reviewer-finding" for value in self.detailed_findings
                ),
                "source_occurrence_count": sum(
                    value.occurrence_count for value in self.detailed_findings
                ),
                "source_observation_count": sum(self.source_severity_distribution.values()),
                "canonical_occurrence_count": self.occurrence_count,
                "business_impact_supplied_count": sum(
                    value.business_impact != "unknown" for value in self.detailed_findings
                ),
                "technical_impact_supplied_count": sum(
                    value.technical_impact != "unknown" for value in self.detailed_findings
                ),
                "technical_impact_basis_count": sum(
                    value.technical_impact_basis != "unknown" for value in self.detailed_findings
                ),
                "business_impact_basis_count": sum(
                    value.business_impact_basis != "unknown" for value in self.detailed_findings
                ),
                "remediation_supplied_count": sum(
                    value.remediation != "unknown" for value in self.detailed_findings
                ),
                "remediation_basis_count": sum(
                    value.remediation_basis != "unknown" for value in self.detailed_findings
                ),
                "remediation_owner_count": sum(
                    value.remediation_owner != "unknown" for value in self.detailed_findings
                ),
                "verification_step_count": sum(
                    len(value.verification_steps) for value in self.detailed_findings
                ),
            }
            if any(self.summary_counts.get(key) != value for key, value in expected.items()):
                raise ValueError("Report counts do not reconcile to frozen records")
        return self


def executive_summary_text(
    *,
    source: dict[str, Any],
    detailed: list[dict[str, Any]],
    severity: dict[str, int],
    reviewer_findings: list[dict[str, Any]],
) -> str:
    """Compose the executive summary from frozen counts and attributed review content only."""
    observations = source.get("observations", [])
    assets = source.get("assets", [])
    analytics = source.get("correlation", {})
    candidate_count = len(analytics.get("cross_tool_candidate_groups", []))
    merge_count = len(analytics.get("reviewed_clusters", []))
    canonical_count = len(source.get("findings", []))
    if not observations:
        overview = (
            f"No source observations are present in the selected revisions; {canonical_count} canonical records, "
            f"{candidate_count} correlation candidates, and {merge_count} reviewer-merged groups are in the snapshot. "
            "This is not a clean-assessment conclusion."
        )
    else:
        overview = (
            f"The frozen selection contains {len(assets)} linked assets and {len(observations)} source observations; "
            f"{len(reviewer_findings)} reviewer-authored report findings group those observations, "
            f"alongside {canonical_count} canonical records, {candidate_count} correlation candidates, "
            f"and {merge_count} reviewer-merged groups. "
            "Source observations are not confirmations."
        )

    validation_counts: dict[str, int] = {}
    for finding in detailed:
        state = str(finding.get("validation_state", "unknown")).casefold()
        label = (
            state
            if state in {"confirmed", "suspected", "rejected", "contradictory"}
            else "unknown-or-mixed"
        )
        validation_counts[label] = validation_counts.get(label, 0) + 1
    validation = (
        "Reviewer validation states by detailed record: "
        + (
            ", ".join(f"{key} {validation_counts[key]}" for key in sorted(validation_counts))
            if validation_counts
            else "none recorded"
        )
        + "."
    )

    severity_text = (
        "Source-reported severity counts: "
        + ", ".join(f"{key} {severity[key]}" for key in sorted(severity))
        + "."
        if severity
        else "No source severity was supplied."
    )
    ranking = (
        source.get("correlation", {})
        .get("contextual_risk_ranking", {})
        .get("ranked_observations", [])
    )
    priority_entries = []
    for item in ranking[:3]:
        priority = item.get("priority", {})
        index = priority.get("local_priority_index")
        factors = priority.get("factors", {})
        supported_factors = []
        for factor_name in (
            "source_cvss",
            "exposure",
            "exploitability",
            "asset_criticality",
            "source_confidence",
        ):
            factor = factors.get(factor_name, {})
            if factor.get("state") not in {None, "unknown"}:
                detail = f"{factor_name}={factor.get('value')}"
                if factor.get("version"):
                    detail += f" v{factor['version']}"
                if factor.get("reference"):
                    detail += f" (ref: {factor['reference']})"
                if factor.get("method"):
                    detail += f" (method: {factor['method']})"
                supported_factors.append(detail)
        missing = priority.get("missing_context", [])
        rationale = (
            "; ".join(supported_factors) if supported_factors else "no documented ranking factors"
        )
        if missing:
            rationale += "; unknown context: " + ", ".join(str(value) for value in missing)
        priority_entries.append(
            f"{item.get('observation_id', item.get('id', 'unknown observation'))} "
            f"(source severity {item.get('source_severity') or 'unknown'}, "
            f"{priority.get('review_attention', 'standard-review')}, "
            f"local index {index if index is not None else 'unknown'}; rationale: {rationale})"
        )
    priority_text = (
        "Priority review entries: "
        + "; ".join(priority_entries)
        + ". The local index is an uncalibrated triage aid, not a probability or CVSS score."
        if priority_entries
        else "No ranked observation is available; priority is unknown."
    )

    technical_impact_count = sum(
        value.get("technical_impact") != "unknown" for value in reviewer_findings
    )
    impact_count = sum(value.get("business_impact") != "unknown" for value in reviewer_findings)
    recommendation_count = sum(value.get("remediation") != "unknown" for value in reviewer_findings)
    verified_step_count = sum(
        len(value.get("verification_steps", [])) for value in reviewer_findings
    )
    action_text = (
        f"Reviewer impact statements: technical {technical_impact_count}, business {impact_count}; "
        f"reviewer recommendations: {recommendation_count} "
        f"with {verified_step_count} proposed verification steps. These are reviewer-supplied, "
        "not independently validated or executed; missing fields remain unknown."
    )

    exceptional = []
    incomplete_states = {
        "failed",
        "partial",
        "quarantined",
        "blocked",
        "cancelled",
        "timeout",
        "error",
    }
    for value in source.get("result_revisions", []):
        state = str(value.get("state", "unknown")).casefold()
        if state in incomplete_states:
            exceptional.append(f"{value.get('run_id', 'unknown run')} {state}")
    for value in source.get("tool_runs", []):
        state = str(value.get("state", "unknown")).casefold()
        if state in incomplete_states:
            entry = f"{value.get('id', 'unknown run')} {state}"
            if entry not in exceptional:
                exceptional.append(entry)
    processing = (
        "Partial or failed source processing: " + "; ".join(exceptional) + "."
        if exceptional
        else "No partial/failed result state was recorded in the selected records; this does not establish complete coverage."
    )
    boundary = (
        "Only selected frozen revisions are represented. Target coverage, authorization, source authenticity, "
        "and unselected assets/endpoints are not independently verified; no live scan is claimed."
    )
    return " ".join(
        (overview, validation, severity_text, priority_text, action_text, processing, boundary)
    )


def build_vapt_content(source: dict[str, Any]) -> dict[str, Any]:
    """Assemble required report sections only from frozen, assessment-owned snapshots."""
    observations = source.get("observations", [])
    findings = source.get("findings", [])
    detailed = detailed_records(source)
    all_references = [
        reference for finding in detailed for reference in finding["standard_references"]
    ]
    all_references.insert(
        0,
        FrozenStandardReference(
            framework="nist-sp-800-115",
            name="NIST SP 800-115",
            version="2008",
            status="applicable",
            relation="methodology",
            identifier="SP 800-115",
            title="Technical Guide to Information Security Testing and Assessment",
            source_url="https://doi.org/10.6028/NIST.SP.800-115",
            rationale=(
                "Cited as a general testing-methodology reference. This report may contain recorded imports only; "
                "the citation does not assert every NIST procedure or a live test was performed."
            ),
            validation="official publication reference; procedure applicability is limited by recorded scope and methods",
        ).model_dump(mode="json"),
    )
    reviewer_findings = [value for value in detailed if value["record_kind"] == "reviewer-finding"]
    analytics = source.get("correlation", {})
    reviewed_correlations = analytics.get("reviewed_clusters", [])
    reviewed_splits = analytics.get("reviewed_splits", [])
    current_scope = source.get("scope") or {}
    coverage_context = source.get("coverage_snapshot", source.get("coverage", {}))
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
                "Standards references are source-reported or reviewer-mapped; they do not establish compliance, certification, vulnerability confirmation, or adversary activity.",
                "External CVE/CWE advisory freshness, remediation correctness, and business impact have not been independently validated.",
                "No live scan is claimed by a recorded-import workflow.",
                *source.get("limitations", []),
                *coverage_context.get("gaps", []),
            ]
        )
    )
    scope_status = "participant-supplied; not independently verified"
    executive_summary = executive_summary_text(
        source=source,
        detailed=detailed,
        severity=severity,
        reviewer_findings=reviewer_findings,
    )
    content = VaptReportContent.model_validate(
        {
            "assessment_id": source["assessment_id"],
            "created_at": source["created_at"],
            "assessment_complete": False,
            "executive_summary": executive_summary,
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
                "coverage_boundary": "Assessment-level coverage frozen at export; detailed sources are limited to selected revisions",
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
            "finding_reviews": source.get("finding_reviews", []),
            "detailed_findings": detailed,
            "standards_catalog_revision": CATALOG_REVISION,
            "standards_register": framework_register(all_references),
            "standard_references": all_references,
            "summary_counts": {
                "source_observation_count": len(observations),
                "reviewer_finding_count": len(reviewer_findings),
                "detailed_record_count": len(detailed),
                "source_occurrence_count": sum(value["occurrence_count"] for value in detailed),
                "canonical_finding_count": len({value.get("id") for value in findings}),
                "canonical_occurrence_count": len(source.get("occurrences", [])),
                "business_impact_supplied_count": sum(
                    value["business_impact"] != "unknown" for value in detailed
                ),
                "technical_impact_supplied_count": sum(
                    value["technical_impact"] != "unknown" for value in detailed
                ),
                "technical_impact_basis_count": sum(
                    value["technical_impact_basis"] != "unknown" for value in detailed
                ),
                "business_impact_basis_count": sum(
                    value["business_impact_basis"] != "unknown" for value in detailed
                ),
                "remediation_supplied_count": sum(
                    value["remediation"] != "unknown" for value in detailed
                ),
                "remediation_basis_count": sum(
                    value["remediation_basis"] != "unknown" for value in detailed
                ),
                "remediation_owner_count": sum(
                    value["remediation_owner"] != "unknown" for value in detailed
                ),
                "verification_step_count": sum(
                    len(value["verification_steps"]) for value in detailed
                ),
            },
            "execution_summary": [
                {
                    "run_id": value.get("run_id"),
                    "state": value.get("state", "unknown"),
                    "limitations": value.get("warnings", value.get("limitations", [])),
                    "parser_code": value.get("parser_code", "unknown"),
                    "mode": value.get("mode", "unknown"),
                    "captured_at": value.get("captured_at"),
                }
                for value in source.get("result_revisions", [])
            ],
            "evidence_manifest": source.get("evidence_references", []),
            "scope_snapshots": source.get("scope_snapshots", []),
            "occurrence_count": len(source.get("occurrences", [])),
            "impact_and_remediation": {
                "entries": [
                    {
                        key: value[key]
                        for key in (
                            "id",
                            "technical_impact",
                            "technical_impact_basis",
                            "business_impact",
                            "business_impact_basis",
                            "remediation",
                            "remediation_basis",
                            "remediation_owner",
                            "verification_steps",
                            "references",
                            "content_provenance",
                        )
                    }
                    for value in reviewer_findings
                ],
                "status": "reviewer-supplied; unknown fields remain explicit"
                if reviewer_findings
                else "not-provided; requires a reviewed source or analyst decision",
                "business_impact": reviewer_findings[0]["business_impact"]
                if len(reviewer_findings) == 1
                else "see per-finding entries"
                if reviewer_findings
                else "unknown",
                "remediation": reviewer_findings[0]["remediation"]
                if len(reviewer_findings) == 1
                else "see per-finding entries"
                if reviewer_findings
                else "unknown",
                "references": sorted(
                    {reference for value in reviewer_findings for reference in value["references"]}
                ),
                "recommendation_status": "reviewer supplied; not independently validated or executed",
                "recommendations": [
                    {
                        "finding_id": value["id"],
                        "assets": value["asset_ids"],
                        "action": value["remediation"],
                        "basis": value["remediation_basis"],
                        "owner": value["remediation_owner"],
                        "verification_steps": value["verification_steps"],
                        "status": "reviewer supplied; not independently validated or executed"
                        if value["remediation"] != "unknown"
                        else "not provided; requires human review",
                    }
                    for value in reviewer_findings
                ],
            },
            "approvals_and_decisions": {
                "approvals": source.get("approvals", []),
                "decisions": source.get("decisions", []),
                "action_approvals": source.get("action_approvals", []),
                "plans": source.get("plans", []),
            },
            "limitations": limitations,
            "coverage": coverage_context,
            "grounded_claims": [
                {"proposal_id": proposal["proposal_id"], **claim}
                for proposal in source.get("grounded_proposals", [])
                for claim in proposal.get("claims", [])
            ],
        }
    ).model_dump(mode="json")
    return content

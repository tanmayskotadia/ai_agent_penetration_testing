"""Evidence validator for reportable claims; unsupported claims remain unknown."""

from collections.abc import Mapping
from typing import Any


def validate_source_claim(
    claim: Mapping[str, Any],
    *,
    observations: Mapping[str, Mapping[str, Any]],
    evidence_assets: Mapping[str, str],
) -> dict[str, Any]:
    """Allow a factual value only when the cited observation proves the same asset/value.

    This deliberately performs no advisory lookup and no model-based inference. A valid
    identifier shape or a high source score does not authenticate vulnerability truth.
    """
    claim_type = claim.get("type")
    value = claim.get("value")
    evidence_id = claim.get("evidence_id")
    asset_id = claim.get("asset_id")
    reasons: list[str] = []
    observation = observations.get(str(claim.get("observation_id", "")))
    if not isinstance(observation, Mapping):
        reasons.append("cited-observation-not-found")
    if not isinstance(evidence_id, str) or not evidence_id:
        reasons.append("evidence-reference-required")
    if not isinstance(asset_id, str) or not asset_id:
        reasons.append("asset-reference-required")
    if observation is not None:
        if str(observation.get("evidence_id")) != evidence_id:
            reasons.append("evidence-does-not-match-observation")
        if str(observation.get("asset_id")) != asset_id:
            reasons.append("asset-does-not-match-observation")
        if evidence_assets.get(str(evidence_id)) != str(asset_id):
            reasons.append("evidence-is-not-linked-to-asset")

    allowed = {
        "cve": ("cve",),
        "cwe": ("cwe",),
        "cvss_score": ("cvss_score",),
        "source_severity": ("source_severity",),
        "title": ("title",),
    }.get(str(claim_type))
    if allowed is None:
        reasons.append("claim-type-not-supported-by-source-contract")
    elif observation is not None:
        if value is None or not any(observation.get(field) == value for field in allowed):
            reasons.append("claim-value-not-present-in-cited-source")
    if claim_type == "cvss_score" and observation is not None:
        if observation.get("cvss_version") is None:
            reasons.append("cvss-version-unknown")
    if claim.get("requires_external_validation"):
        reasons.append("external-advisory-validation-unavailable")

    return {
        "schema_version": "1.0",
        "claim_type": str(claim_type or "unknown"),
        "value": value if not reasons else None,
        "state": "source-supported" if not reasons else "unknown",
        "information_kind": "observed-evidence" if not reasons else "unknown",
        "evidence_id": evidence_id,
        "observation_id": str(claim.get("observation_id", "")) or None,
        "asset_id": asset_id,
        "reasons": list(dict.fromkeys(reasons)),
        "limitations": [
            "A matching imported value proves only what that source reported, not that the underlying issue is true.",
            "Identifier syntax and source occurrence are not external CVE/CWE/advisory verification.",
        ],
    }

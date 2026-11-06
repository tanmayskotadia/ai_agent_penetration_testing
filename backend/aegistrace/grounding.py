"""Evidence validator for reportable claims; unsupported claims remain unknown."""

import math
import re
from collections.abc import Mapping
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictFloat,
    StrictInt,
    StrictStr,
    model_validator,
)


class SourceClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str = Field(min_length=1, max_length=40)
    value: StrictStr | StrictFloat | StrictInt | None = None
    kind: Literal["fact", "inference", "unknown"] = "fact"
    observation_id: str = Field(min_length=1, max_length=100)
    evidence_id: str = Field(min_length=1, max_length=100)
    asset_id: str = Field(min_length=1, max_length=100)
    requires_external_validation: bool = False

    @model_validator(mode="after")
    def bounded_value(self) -> "SourceClaim":
        if isinstance(self.value, str) and len(self.value) > 2000:
            raise ValueError("claim value exceeds 2000 characters")
        if isinstance(self.value, float) and not math.isfinite(self.value):
            raise ValueError("claim value must be finite")
        return self


def validate_source_claim(
    claim: Mapping[str, Any],
    *,
    observations: Mapping[str, Mapping[str, Any]],
    evidence_assets: Mapping[str, str | set[str]],
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
    if claim.get("kind", "fact") != "fact":
        reasons.append("inference-or-unknown-is-not-a-source-fact")
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
        linked = evidence_assets.get(str(evidence_id))
        if not (asset_id in linked if isinstance(linked, set) else linked == asset_id):
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
        if not observation.get("cvss_vector"):
            reasons.append("cvss-vector-unknown")
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 10:
            reasons.append("invalid-cvss-score")
    if claim_type in {"cve", "cwe"}:
        pattern = r"CVE-\d{4}-\d{4,}" if claim_type == "cve" else r"CWE-\d{1,6}"
        if not isinstance(value, str) or not re.fullmatch(pattern, value):
            reasons.append("invalid-identifier")
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


def ground_claims(
    claims: list[dict[str, Any]], observations: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Resolve claims only against server-owned normalized observations, preserving conflicts."""
    by_id = {str(row.get("id", row.get("observation_id", ""))): row for row in observations}
    links: dict[str, str | set[str]] = {}
    for row in observations:
        evidence = str(row.get("evidence_id", ""))
        assets = links.setdefault(evidence, set())
        if isinstance(assets, set):
            assets.add(str(row.get("asset_id", "")))
    results = []
    for claim in claims:
        result = validate_source_claim(claim, observations=by_id, evidence_assets=links)
        field = str(claim.get("type", ""))
        conflicts = [
            str(row.get("id", row.get("observation_id", "")))
            for row in observations
            if str(row.get("asset_id")) == claim.get("asset_id")
            and row.get("cve") == by_id.get(str(claim.get("observation_id")), {}).get("cve")
            and row.get("cve") is not None
            and field in row
            and row[field] is not None
            and row[field] != claim.get("value")
        ]
        result["conflicting_observation_ids"] = conflicts
        result["external_verification"] = (
            "unavailable; source occurrence is not advisory validation"
        )
        if conflicts:
            result["reasons"].append("conflicting-sources-require-review")
            result["state"] = "unknown"
            result["information_kind"] = "unknown"
            result["value"] = None
        results.append(result)
    return results

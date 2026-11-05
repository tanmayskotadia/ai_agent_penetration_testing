"""Transparent, uncalibrated remediation priority with explicit missing factors."""

from collections.abc import Iterable, Mapping
from typing import Any

POLICY_VERSION = "aegistrace-context-priority-v1"
_WEIGHTS = {
    "source_cvss": 0.40,
    "exposure": 0.20,
    "exploitability": 0.20,
    "asset_criticality": 0.15,
    "source_confidence": 0.05,
}


def _reported_context(value: Any, reference: Any) -> Any:
    if not isinstance(reference, str) or not reference.strip():
        return None
    return value


def rank_observations(
    observations: Iterable[dict[str, Any]],
    *,
    asset_context: Mapping[str, Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Rank by supported context; do not invent scores when contextual inputs are absent.

    Context fields are accepted only when accompanied by an evidence/provenance reference.
    Source CVSS is preserved verbatim and only normalized for the separate local index.
    """
    context_by_asset = asset_context or {}
    ranked: list[dict[str, Any]] = []
    for source in observations:
        item = dict(source)
        context = context_by_asset.get(str(source.get("asset_id", "")), {})
        factors: dict[str, dict[str, Any]] = {}
        weighted = 0.0
        available_weight = 0.0

        cvss = source.get("cvss_score")
        cvss_version = source.get("cvss_version")
        cvss_value = (
            float(cvss) * 10
            if isinstance(cvss, (int, float)) and not isinstance(cvss, bool) and cvss_version
            else None
        )
        factors["source_cvss"] = {
            "value": cvss,
            "version": cvss_version,
            "weight": _WEIGHTS["source_cvss"],
            "state": "source-reported" if cvss_value is not None else "unknown",
        }
        if cvss_value is not None:
            weighted += cvss_value * _WEIGHTS["source_cvss"]
            available_weight += _WEIGHTS["source_cvss"]

        exposure = _reported_context(context.get("exposure"), context.get("exposure_reference"))
        exposure_values = {"internet-facing": 100, "internal": 60, "restricted": 30}
        exposure_score = exposure_values.get(exposure) if isinstance(exposure, str) else None
        factors["exposure"] = {
            "value": exposure if exposure_score is not None else None,
            "reference": context.get("exposure_reference") if exposure_score is not None else None,
            "weight": _WEIGHTS["exposure"],
            "state": "recorded-context" if exposure_score is not None else "unknown",
        }
        if exposure_score is not None:
            weighted += exposure_score * _WEIGHTS["exposure"]
            available_weight += _WEIGHTS["exposure"]

        exploitability = _reported_context(
            context.get("exploitability"), context.get("exploitability_reference")
        )
        exploitability_values = {"confirmed": 100, "suspected": 50}
        exploitability_score = (
            exploitability_values.get(exploitability) if isinstance(exploitability, str) else None
        )
        factors["exploitability"] = {
            "value": exploitability if exploitability_score is not None else None,
            "reference": context.get("exploitability_reference")
            if exploitability_score is not None
            else None,
            "weight": _WEIGHTS["exploitability"],
            "state": "recorded-context" if exploitability_score is not None else "unknown",
        }
        if exploitability_score is not None:
            weighted += exploitability_score * _WEIGHTS["exploitability"]
            available_weight += _WEIGHTS["exploitability"]

        criticality = _reported_context(
            context.get("criticality"), context.get("criticality_reference")
        )
        criticality_score = (
            (float(criticality) - 1) * 25
            if isinstance(criticality, int)
            and not isinstance(criticality, bool)
            and 1 <= criticality <= 5
            else None
        )
        factors["asset_criticality"] = {
            "value": criticality if criticality_score is not None else None,
            "reference": context.get("criticality_reference")
            if criticality_score is not None
            else None,
            "scale": "analyst-recorded 1 (low) to 5 (critical); not inferred",
            "weight": _WEIGHTS["asset_criticality"],
            "state": "recorded-context" if criticality_score is not None else "unknown",
        }
        if criticality_score is not None:
            weighted += criticality_score * _WEIGHTS["asset_criticality"]
            available_weight += _WEIGHTS["asset_criticality"]

        confidence = source.get("confidence")
        confidence_score = (
            float(confidence) * 100
            if isinstance(confidence, (int, float))
            and not isinstance(confidence, bool)
            and source.get("confidence_method")
            else None
        )
        factors["source_confidence"] = {
            "value": confidence if confidence_score is not None else None,
            "method": source.get("confidence_method") if confidence_score is not None else None,
            "weight": _WEIGHTS["source_confidence"],
            "state": "method-disclosed" if confidence_score is not None else "unknown",
        }
        if confidence_score is not None:
            weighted += confidence_score * _WEIGHTS["source_confidence"]
            available_weight += _WEIGHTS["source_confidence"]

        contextual_available = any(
            factors[name]["state"] == "recorded-context"
            for name in ("exposure", "exploitability", "asset_criticality")
        )
        local_score = (
            round(weighted / available_weight, 1)
            if contextual_available and available_weight
            else None
        )
        attention = (
            "high-severity-low-confidence-review"
            if cvss_value is not None
            and cvss_value >= 70
            and confidence_score is not None
            and confidence_score < 50
            else "standard-review"
        )
        item["priority"] = {
            "policy": POLICY_VERSION,
            "local_priority_index": local_score,
            "state": "contextual-index" if local_score is not None else "context-insufficient",
            "factors": factors,
            "review_attention": attention,
            "missing_context": [
                key
                for key in ("exposure", "exploitability", "asset_criticality")
                if factors[key]["state"] == "unknown"
            ],
            "meaning": "A deterministic triage index over available documented inputs; not CVSS, exploitability probability, or calibrated risk.",
        }
        ranked.append(item)

    ranked.sort(
        key=lambda item: (
            0
            if item["priority"]["review_attention"] == "high-severity-low-confidence-review"
            else 1,
            item["priority"]["state"] != "contextual-index",
            -(item["priority"]["local_priority_index"] or 0),
            not isinstance(item.get("cvss_score"), (float, int))
            or isinstance(item.get("cvss_score"), bool),
            -float(item["cvss_score"])
            if isinstance(item.get("cvss_score"), (float, int))
            and not isinstance(item.get("cvss_score"), bool)
            else 0,
            str(item.get("observation_id", item.get("id", ""))),
        )
    )
    return {
        "policy": POLICY_VERSION,
        "ranking_method": "Contextual index when provenance-backed asset context exists; otherwise source-reported CVSS as a secondary ordering signal and local index remains unknown.",
        "ranked_observations": ranked,
        "limitations": [
            "Local priority is deterministic triage, not a probability or CVSS recalculation.",
            "Exposure, exploitability and asset criticality require documented participant/reviewer provenance.",
            "Unknown factors remain unknown; severe low-confidence evidence receives an explicit review flag.",
        ],
    }

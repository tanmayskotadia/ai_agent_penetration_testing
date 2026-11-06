"""Pure validation and materialization for immutable reviewer triage records."""

from collections.abc import Iterable
from typing import Any

VALID_STATES = {"suspected", "confirmed", "false-positive", "contradictory", "unknown"}


def validate_review(review: dict[str, Any], known_ids: set[str]) -> dict[str, Any]:
    """Validate a human decision against this assessment's observation inventory."""
    observation_id = review.get("observation_id")
    state = review.get("validation_state")
    rationale = review.get("rationale")
    contradictions = review.get("contradictory_observation_ids", [])
    if not isinstance(observation_id, str) or observation_id not in known_ids:
        raise ValueError("review observation is not in this assessment")
    if not isinstance(state, str) or state not in VALID_STATES:
        raise ValueError("unsupported reviewer validation state")
    if not isinstance(rationale, str) or not rationale.strip() or len(rationale) > 2000:
        raise ValueError("reviewer rationale is required and must be at most 2000 characters")
    if not isinstance(contradictions, list) or len(contradictions) > 50:
        raise ValueError("contradiction references are invalid")
    if any(not isinstance(item, str) for item in contradictions):
        raise ValueError("contradiction references are invalid")
    if len(set(contradictions)) != len(contradictions) or any(
        not isinstance(item, str) or item not in known_ids or item == observation_id
        for item in contradictions
    ):
        raise ValueError(
            "contradiction references must be distinct, non-self observations in this assessment"
        )
    if (state == "contradictory") != bool(contradictions):
        raise ValueError(
            "contradictory state requires cited observations, and other states forbid them"
        )
    return {
        "observation_id": observation_id,
        "validation_state": state,
        "rationale": rationale.strip(),
        "contradictory_observation_ids": sorted(contradictions),
        "information_kind": "reviewer-decision",
        "confidence": None,
        "confidence_state": "unknown",
        "confidence_method": None,
        "calibration_status": "not-calibrated",
    }


def latest_by_observation(reviews: Iterable[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Return the last explicit human decision per observation, preserving history elsewhere."""
    latest: dict[str, dict[str, Any]] = {}
    for item in reviews:
        request = item.get("request", {})
        observation_id = request.get("observation_id")
        if isinstance(observation_id, str):
            latest[observation_id] = {
                key: request[key]
                for key in (
                    "observation_id",
                    "validation_state",
                    "rationale",
                    "contradictory_observation_ids",
                    "recorded_by",
                    "recorded_at",
                    "information_kind",
                    "confidence",
                    "confidence_state",
                    "confidence_method",
                    "calibration_status",
                )
                if key in request
            }
    return latest


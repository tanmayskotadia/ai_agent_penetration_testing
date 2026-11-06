"""Synthetic ranking inputs exercise policy behavior, not scanner accuracy."""

from copy import deepcopy
from math import nan

import pytest
from aegistrace.correlation import correlate_observations
from aegistrace.risk_ranking import rank_observations


def priority(source, context=None, reviews=None):
    return rank_observations(
        [source], asset_context={"asset": context or {}}, reviewer_decisions=reviews
    )["ranked_observations"][0]["priority"]


def test_reproducible_index_monotonic_context_and_preserved_source():
    source = {"id": "obs", "asset_id": "asset", "cvss_score": 8.0, "cvss_version": "3.1"}
    before = deepcopy(source)
    scores = []
    for exposure in ("restricted", "internal", "internet-facing"):
        result = priority(
            source, {"exposure": exposure, "exposure_reference": "synthetic inventory"}
        )
        assert result["local_priority_index"] == round(
            result["weighted_sum"] / result["available_weight"], 1
        )
        assert result == priority(
            source, {"exposure": exposure, "exposure_reference": "synthetic inventory"}
        )
        scores.append(result["local_priority_index"])
    assert scores == sorted(scores) and len(set(scores)) == 3
    assert source == before


@pytest.mark.parametrize("value", [nan, float("inf"), -1, 11, True, "8"])
def test_invalid_cvss_is_unknown_and_does_not_poison_ordering(value):
    result = priority({"id": "obs", "cvss_score": value, "cvss_version": "3.1"})
    assert result["factors"]["source_cvss"]["state"] == "unknown"
    assert result["local_priority_index"] is None


@pytest.mark.parametrize("value", [nan, float("inf"), -1, 2, True])
def test_invalid_confidence_never_becomes_a_score(value):
    assert (
        priority({"confidence": value, "confidence_method": "test-only"})["factors"][
            "source_confidence"
        ]["state"]
        == "unknown"
    )


def test_unknown_context_and_disputed_exploitability_remain_explicit():
    source = {"id": "obs", "asset_id": "asset", "cvss_score": 9, "cvss_version": "3.1"}
    assert priority(source, {"exposure": "internet-facing"})["local_priority_index"] is None
    review = {
        "obs": {
            "validation_state": "contradictory",
            "contradictory_observation_ids": ["other"],
            "rationale": "test disagreement",
        }
    }
    result = priority(
        source,
        {"exploitability": "confirmed", "exploitability_reference": "test-only assertion"},
        review,
    )
    assert result["local_priority_index"] is None
    assert result["review_attention"] == "contradictory-evidence-review"
    assert result["reviewer_decision"] == review["obs"]
    assert "exploitability" in result["missing_context"]


def test_correlation_preserves_cvss_vector_and_passes_reviewer_disagreement():
    source = {
        "id": "obs",
        "asset_id": "asset",
        "cvss_score": 8,
        "cvss_version": "3.1",
        "cvss_vector": "source vector",
    }
    result = correlate_observations(
        [source], {}, reviewer_decisions={"obs": {"validation_state": "contradictory"}}
    )
    ranked = result["contextual_risk_ranking"]["ranked_observations"][0]
    assert ranked["source_cvss_vector"] == "source vector"
    assert ranked["priority"]["review_attention"] == "contradictory-evidence-review"

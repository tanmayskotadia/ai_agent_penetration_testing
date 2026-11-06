import pytest
from aegistrace.grounding import SourceClaim, ground_claims, validate_source_claim


def test_source_claim_requires_matching_observation_evidence_and_asset():
    observation = {
        "id": "observation-1",
        "evidence_id": "evidence-1",
        "asset_id": "asset-1",
        "cve": "CVE-2024-1234",
        "cvss_score": 7.5,
        "cvss_version": "3.1",
    }
    evidence_assets = {"evidence-1": "asset-1"}
    valid = validate_source_claim(
        {
            "type": "cve",
            "value": "CVE-2024-1234",
            "evidence_id": "evidence-1",
            "observation_id": "observation-1",
            "asset_id": "asset-1",
        },
        observations={"observation-1": observation},
        evidence_assets=evidence_assets,
    )
    wrong_asset = validate_source_claim(
        {
            "type": "cve",
            "value": "CVE-2024-1234",
            "evidence_id": "evidence-1",
            "observation_id": "observation-1",
            "asset_id": "asset-2",
        },
        observations={"observation-1": observation},
        evidence_assets=evidence_assets,
    )
    fabricated = validate_source_claim(
        {
            "type": "cve",
            "value": "CVE-2099-9999",
            "evidence_id": "evidence-1",
            "observation_id": "observation-1",
            "asset_id": "asset-1",
        },
        observations={"observation-1": observation},
        evidence_assets=evidence_assets,
    )

    assert valid["state"] == "source-supported"
    assert (
        wrong_asset["state"] == "unknown"
        and "asset-does-not-match-observation" in wrong_asset["reasons"]
    )
    assert fabricated["state"] == "unknown" and fabricated["value"] is None


def test_missing_cvss_version_and_external_advisory_stay_unknown():
    observation = {"evidence_id": "e1", "asset_id": "a1", "cvss_score": 9.8}
    result = validate_source_claim(
        {
            "type": "cvss_score",
            "value": 9.8,
            "evidence_id": "e1",
            "observation_id": "o1",
            "asset_id": "a1",
            "requires_external_validation": True,
        },
        observations={"o1": observation},
        evidence_assets={"e1": "a1"},
    )

    assert result["state"] == "unknown"
    assert "cvss-version-unknown" in result["reasons"]
    assert "external-advisory-validation-unavailable" in result["reasons"]


def test_conflicts_missing_vectors_and_inferences_remain_unknown():
    sources = [
        {
            "id": "o1",
            "evidence_id": "e1",
            "asset_id": "a1",
            "cve": "CVE-2024-1234",
            "cvss_score": 7.5,
            "cvss_version": "3.1",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        },
        {
            "id": "o2",
            "evidence_id": "e2",
            "asset_id": "a1",
            "cve": "CVE-2024-1234",
            "cvss_score": 9.8,
            "cvss_version": "3.1",
        },
    ]
    citation = {"observation_id": "o1", "evidence_id": "e1", "asset_id": "a1"}
    conflict = ground_claims([citation | {"type": "cvss_score", "value": 7.5}], sources)[0]
    assert conflict["state"] == "unknown" and conflict["conflicting_observation_ids"] == ["o2"]
    assert conflict["value"] is None
    inferred = ground_claims(
        [citation | {"type": "cve", "value": "CVE-2024-1234", "kind": "inference"}], sources
    )[0]
    assert inferred["value"] is None and "inference-or-unknown" in str(inferred["reasons"])
    # An identifier copied from a source does not establish freshness/existence in an advisory.
    stale_advisory = ground_claims(
        [
            citation
            | {"type": "cve", "value": "CVE-2024-1234", "requires_external_validation": True}
        ],
        sources,
    )[0]
    assert stale_advisory["state"] == "unknown"
    assert "external-advisory-validation-unavailable" in stale_advisory["reasons"]
    missing_vector = ground_claims(
        [
            {
                "observation_id": "o2",
                "evidence_id": "e2",
                "asset_id": "a1",
                "type": "cvss_score",
                "value": 9.8,
            }
        ],
        [sources[1]],
    )[0]
    assert "cvss-vector-unknown" in missing_vector["reasons"]
    assert sources[0]["cvss_score"] == 7.5 and sources[1]["cvss_score"] == 9.8


def test_claim_values_are_bounded_and_not_coerced_from_boolean_or_nonfinite():
    for value in (True, float("nan"), float("inf"), "x" * 2001):
        with pytest.raises(ValueError):
            SourceClaim(
                type="cvss_score", value=value, observation_id="o", evidence_id="e", asset_id="a"
            )

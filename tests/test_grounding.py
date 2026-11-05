from aegistrace.grounding import validate_source_claim


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

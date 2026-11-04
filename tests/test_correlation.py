"""Review-only correlation preserves source occurrences and provenance."""

from aegistrace.correlation import correlate_observations


def test_cve_candidate_group_preserves_occurrences_and_source_cvss_order():
    observations = [
        {
            "id": "obs-zap",
            "run_id": "run-zap",
            "evidence_id": "ev-zap",
            "asset_id": "asset-a",
            "source_key": "alert-1",
            "title": "Example flaw",
            "cve": "cve-2024-1234",
            "cvss_score": 8.2,
            "cvss_version": "3.1",
        },
        {
            "id": "obs-nikto",
            "run_id": "run-nikto",
            "evidence_id": "ev-nikto",
            "asset_id": "asset-b",
            "source_key": "test-2",
            "title": "Different vendor wording",
            "cve": "CVE-2024-1234",
            "cvss_score": 6.1,
            "cvss_version": "3.0",
        },
        {
            "id": "obs-unscored",
            "run_id": "run-zap",
            "evidence_id": "ev-zap",
            "asset_id": "asset-a",
            "source_key": "alert-3",
            "title": "Unscored observation",
        },
    ]

    result = correlate_observations(observations, {"run-zap": "OWASP ZAP", "run-nikto": "Nikto"})

    assert result["candidate_group_count"] == 1
    group = result["cross_tool_candidate_groups"][0]
    assert group["match_basis"] == "CVE"
    assert group["source_tools"] == ["Nikto", "OWASP ZAP"]
    assert group["asset_ids"] == ["asset-a", "asset-b"]
    assert {item["observation_id"] for item in group["observations"]} == {"obs-zap", "obs-nikto"}
    assert group["source_cvss_range"] == [6.1, 8.2]
    assert [item["observation_id"] for item in result["ranked_observations"]] == [
        "obs-zap",
        "obs-nikto",
        "obs-unscored",
    ]


def test_fallback_requires_cwe_and_normalized_title_and_two_tools():
    base = {
        "evidence_id": "ev",
        "asset_id": "asset",
        "title": "  Missing   Access-Control! ",
        "cwe": "cwe-284",
    }
    observations = [
        {**base, "id": "first", "run_id": "one"},
        {**base, "id": "second", "run_id": "two", "title": "Missing access control"},
        {**base, "id": "third", "run_id": "one", "cwe": None},
    ]

    result = correlate_observations(observations, {"one": "Nmap", "two": "OWASP ZAP"})

    assert result["candidate_group_count"] == 1
    assert result["cross_tool_candidate_groups"][0]["match_basis"] == "CWE and normalized title"
    assert len(result["cross_tool_candidate_groups"][0]["observations"]) == 2


def test_same_tool_matches_are_not_labeled_cross_tool():
    pair = [
        {"id": "a", "run_id": "one", "cve": "CVE-2024-8888"},
        {"id": "b", "run_id": "two", "cve": "CVE-2024-8888"},
    ]

    result = correlate_observations(pair, {"one": "Nmap", "two": "Nmap"})

    assert result["candidate_group_count"] == 0
    assert len(result["ranked_observations"]) == 2

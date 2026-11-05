"""Review-only correlation preserves source occurrences and provenance."""

from aegistrace.correlation import correlate_observations


def test_cve_candidate_group_preserves_occurrences_and_source_cvss_order():
    observations = [
        {
            "id": "obs-zap",
            "run_id": "run-zap",
            "evidence_id": "ev-zap",
            "asset_id": "asset-a",
            "endpoint_id": "endpoint-shared",
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
            "asset_id": "asset-a",
            "endpoint_id": "endpoint-shared",
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
    assert group["asset_ids"] == ["asset-a"]
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
        {"id": "a", "run_id": "one", "asset_id": "asset-a", "cve": "CVE-2024-8888"},
        {"id": "b", "run_id": "two", "asset_id": "asset-a", "cve": "CVE-2024-8888"},
    ]

    result = correlate_observations(pair, {"one": "Nmap", "two": "Nmap"})

    assert result["candidate_group_count"] == 0


def test_same_asset_service_and_parameter_can_match_across_tools_without_endpoint():
    pair = [
        {
            "id": "zap-observation",
            "run_id": "zap",
            "asset_id": "asset-a",
            "service_id": "service-https",
            "parameter_names": ["id"],
            "cve": "CVE-2024-1234",
        },
        {
            "id": "nikto-observation",
            "run_id": "nikto",
            "asset_id": "asset-a",
            "service_id": "service-https",
            "parameter_names": ["id"],
            "cve": "CVE-2024-1234",
        },
    ]

    result = correlate_observations(pair, {"zap": "OWASP ZAP", "nikto": "Nikto"})

    assert result["candidate_group_count"] == 1
    assert {
        item["service_id"] for item in result["cross_tool_candidate_groups"][0]["observations"]
    } == {"service-https"}
    assert len(result["ranked_observations"]) == 2


def test_cve_candidates_do_not_collapse_distinct_assets_endpoints_or_parameters():
    base = {
        "cve": "CVE-2024-1234",
        "title": "Example issue",
        "parameter_names": ["id"],
    }
    observations = [
        {**base, "id": "a", "run_id": "zap", "asset_id": "asset-a", "endpoint_id": "path-1"},
        {**base, "id": "b", "run_id": "nikto", "asset_id": "asset-b", "endpoint_id": "path-1"},
        {**base, "id": "c", "run_id": "nikto", "asset_id": "asset-a", "endpoint_id": "path-2"},
        {
            **base,
            "id": "d",
            "run_id": "nikto",
            "asset_id": "asset-a",
            "endpoint_id": "path-1",
            "parameter_names": ["account"],
        },
    ]
    result = correlate_observations(observations, {"zap": "OWASP ZAP", "nikto": "Nikto"})

    assert result["candidate_group_count"] == 0


def test_context_priority_keeps_unknown_unknown_and_flags_severe_low_confidence():
    observations = [
        {
            "id": "high-uncertain",
            "asset_id": "asset-high",
            "cvss_score": 8.7,
            "cvss_version": "3.1",
            "confidence": 0.2,
            "confidence_method": "test-only source-quality rubric",
        },
        {"id": "unscored", "asset_id": "asset-unknown"},
        {"id": "contextual", "asset_id": "asset-app", "cvss_score": 5.0, "cvss_version": "3.1"},
    ]
    context = {
        "asset-app": {
            "exposure": "internet-facing",
            "exposure_reference": "reviewed test-only inventory row",
            "criticality": 5,
            "criticality_reference": "reviewed test-only asset classification",
        }
    }

    result = correlate_observations(observations, {}, asset_context=context)
    ranking = result["contextual_risk_ranking"]
    by_id = {item["observation_id"]: item["priority"] for item in ranking["ranked_observations"]}

    assert ranking["policy"] == "aegistrace-context-priority-v1"
    assert by_id["high-uncertain"]["review_attention"] == "high-severity-low-confidence-review"
    assert by_id["unscored"]["local_priority_index"] is None
    assert by_id["contextual"]["state"] == "contextual-index"
    assert by_id["contextual"]["factors"]["asset_criticality"]["reference"]


"""Handcrafted Nikto parser cases; these are not scanner evidence."""

import json

import pytest
from aegistrace.correlation import correlate_observations
from aegistrace.nikto_parse import normalize_nikto
from aegistrace.safe_parse import isolated_inspection
from aegistrace.zap_parse import normalize_zap

SAMPLE = json.dumps(
    [
        {
            "host": "example.invalid",
            "vulnerabilities": [
                {
                    "id": "OSVDB-12345",
                    "references": "CVE-2024-12345; CWE-79",
                    "method": "GET",
                    "url": "https://example.invalid/app/check?token=private-value",
                    "msg": "Handcrafted Nikto parser test message",
                }
            ],
        }
    ]
).encode()


def test_nikto_maps_only_explicit_unambiguous_references_without_inventing_severity():
    parsed = normalize_nikto(SAMPLE, "2.6.1")

    assert parsed["state"] == "normalized"
    alert = parsed["alerts"][0]
    assert alert["classification"] == "server-configuration-observation"
    assert alert["plugin_id"] == "OSVDB-12345"
    assert alert["alert_ref"] == "CVE-2024-12345; CWE-79"
    assert alert["cve"] == "CVE-2024-12345"
    assert alert["cwe"] == "CWE-79"
    assert alert["cve_references"] == ["CVE-2024-12345"]
    assert alert["cwe_references"] == ["CWE-79"]
    assert alert["name"] == "Handcrafted Nikto parser test message"
    assert alert["risk"] == "unknown"
    assert alert["confidence_label"] == "unknown"
    assert alert["risk"] == "unknown"
    assert alert["instances"][0]["uri"] == "https://example.invalid/app/check"
    assert parsed["assets"] == ["https://example.invalid/app/check"]
    serialized = json.dumps(parsed)
    assert "private-value" not in serialized


def test_nikto_accepts_cli_version_banner_in_isolated_worker():
    parsed = isolated_inspection(
        SAMPLE, "Nikto", "nikto-json-normalize-v1", "Nikto 2.6.1 (LW 2.5)"
    )

    assert parsed["state"] == "normalized"
    assert parsed["parsed_records"] == 1


def test_ambiguous_or_non_string_references_do_not_create_correlation_identifiers():
    raw = json.dumps(
        [
            {
                "vulnerabilities": [
                    {
                        "references": "CVE-2024-12345; CVE-2024-67890 CWE-79 CWE-89",
                        "url": "https://example.invalid/app/check",
                    },
                    {
                        "references": ["CVE-2024-12345", "CWE-79"],
                        "url": "https://example.invalid/app/other",
                    },
                ]
            }
        ]
    ).encode()
    parsed = normalize_nikto(raw, "2.6.1")

    assert parsed["state"] == "normalized"
    assert parsed["alerts"][0]["cve_references"] == ["CVE-2024-12345", "CVE-2024-67890"]
    assert parsed["alerts"][0]["cwe_references"] == ["CWE-79", "CWE-89"]
    assert parsed["alerts"][0]["cve"] is None
    assert parsed["alerts"][0]["cwe"] is None
    assert parsed["alerts"][1]["cve_references"] == []
    assert parsed["alerts"][1]["cwe_references"] == []


def test_explicit_source_reported_cve_can_correlate_nikto_and_zap_observations():
    zap = normalize_zap(
        json.dumps(
            {
                "alerts": [
                    {
                        "alert": "TEST ONLY shared source issue",
                        "cve": "CVE-2024-12345",
                        "instances": [
                            {
                                "uri": "https://example.invalid/app/check",
                                "method": "GET",
                            }
                        ],
                    }
                ]
            }
        ).encode(),
        "2.16.0",
    )
    nikto = normalize_nikto(SAMPLE, "2.6.1")
    assert zap["state"] == nikto["state"] == "normalized"
    observations = [
        {
            "id": f"{tool}-observation",
            "asset_id": "same-test-asset",
            "endpoint_id": "same-test-endpoint",
            "parameter_names": [],
            "run_id": f"{tool}-run",
            "evidence_id": f"{tool}-evidence",
            "title": alert["name"],
            "cve": alert.get("cve"),
            "cwe": alert.get("cwe"),
        }
        for tool, alert in (
            ("OWASP ZAP", zap["alerts"][0]),
            ("Nikto", nikto["alerts"][0]),
        )
    ]

    result = correlate_observations(
        observations,
        {"OWASP ZAP-run": "OWASP ZAP", "Nikto-run": "Nikto"},
    )

    assert result["candidate_group_count"] == 1
    candidate = result["cross_tool_candidate_groups"][0]
    assert candidate["match_basis"] == "CVE"
    assert candidate["source_tools"] == ["Nikto", "OWASP ZAP"]
    assert candidate["observation_count"] == 2


@pytest.mark.parametrize(
    "version",
    [
        "2.5.0",
        "Nikto 2.5.0 (LW 2.5)",
        "3.0.0",
        "Nikto 3.0.0 (LW 2.5)",
        "2.6",
        "2.6.invalid",
        "Nikto latest",
        "source-declared",
    ],
)
def test_unsupported_nikto_versions_are_quarantined(version):
    parsed = normalize_nikto(SAMPLE, version)

    assert parsed["state"] == "quarantined"
    assert parsed["code"] == "unsupported-version-or-size"
    assert parsed["alerts"] == []


@pytest.mark.parametrize(
    ("raw", "version", "code"),
    [
        (b'[{"vulnerabilities":[],"vulnerabilities":[]}]', "2.6.1", "duplicate-json-key"),
        (b"{}", "2.6.1", "unsupported-format-or-host-limit"),
        (
            b'[{"vulnerabilities":[{"url":"https://example.invalid","method":"TRACE"}]}]',
            "2.6.1",
            "invalid-observation-url-or-method",
        ),
        (
            b'[{"vulnerabilities":[{"url":"https://example.invalid/app#fragment"}]}]',
            "2.6.1",
            "invalid-url",
        ),
    ],
)
def test_invalid_or_ambiguous_nikto_documents_are_quarantined(raw, version, code):
    parsed = normalize_nikto(raw, version)

    assert parsed["state"] == "quarantined"
    assert parsed["code"] == code
    assert parsed["alerts"] == []
    assert parsed["assets"] == []


def test_empty_nikto_report_is_zero_observations_not_coverage():
    parsed = normalize_nikto(b"[]", "2.6.1")

    assert parsed["state"] == "normalized"
    assert parsed["code"] == "no-observations"
    assert parsed["parsed_records"] == 0


def test_missing_source_identifiers_are_not_fabricated():
    raw = b'[{"vulnerabilities":[{"url":"https://example.invalid/"}]}]'
    parsed = normalize_nikto(raw, "2.6.1")

    assert parsed["state"] == "normalized"
    assert parsed["alerts"][0]["plugin_id"] == ""
    assert parsed["alerts"][0]["alert_ref"] == ""
    assert parsed["alerts"][0]["name"] == "Nikto server observation"


def test_nikto_normalization_runs_in_isolated_parser_worker():
    parsed = isolated_inspection(SAMPLE, "Nikto", "nikto-json-normalize-v1", "2.6.1")

    assert parsed["state"] == "normalized"
    assert parsed["parsed_records"] == 1
    assert "private-value" not in json.dumps(parsed)

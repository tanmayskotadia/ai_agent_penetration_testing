"""Handcrafted Nikto parser cases; these are not scanner evidence."""

import json

import pytest
from aegistrace.nikto_parse import normalize_nikto
from aegistrace.safe_parse import isolated_inspection

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


def test_nikto_preserves_source_labels_without_inventing_severity_or_cves():
    parsed = normalize_nikto(SAMPLE, "2.6.1")

    assert parsed["state"] == "normalized"
    alert = parsed["alerts"][0]
    assert alert["classification"] == "server-configuration-observation"
    assert alert["plugin_id"] == "OSVDB-12345"
    assert alert["alert_ref"] == "CVE-2024-12345; CWE-79"
    assert alert["name"] == "Handcrafted Nikto parser test message"
    assert alert["risk"] == "unknown"
    assert alert["confidence_label"] == "unknown"
    assert "cves" not in alert
    assert alert["instances"][0]["uri"] == "https://example.invalid/app/check"
    assert parsed["assets"] == ["https://example.invalid/app/check"]
    serialized = json.dumps(parsed)
    assert "private-value" not in serialized


@pytest.mark.parametrize("version", ["2.5.0", "3.0.0", "2.6", "2.6.invalid", "source-declared"])
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

"""Handcrafted OWASP ZAP Alerts samples; parser tests are not scanner evidence."""

import json

import pytest
from aegistrace.zap_parse import normalize_zap


def _sample() -> bytes:
    return json.dumps(
        {
            "alerts": [
                {
                    "id": "10021",
                    "pluginId": "10021",
                    "alertRef": "10021-1",
                    "alert": "Example alert",
                    "riskdesc": "Low (Medium)",
                    "confidence": "Medium",
                    "param": "session=must-not-appear",
                    "instances": [
                        {
                            "uri": "https://example.invalid/app?account=alice&token=private-value",
                            "method": "GET",
                            "param": "search=private-value",
                            "requestHeader": "Authorization: Bearer private-value",
                            "requestBody": "private request body",
                            "responseHeader": "Set-Cookie: session=private-value",
                            "responseBody": "private response body",
                        }
                    ],
                }
            ]
        }
    ).encode()


def test_zap_alert_import_retains_ids_endpoints_and_parameter_names_only():
    parsed = normalize_zap(_sample(), "2.16.0")

    assert parsed["state"] == "normalized"
    alert = parsed["alerts"][0]
    assert alert["alert_id"] == "10021"
    assert alert["plugin_id"] == "10021"
    assert alert["alert_ref"] == "10021-1"
    instance = alert["instances"][0]
    assert instance["method"] == "GET"
    assert instance["path"] == "/app"
    assert instance["parameter_names"] == ["account", "search", "session", "token"]
    assert instance["request_response_evidence"] == "encrypted-original-only"
    serialized = json.dumps(parsed)
    for private_value in (
        "alice",
        "private-value",
        "Authorization",
        "private request body",
        "private response body",
    ):
        assert private_value not in serialized
    assert parsed["assets"] == ["https://example.invalid/app"]


@pytest.mark.parametrize(
    ("raw", "version", "code"),
    [
        (b'{"alerts":[],"alerts":[]}', "2.16.0", "duplicate-json-key"),
        (b'{"alerts":[]}', "2.latest", "unsupported-version-or-size"),
        (b'{"alerts":[]}', "2.16.0", "asset-mapping-unavailable"),
        (
            b'{"alerts":[{"instances":[{"uri":"https://example.invalid","method":"TRACE"}]}]}',
            "2.16.0",
            "invalid-instance",
        ),
    ],
)
def test_invalid_or_unsupported_zap_alert_documents_are_quarantined(raw, version, code):
    parsed = normalize_zap(raw, version)

    assert parsed["state"] == "quarantined"
    assert parsed["code"] == code
    assert parsed["alerts"] == []
    assert parsed["assets"] == []


def test_zap_query_parameter_count_is_bounded_and_bad_query_is_not_reflected():
    uri = "https://example.invalid/?" + "&".join("p=x" for _ in range(51))
    parsed = normalize_zap(
        json.dumps({"alerts": [{"instances": [{"uri": uri}]}]}).encode(), "2.16.0"
    )

    assert parsed["state"] == "normalized"
    assert parsed["alerts"][0]["instances"][0]["parameter_names"] == []
    assert "private" not in json.dumps(parsed)


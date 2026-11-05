"""Handcrafted parser-only samples; they are not genuine scanner evidence."""

import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from aegistrace.auth import issue_identity
from aegistrace.safe_parse import inspect_container, isolated_inspection
from aegistrace.scanner_parse import parse_scanner_export

pytest_plugins = ("test_ingestion",)

NESSUS = b"""<?xml version="1.0"?>
<!DOCTYPE NessusClientData_v2>
<NessusClientData_v2><Report name="test">
  <ReportHost name="server-a"><HostProperties><tag name="host-ip">192.0.2.10</tag></HostProperties>
    <ReportItem port="443" protocol="tcp" svc_name="https" severity="2" pluginID="123" pluginName="Example finding">
      <risk_factor>Medium</risk_factor><cvss3_base_score>6.4</cvss3_base_score>
      <cvss3_vector>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N</cvss3_vector>
      <cve>CVE-2024-12345</cve><plugin_output>private output</plugin_output>
    </ReportItem>
    <ReportItem port="443" protocol="tcp" svc_name="https" severity="2" pluginID="123" pluginName="Example finding">
      <risk_factor>Medium</risk_factor><cve>CVE-2024-12345</cve>
    </ReportItem>
  </ReportHost>
  <ReportHost name="server-b"><HostProperties><tag name="host-ip">192.0.2.11</tag></HostProperties>
    <ReportItem port="0" protocol="tcp" severity="0" pluginID="0" pluginName="Informational"/>
  </ReportHost>
</Report></NessusClientData_v2>"""

GREENBONE = b"""<get_reports_response><report id="report-1"><results>
  <result id="result-1"><host>192.0.2.20</host><port>8443/tcp</port>
    <nvt oid="1.3.6.1.4.1.25623.1.0.1"><name>Greenbone observation</name><cvss_base>7.1</cvss_base><refs><ref type="cve" id="CVE-2023-12345"/></refs></nvt>
    <severity>High</severity><qod><value>80</value><type>remote_banner</type></qod>
  </result></results></report></get_reports_response>"""

NIKTO = json.dumps(
    [
        {
            "host": "example.invalid",
            "vulnerabilities": [
                {
                    "id": "OSVDB-12345",
                    "references": "CVE-2024-12345",
                    "method": "GET",
                    "url": "https://example.invalid/app/check?token=private-value",
                    "msg": "Handcrafted Nikto import integration test only",
                }
            ],
        }
    ]
).encode()

BURP = (
    b"""<?xml version="1.0"?><!DOCTYPE issues [<!ELEMENT issues ANY>]>
<issues burpVersion="test"><issue><serialNumber>42</serialNumber><type>100</type>
  <name>Example web issue</name><host ip="192.0.2.30">https://example.invalid</host>
  <path>/app/check?token=secret-query</path><severity>High</severity><confidence>Certain</confidence>
  <vulnerabilityClassifications><cwe>https://cwe.mitre.org/data/definitions/79.html</cwe></vulnerabilityClassifications>
  <requestresponse><request base64="true">"""
    + base64.b64encode(b"Cookie: secret-header\r\n\r\nsecret-body")
    + b"""</request></requestresponse>
</issue></issues>"""
)

ZAP = json.dumps(
    {
        "alerts": [
            {
                "id": "10021",
                "pluginId": "10021",
                "alertRef": "10021-1",
                "alert": "Handcrafted parser integration test only",
                "riskdesc": "Low",
                "confidence": "Medium",
                "instances": [
                    {
                        "uri": "https://example.invalid/app?token=private-value",
                        "method": "GET",
                        "param": "token=private-value",
                        "requestHeader": "Authorization: Bearer private-value",
                        "responseBody": "private output",
                    }
                ],
            }
        ]
    }
).encode()


def test_nessus_import_preserves_plugin_occurrences_cvss_and_host_identity():
    parsed = parse_scanner_export(NESSUS, "Nessus")

    assert parsed["state"] == "normalized"
    assert parsed["assets"] == ["192.0.2.10", "192.0.2.11"]
    assert len(parsed["observations"]) == 3
    first, duplicate, other_host = parsed["observations"]
    assert first["port"] == 443 and first["protocol"] == "tcp"
    assert first["cvss_score"] == 6.4 and first["cvss_version"] == "3.1"
    assert first["cves"] == ["CVE-2024-12345"]
    assert first["source_key"] == duplicate["source_key"]
    assert first["asset"] != other_host["asset"]
    assert "private output" not in json.dumps(parsed)


def test_greenbone_qod_stays_source_metadata_and_not_confidence():
    parsed = parse_scanner_export(GREENBONE, "Greenbone")

    assert parsed["state"] == "normalized"
    item = parsed["observations"][0]
    assert item["cves"] == ["CVE-2023-12345"]
    assert item["qod"] == {"value": "80", "type": "remote_banner"}
    assert "confidence" not in item


def test_burp_internal_doctype_and_base64_messages_are_not_decoded_or_copied():
    parsed = parse_scanner_export(BURP, "Burp Suite")
    inspected = inspect_container(BURP, "Burp Suite", "burp-xml", "source-declared")

    assert parsed["state"] == "normalized"
    assert inspected["state"] == "container-validated"
    assert parsed["observations"][0]["asset"] == "https://example.invalid/app/check"
    serialized = json.dumps(parsed)
    assert "secret-header" not in serialized
    assert "secret-body" not in serialized
    assert "secret-query" not in serialized


def test_truncated_and_entity_expansion_exports_are_quarantined():
    truncated = parse_scanner_export(NESSUS[:-40], "Nessus")
    xxe = b'<!DOCTYPE x [<!ENTITY secret SYSTEM "file:///must-not-read">]><NessusClientData_v2>&secret;</NessusClientData_v2>'

    assert truncated["state"] == "quarantined"
    assert truncated["incomplete"] is True
    assert parse_scanner_export(xxe, "Nessus")["state"] == "quarantined"


def test_offline_normalizer_runs_in_isolated_parser_worker():
    result = isolated_inspection(NESSUS, "Nessus", "nessus-normalize-v1", "source-declared")

    assert result["state"] == "normalized"
    assert result["parsed_records"] == 3


@pytest.mark.parametrize(
    ("tool", "format_name", "route", "raw", "targets", "version", "expected"),
    [
        (
            "Nessus",
            "nessus-xml",
            "normalize-nessus",
            NESSUS,
            ["192.0.2.0/24"],
            "source-declared",
            3,
        ),
        (
            "Greenbone",
            "greenbone-xml",
            "normalize-greenbone",
            GREENBONE,
            ["192.0.2.0/24"],
            "source-declared",
            1,
        ),
        (
            "Nikto",
            "nikto-json",
            "normalize-nikto",
            NIKTO,
            ["https://example.invalid/app"],
            "2.6.1",
            1,
        ),
        (
            "Burp Suite",
            "burp-xml",
            "normalize-burp",
            BURP,
            ["https://example.invalid"],
            "source-declared",
            1,
        ),
        (
            "OWASP ZAP",
            "zap-alerts-json",
            "normalize-zap",
            ZAP,
            ["https://example.invalid/app"],
            "2.16.0",
            1,
        ),
    ],
)
def test_candidate_imports_flow_through_encrypted_evidence_and_scope(
    import_context, tool, format_name, route, raw, targets, version, expected
):
    client, settings = import_context

    def headers():
        return {
            "Authorization": "Bearer " + issue_identity(settings, "owner"),
            "X-Request-ID": str(uuid4()),
            "Idempotency-Key": str(uuid4()),
        }

    def post(path, body):
        response = client.post(path, json=body, headers=headers())
        assert response.status_code in {200, 201, 202}, f"{path}: {response.text}"
        return response.json()

    assessment = post("/api/v1/assessments", {"name": "Handcrafted parser integration test only"})
    base = f"/api/v1/assessments/{assessment['id']}"
    scope = post(base + "/scopes", {"revision": 1, "targets": targets})
    now = datetime.now(UTC)
    run = post(
        base + "/runs",
        {
            "scope_id": scope["id"],
            "tool": tool,
            "tool_version": version,
            "captured_at": now.isoformat(),
        },
    )
    evidence = post(
        base + "/runs/" + run["id"] + "/evidence",
        {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "pointer": "/",
            "pointer_type": "whole-file",
            "captured_at": now.isoformat(),
        },
    )
    upload = client.put(
        base + "/evidence/" + evidence["id"] + "/original",
        content=raw,
        params={"expires_at": (now + timedelta(days=1)).isoformat()},
        headers=headers(),
    )
    assert upload.status_code == 201, upload.text
    imported = post(
        base + "/imports",
        {
            "scope_id": scope["id"],
            "scope_revision": 1,
            "tool": tool,
            "format": format_name,
            "evidence_id": evidence["id"],
        },
    )

    normalized = post(base + f"/imports/{imported['id']}/{route}", {"asset_mapping": {}})

    assert normalized["state"] == "normalized"
    assert normalized["mode"] == "recorded-import"
    assert normalized["native_live_execution"] is False
    assert normalized["findings_created"] == 0
    assert len(normalized["observation_ids"]) == expected
    assert normalized["out_of_scope_assets"] == []
    assert "private output" not in json.dumps(normalized)
    assert "secret-header" not in json.dumps(normalized)
    assert "private-value" not in json.dumps(normalized)
    if tool == "Nikto":
        assert normalized["alerts"][0]["plugin_id"] == "OSVDB-12345"
        assert normalized["alerts"][0]["risk"] == "unknown"
        assert "cves" not in normalized["alerts"][0]
        assert normalized["alerts"][0]["instances"][0]["uri"] == (
            "https://example.invalid/app/check"
        )

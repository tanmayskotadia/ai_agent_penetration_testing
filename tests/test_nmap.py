"""Handcrafted native-format contracts, explicitly not genuine scanner output."""

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from aegistrace.auth import issue_identity
from aegistrace.nmap_parse import normalize_nmap
from aegistrace.safe_parse import isolated_inspection
from test_ingestion import import_context as import_context

XML = b'<nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05"><host><status state="up"/><address addr="192.0.2.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="80"><state state="open"/><service name="http" product="TEST ONLY"/></port><port protocol="tcp" portid="81"><state state="closed"/></port><port protocol="tcp" portid="82"><state state="filtered"/></port><port protocol="tcp" portid="83"/></ports></host><runstats><finished exit="success"/></runstats></nmaprun>'


def source(context, raw=XML, targets=None):
    client, config = context

    def headers():
        return {
            "Authorization": "Bearer " + issue_identity(config, "owner", "reviewer"),
            "X-Request-ID": str(uuid4()),
            "Idempotency-Key": str(uuid4()),
        }

    def post(path, body):
        response = client.post(path, json=body, headers=headers())
        assert response.status_code in {200, 201, 202}, response.text
        return response.json()

    assessment = post("/api/v1/assessments", {"name": "TEST ONLY native-format parser"})
    base = "/api/v1/assessments/" + assessment["id"]
    scope = post(base + "/scopes", {"revision": 1, "targets": targets or ["192.0.2.10"]})
    now = datetime.now(UTC).isoformat()
    run = post(
        base + "/runs",
        {"scope_id": scope["id"], "tool": "Nmap", "tool_version": "7.95", "captured_at": now},
    )
    evidence = post(
        base + "/runs/" + run["id"] + "/evidence",
        {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "pointer": "/",
            "pointer_type": "whole-file",
            "captured_at": now,
        },
    )
    uploaded = client.put(
        base + "/evidence/" + evidence["id"] + "/original",
        content=raw,
        params={"expires_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat()},
        headers=headers(),
    )
    assert uploaded.status_code == 201
    request = {
        "scope_id": scope["id"],
        "scope_revision": 1,
        "tool": "Nmap",
        "format": "nmap-xml",
        "evidence_id": evidence["id"],
    }
    imported = post(base + "/imports", request)
    return base, headers, imported, request, run, evidence


def test_port_states_ipv6_missing_versions_and_incomplete_output():
    parsed = normalize_nmap(XML, "7.95")
    assert parsed["state"] == "normalized"
    assert [x["state"] for x in parsed["hosts"][0]["ports"]] == [
        "open",
        "closed",
        "filtered",
        "unknown",
    ]
    assert parsed["hosts"][0]["ports"][0]["service"]["version"] is None
    v6 = XML.replace(b'192.0.2.10" addrtype="ipv4', b'2001:db8::10" addrtype="ipv6')
    assert normalize_nmap(v6, "7.95")["assets"] == ["2001:db8::10"]
    assert normalize_nmap(XML[:-35], "7.95")["state"] == "partial"
    assert (
        normalize_nmap(XML.replace(b'exit="success"', b'exit="error"'), "7.95")["state"]
        == "partial"
    )
    assert normalize_nmap(XML, "8.0")["state"] == "quarantined"
    xxe = b'<!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///not-read">]>' + XML
    assert normalize_nmap(xxe, "7.95")["state"] == "quarantined"
    assert isolated_inspection(XML, "Nmap", "nmap-normalize-v1", "7.95")["state"] == "normalized"


def test_import_normalization_provenance_dedup_and_scope(import_context):
    client, _ = import_context
    base, headers, imported, request, run, evidence = source(import_context)
    scopes = client.get(base + "/scopes", headers=headers())
    assert scopes.status_code == 200 and scopes.json()[0]["id"] == run["scope_id"]
    response = client.post(
        base + "/imports/" + imported["id"] + "/normalize-nmap", json={}, headers=headers()
    )
    assert response.status_code == 201, response.text
    value = response.json()
    assert value["mode"] == "recorded-import" and not value["native_live_execution"]
    assert value["run_id"] == run["id"] and value["evidence_id"] == evidence["id"]
    assert value["source_sha256"] == hashlib.sha256(XML).hexdigest()
    assert (
        len(value["asset_ids"]) == 1
        and len(value["service_ids"]) == 1
        and len(value["observation_ids"]) == 4
    )
    assert value["findings_created"] == 0
    again = client.post(base + "/imports", json=request, headers=headers()).json()
    repeated = client.post(
        base + "/imports/" + again["id"] + "/normalize-nmap", json={}, headers=headers()
    ).json()
    assert (
        repeated["service_ids"] == value["service_ids"]
        and repeated["observation_ids"] == value["observation_ids"]
    )
    outside = source(import_context, targets=["192.0.2.99"])
    result = client.post(
        outside[0] + "/imports/" + outside[2]["id"] + "/normalize-nmap",
        json={},
        headers=outside[1](),
    ).json()
    assert result["state"] == "quarantined" and not result["asset_ids"]


@pytest.mark.services
def test_postgresql_candidate_nmap_intake(import_context):
    test_import_normalization_provenance_dedup_and_scope(import_context)

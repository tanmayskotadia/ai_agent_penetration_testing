"""All malicious and native-shaped samples here are handcrafted parser tests only."""

import hashlib
import io
import json
import os
import secrets
import socket
import time
import zipfile
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from aegistrace.api import create_app
from aegistrace.auth import issue_identity
from aegistrace.db import make_engine
from aegistrace.safe_parse import inspect_container, isolated_inspection, mapped_assets
from aegistrace.schema_v1 import metadata
from aegistrace.settings import Settings
from fastapi.testclient import TestClient

TEST_XML = b'<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05"><host><address addr="192.0.2.10" addrtype="ipv4"/></host><runstats><finished exit="success"/></runstats></nmaprun>'


def test_native_bare_doctype_is_allowed_but_xxe_and_stylesheet_are_never_fetched(monkeypatch):
    calls = []

    def deny(*args, **kwargs):
        calls.append(args)
        raise AssertionError("network forbidden")

    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)
    with_style = TEST_XML.replace(
        b'<?xml version="1.0"?>',
        b'<?xml version="1.0"?><?xml-stylesheet href="https://untrusted.invalid/not-fetched"?>',
    )
    assert (
        inspect_container(with_style, "Nmap", "nmap-xml", "7.95")["state"] == "container-validated"
    )
    xxe = b'<!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM "file:///must-never-read">]><nmaprun scanner="nmap" version="7.95" xmloutputversion="1.05">&xxe;</nmaprun>'
    assert inspect_container(xxe, "Nmap", "nmap-xml", "7.95")["state"] == "quarantined"
    external = xxe.replace(b"file:///must-never-read", b"https://untrusted.invalid/not-fetched")
    assert isolated_inspection(external, "Nmap", "nmap-xml", "7.95")["state"] == "quarantined"
    assert calls == []


@pytest.mark.parametrize(
    "raw,tool,format_name,version",
    [
        (TEST_XML[:-20], "Nmap", "nmap-xml", "7.95"),
        (TEST_XML, "Nmap", "nmap-xml", "99.0"),
        (b"<x>" * 50 + b"</x>" * 50, "Nmap", "nmap-xml", "7.95"),
        (b"[" * 100 + b"0" + b"]" * 100, "OWASP ZAP", "zap-alerts-json", "2.16.0"),
        (b'{"alerts":[],"alerts":[]}', "OWASP ZAP", "zap-alerts-json", "2.16.0"),
        (
            b'{"alerts":[{"url":"https://example.invalid/","value":NaN}]}',
            "OWASP ZAP",
            "zap-alerts-json",
            "2.16.0",
        ),
        (
            b'{"alerts":[{"url":"https://example.invalid/","value":"\\u0000"}]}',
            "OWASP ZAP",
            "zap-alerts-json",
            "2.16.0",
        ),
        (b"<html><script>throw 'never executed'</script></html>", "Nmap", "html", "7.95"),
        (b"x" * 2097153, "Nmap", "nmap-xml", "7.95"),
    ],
)
def test_malformed_oversized_unsupported_and_hostile_containers_quarantined(
    raw, tool, format_name, version
):
    result = inspect_container(raw, tool, format_name, version)
    assert result["state"] == "quarantined" and len(json.dumps(result)) < 131072


def test_archive_traversal_bomb_rejected_without_extraction_and_timeout_bounded(tmp_path):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("../../must-not-extract.txt", b"x" * 5000000)
    result = inspect_container(stream.getvalue(), "Nmap", "nmap-xml", "7.95")
    assert result["code"] == "archives-unsupported"
    assert list(tmp_path.iterdir()) == []
    before = time.monotonic()
    result = isolated_inspection(TEST_XML, "Nmap", "nmap-xml", "7.95", timeout=0.000001)
    assert result["state"] == "quarantined" and time.monotonic() - before < 5


def test_scope_mapping_and_exclusions_take_precedence():
    assert mapped_assets(["192.0.2.10"], ["asset-a"], [], {"192.0.2.10": "asset-a"}) == (
        ["192.0.2.10"],
        [],
    )
    assert mapped_assets(
        ["192.0.2.10"], ["asset-a"], ["192.0.2.0/24"], {"192.0.2.10": "asset-a"}
    ) == ([], ["192.0.2.10"])
    assert (
        mapped_assets(["https://example.invalid/app/a"], ["https://example.invalid/app"], [], {})[1]
        == []
    )
    assert mapped_assets(
        ["https://example.invalid/application"], ["https://example.invalid/app"], [], {}
    )[1]
    with pytest.raises(ValueError):
        mapped_assets(
            ["https://example.invalid/app/%2e%2e/admin"], ["https://example.invalid/app"], [], {}
        )


@pytest.fixture
def import_context(tmp_path, request):
    settings = Settings(
        _env_file=None,
        app_secret=secrets.token_hex(32),
        evidence_key=secrets.token_hex(32),
        database_url=os.environ["DATABASE_URL"]
        if request.node.get_closest_marker("services")
        else f"sqlite:///{tmp_path / 'imports.db'}",
    )
    engine = make_engine(settings)
    metadata.create_all(engine)
    with TestClient(create_app(settings)) as client:
        yield client, settings
    engine.dispose()


def ingestion_flow(context, raw, targets):
    client, settings = context

    def headers():
        return {
            "Authorization": "Bearer " + issue_identity(settings, "owner"),
            "X-Request-ID": str(uuid4()),
            "Idempotency-Key": str(uuid4()),
        }

    def post(path, body):
        response = client.post(path, json=body, headers=headers())
        assert response.status_code in {200, 201, 202}, response.text
        return response.json()

    assessment = post("/api/v1/assessments", {"name": "Parser test only, not a real capture"})
    base = "/api/v1/assessments/" + assessment["id"]
    scope = post(base + "/scopes", {"revision": 1, "targets": targets})
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
    route = base + "/evidence/" + evidence["id"]
    response = client.put(
        route + "/original",
        content=raw,
        params={"expires_at": (datetime.now(UTC) + timedelta(days=1)).isoformat()},
        headers=headers(),
    )
    assert response.status_code == 201, response.text
    imported = post(
        base + "/imports",
        {
            "scope_id": scope["id"],
            "scope_revision": 1,
            "tool": "Nmap",
            "format": "nmap-xml",
            "evidence_id": evidence["id"],
        },
    )
    result = post(base + "/imports/" + imported["id"] + "/inspect", {})
    ticket = post(route + "/download-ticket", {})["ticket"]
    restored = client.get(route + "/original", headers=headers() | {"X-Download-Ticket": ticket})
    assert restored.content == raw
    assert client.get(base + "/findings", headers=headers()).json() == []
    assert result["findings_created"] == 0 and result["mode"] == "recorded-import"
    return result


def test_integrated_scope_quarantine_and_preserved_original(import_context):
    valid = ingestion_flow(import_context, TEST_XML, ["192.0.2.10"])
    assert valid["state"] == "container-validated" and not valid["normalizer_enabled"]
    outside = ingestion_flow(import_context, TEST_XML, ["192.0.2.99"])
    assert outside["state"] == "quarantined" and outside["out_of_scope_assets"] == ["192.0.2.10"]
    partial = ingestion_flow(import_context, TEST_XML[:-20], ["192.0.2.10"])
    assert partial["state"] == "quarantined" and partial["parsed_records"] >= 1


@pytest.mark.services
def test_postgresql_quarantine_and_exact_original_roundtrip(import_context):
    if os.environ.get("RUN_SERVICE_TESTS") != "1":
        pytest.skip("requires PostgreSQL")
    test_integrated_scope_quarantine_and_preserved_original(import_context)

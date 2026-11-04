"""Bounded offline parsers for Nessus, Greenbone and Burp issue exports."""

import ipaddress
import re
from typing import Any
from urllib.parse import urlsplit

from defusedxml import ElementTree as SafeET

from aegistrace.safe_parse import (
    MAX_ASSETS,
    MAX_BYTES,
    MAX_DEPTH,
    MAX_NODES,
    ParseRejected,
    canonical,
)

MAX_ITEMS = 10000
MAX_TEXT = 65536


def _xml_root(raw: bytes) -> Any:
    if not 0 < len(raw) <= MAX_BYTES:
        raise ParseRejected("size-limit")
    try:
        root = SafeET.fromstring(raw, forbid_dtd=False, forbid_entities=True, forbid_external=True)
    except SafeET.ParseError as error:
        raise ParseRejected("truncated-or-malformed-xml") from error
    stack = [(root, 1)]
    nodes = 0
    while stack:
        node, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH or len(node.attrib) > 128:
            raise ParseRejected("structure-limit")
        if any(
            len(value) > MAX_BYTES or any(ord(char) < 32 and char not in "\t\n\r" for char in value)
            for value in node.attrib.values()
        ):
            raise ParseRejected("string-limit")
        detail_text = node.tag.lower() in {
            "plugin_output",
            "description",
            "request",
            "response",
        }
        text_limit = MAX_BYTES if detail_text else MAX_TEXT
        if any(value is not None and len(value) > text_limit for value in (node.text, node.tail)):
            raise ParseRejected("string-limit")
        stack.extend((child, depth + 1) for child in node)
    return root


def _child_text(node: Any, name: str) -> str | None:
    child = node.find(name)
    value = child.text.strip() if child is not None and child.text else ""
    return value[:MAX_TEXT] or None


def _number(node: Any, *names: str) -> float | None:
    for name in names:
        value = _child_text(node, name)
        if value is None:
            continue
        try:
            score = float(value)
        except ValueError:
            continue
        if 0 <= score <= 10:
            return score
    return None


def _cves(node: Any) -> list[str]:
    found = []
    for item in node.findall(".//cve"):
        value = (item.text or "").strip().upper()
        found.extend(re.findall(r"CVE-[0-9]{4}-[0-9]{4,}", value))
    return sorted(set(found))


def _host_identifier(value: str) -> str:
    value = value.strip()
    if not value or len(value) > 500 or any(ord(char) < 32 for char in value):
        raise ParseRejected("invalid-host")
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value.rstrip(".").lower()


def _result(
    *,
    asset: str,
    pointer: str,
    title: str,
    severity: str | None = None,
    source_key: str | None = None,
    port: int | None = None,
    protocol: str | None = None,
    service: str | None = None,
    cves: list[str] | None = None,
    cwe: str | None = None,
    score: float | None = None,
    vector: str | None = None,
    cvss_version: str | None = None,
    confidence_label: str | None = None,
    qod: dict[str, str | None] | None = None,
) -> dict[str, Any]:
    return {
        "asset": asset,
        "pointer": pointer,
        "source_key": source_key or pointer,
        "title": title[:500] or "Unlabelled source observation",
        "source_severity": severity[:100] if severity else None,
        "port": port,
        "protocol": protocol,
        "service": service[:200] if service else None,
        "cves": cves or [],
        "cwe": cwe,
        "cvss_score": score,
        "cvss_vector": vector[:200] if vector else None,
        "cvss_version": cvss_version,
        "confidence_label": confidence_label[:100] if confidence_label else None,
        "qod": qod,
    }


def parse_nessus(raw: bytes) -> dict[str, Any]:
    root = _xml_root(raw)
    if root.tag != "NessusClientData_v2":
        raise ParseRejected("unsupported-nessus-export")
    observations: list[dict[str, Any]] = []
    assets: set[str] = set()
    for host_index, host in enumerate(root.findall("./Report/ReportHost")):
        props = {
            tag.get("name"): (tag.text or "").strip()
            for tag in host.findall("./HostProperties/tag")
            if tag.get("name")
        }
        candidate = props.get("host-ip") or props.get("hostname") or host.get("name") or ""
        asset = _host_identifier(candidate)
        assets.add(asset)
        for item_index, item in enumerate(host.findall("ReportItem")):
            if len(observations) >= MAX_ITEMS:
                raise ParseRejected("observation-limit")
            port_text = item.get("port", "0")
            try:
                port: int | None = int(port_text)
            except ValueError:
                port = 0
            protocol = (item.get("protocol") or "").lower()
            if port is None or protocol not in {"tcp", "udp"} or not 1 <= port <= 65535:
                port, protocol = None, None
            cvss4 = _number(item, "cvss4_base_score")
            cvss3 = _number(item, "cvss3_base_score")
            cvss2 = _number(item, "cvss_base_score")
            version: str | None
            score: float | None
            if cvss4 is not None:
                vector = _child_text(item, "cvss4_vector")
                score, version = cvss4, "4.0" if vector and vector.startswith("CVSS:4.0/") else None
            elif cvss3 is not None:
                score = cvss3
                vector = _child_text(item, "cvss3_vector")
                version = next(
                    (
                        value
                        for value in ("3.1", "3.0")
                        if vector and vector.startswith(f"CVSS:{value}/")
                    ),
                    None,
                )
            else:
                score, version = (cvss2, "2.0") if cvss2 is not None else (None, None)
                vector = _child_text(item, "cvss_vector") if cvss2 is not None else None
            if version is None:
                vector = None
            plugin_id = item.get("pluginID", "")
            observations.append(
                _result(
                    asset=asset,
                    pointer=f"/Report/ReportHost[{host_index + 1}]/ReportItem[{item_index + 1}]",
                    source_key=f"plugin:{plugin_id}:port:{port or 0}:{protocol or 'unknown'}",
                    title=item.get("pluginName") or "Nessus plugin observation",
                    severity=_child_text(item, "risk_factor") or item.get("severity"),
                    port=port,
                    protocol=protocol,
                    service=item.get("svc_name"),
                    cves=_cves(item),
                    score=score,
                    vector=vector,
                    cvss_version=version,
                )
            )
    if len(assets) > MAX_ASSETS:
        raise ParseRejected("asset-limit")
    return {
        "state": "normalized" if observations else "normalized",
        "code": "ok" if observations else "no-observations",
        "assets": sorted(assets),
        "observations": observations,
        "parsed_records": len(observations),
        "source_format": "nessus-xml",
        "limitations": [
            "Offline .nessus report import; no Tenable API or live scanner capability is implied",
            "User-declared scanner edition and version are not independently verified",
            "Plugin output remains only in the encrypted original evidence",
        ],
    }


def parse_greenbone(raw: bytes) -> dict[str, Any]:
    root = _xml_root(raw)
    reports = root.findall(".//report")
    if root.tag not in {"report", "get_reports_response", "gmp"} or not reports:
        raise ParseRejected("unsupported-greenbone-report")
    observations: list[dict[str, Any]] = []
    assets: set[str] = set()
    report = reports[-1]
    for index, item in enumerate(report.findall("./results/result")):
        if len(observations) >= MAX_ITEMS:
            raise ParseRejected("observation-limit")
        host = _host_identifier(_child_text(item, "host") or "")
        assets.add(host)
        port_value = _child_text(item, "port") or ""
        match = re.fullmatch(r"([0-9]{1,5})/(tcp|udp)", port_value, flags=re.IGNORECASE)
        port = int(match.group(1)) if match and 1 <= int(match.group(1)) <= 65535 else None
        protocol = match.group(2).lower() if match and port is not None else None
        nvt = item.find("nvt")
        cves = []
        if nvt is not None:
            cves = sorted(
                {
                    (ref.get("id") or "").strip().upper()
                    for ref in nvt.findall("./refs/ref")
                    if ref.get("type", "").lower() == "cve"
                    and re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", ref.get("id", "").upper())
                }
            )
        oid = nvt.get("oid", "") if nvt is not None else ""
        qod_value = _child_text(item, "./qod/value")
        qod_type = _child_text(item, "./qod/type")
        observations.append(
            _result(
                asset=host,
                pointer=f"/report/results/result[{index + 1}]",
                source_key=f"result:{item.get('id', index)}:nvt:{oid}:port:{port_value}",
                title=(_child_text(nvt, "name") if nvt is not None else None)
                or "Greenbone NVT observation",
                severity=_child_text(item, "severity") or _child_text(item, "threat"),
                port=port,
                protocol=protocol,
                service=_child_text(item, "name"),
                cves=cves,
                score=_number(nvt, "cvss_base") if nvt is not None else None,
                qod={"value": qod_value, "type": qod_type} if qod_value or qod_type else None,
            )
        )
    if len(assets) > MAX_ASSETS:
        raise ParseRejected("asset-limit")
    return {
        "state": "normalized",
        "code": "ok" if observations else "no-observations",
        "assets": sorted(assets),
        "observations": observations,
        "parsed_records": len(observations),
        "source_format": "greenbone-xml",
        "limitations": [
            "Offline native report import; no GMP requests, task control or feed readiness is performed",
            "QoD is retained as source metadata and is not a calibrated probability",
            "Feed, protocol and scan configuration are not independently verified",
        ],
    }


def parse_burp(raw: bytes) -> dict[str, Any]:
    root = _xml_root(raw)
    if root.tag != "issues":
        raise ParseRejected("unsupported-burp-issue-export")
    observations: list[dict[str, Any]] = []
    assets: set[str] = set()
    for index, issue in enumerate(root.findall("issue")):
        if len(observations) >= MAX_ITEMS:
            raise ParseRejected("observation-limit")
        host_node = issue.find("host")
        raw_host = (host_node.text or "").strip() if host_node is not None else ""
        path = _child_text(issue, "path") or "/"
        parsed = urlsplit(raw_host)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username:
            raise ParseRejected("invalid-burp-host-url")
        # The issue path is location metadata; discard query/fragment and never request it.
        path_parts = urlsplit(path)
        safe_path = path_parts.path or "/"
        asset = f"{parsed.scheme}://{parsed.netloc}{safe_path}"
        asset = canonical(asset)
        assets.add(asset)
        classifications = issue.findall("./vulnerabilityClassifications/*")
        cwe = None
        for classification in classifications:
            value = (classification.text or "").strip()
            match = re.search(r"CWE[-_ ]?([0-9]+)", value, flags=re.IGNORECASE)
            if match:
                cwe = f"CWE-{match.group(1)}"
                break
        observations.append(
            _result(
                asset=asset,
                pointer=f"/issues/issue[{index + 1}]",
                source_key=f"serial:{_child_text(issue, 'serialNumber') or index}:type:{_child_text(issue, 'type') or ''}",
                title=_child_text(issue, "name") or "Burp issue",
                severity=_child_text(issue, "severity"),
                cwe=cwe,
                confidence_label=_child_text(issue, "confidence"),
            )
        )
    if len(assets) > MAX_ASSETS:
        raise ParseRejected("asset-limit")
    return {
        "state": "normalized",
        "code": "ok" if observations else "no-observations",
        "assets": sorted(assets),
        "observations": observations,
        "parsed_records": len(observations),
        "source_format": "burp-xml",
        "limitations": [
            "Offline Burp issue XML import; no Burp API or scanner edition is assumed",
            "Request/response nodes are not decoded or copied into normalized records",
            "Source confidence remains a label; it is not converted to a probability",
        ],
    }


def parse_scanner_export(raw: bytes, tool: str) -> dict[str, Any]:
    try:
        if tool == "Nessus":
            return parse_nessus(raw)
        if tool == "Greenbone":
            return parse_greenbone(raw)
        if tool == "Burp Suite":
            return parse_burp(raw)
        raise ParseRejected("unsupported-tool")
    except ParseRejected as error:
        result = {
            "state": "quarantined",
            "code": str(error),
            "assets": [],
            "observations": [],
            "parsed_records": 0,
        }
        if str(error) == "truncated-or-malformed-xml":
            result["incomplete"] = True
        return result
    except (ValueError, KeyError, TypeError, SafeET.ParseError, RecursionError):
        return {
            "state": "quarantined",
            "code": "malformed-or-unsupported",
            "assets": [],
            "observations": [],
            "parsed_records": 0,
        }
    except Exception:
        return {
            "state": "quarantined",
            "code": "unsafe-or-malformed",
            "assets": [],
            "observations": [],
            "parsed_records": 0,
        }

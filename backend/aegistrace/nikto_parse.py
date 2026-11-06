"""Candidate parser for Nikto's 2.6.x JSON report array; never runs a scanner."""

import json
import re
from typing import Any
from urllib.parse import urlsplit

from aegistrace.safe_parse import (
    MAX_ASSETS,
    MAX_BYTES,
    MAX_DEPTH,
    MAX_NODES,
    ParseRejected,
    _bad_constant,
    _json_pairs,
    canonical,
)

MAX_HOSTS = 200
MAX_OBSERVATIONS = 5000
_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_VERSION = re.compile(
    r"^(?:Nikto\s+)?2\.6\.\d{1,3}(?:[-+][A-Za-z0-9.-]{1,40})?"
    r"(?:\s+\([A-Za-z0-9 ._-]{1,80}\))?$",
    re.IGNORECASE,
)
_CVE_REFERENCE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_CWE_REFERENCE = re.compile(r"\bCWE-\d{1,6}\b", re.IGNORECASE)


def _report_origin(host: dict[str, Any]) -> str:
    """Build the origin Nikto stores beside path-only vulnerability URLs."""
    reported_host = host.get("host") or host.get("ip")
    if not isinstance(reported_host, str) or not reported_host.strip():
        raise ParseRejected("invalid-host-record")
    raw_host = reported_host.strip()
    if any(character in raw_host for character in "/?#@\\\r\n\t "):
        raise ParseRejected("invalid-host-record")
    try:
        parsed_host = urlsplit("//" + raw_host)
        hostname = parsed_host.hostname
        explicit_port = parsed_host.port
    except ValueError as error:
        raise ParseRejected("invalid-host-record") from error
    if not hostname or parsed_host.path or parsed_host.query or parsed_host.fragment:
        raise ParseRejected("invalid-host-record")
    reported_port = host.get("port")
    if reported_port is None:
        port = explicit_port
    else:
        try:
            port = int(reported_port)
        except (TypeError, ValueError) as error:
            raise ParseRejected("invalid-host-record") from error
        if explicit_port is not None and explicit_port != port:
            raise ParseRejected("invalid-host-record")
    scheme = "https" if isinstance(host.get("ssl_info"), dict) else "http"
    if port is not None and not 1 <= port <= 65535:
        raise ParseRejected("invalid-host-record")
    host_literal = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if scheme == "https" else 80
    authority = host_literal if port is None or port == default_port else f"{host_literal}:{port}"
    return canonical(f"{scheme}://{authority}")


def normalize_nikto(raw: bytes, version: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "state": "quarantined",
        "code": "malformed",
        "alerts": [],
        "assets": [],
        "parsed_records": 0,
    }
    try:
        if not 0 < len(raw) <= MAX_BYTES or not _VERSION.fullmatch(version):
            raise ParseRejected("unsupported-version-or-size")
        text = raw.decode("utf-8")
        depth = 0
        quoted = escaped = False
        for char in text:
            if quoted:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == '"':
                    quoted = False
            elif char == '"':
                quoted = True
            elif char in "[{":
                depth += 1
                if depth > MAX_DEPTH:
                    raise ParseRejected("depth-limit")
            elif char in "]}":
                depth -= 1
        data = json.loads(text, object_pairs_hook=_json_pairs, parse_constant=_bad_constant)
        stack, nodes = [data], 0
        while stack:
            value = stack.pop()
            nodes += 1
            if nodes > MAX_NODES:
                raise ParseRejected("structure-limit")
            if isinstance(value, str) and (
                len(value) > 65536 or any(ord(c) < 32 and c not in "\t\n\r" for c in value)
            ):
                raise ParseRejected("invalid-string")
            if isinstance(value, dict):
                stack.extend(value.keys())
                stack.extend(value.values())
            elif isinstance(value, list):
                stack.extend(value)
        if not isinstance(data, list) or len(data) > MAX_HOSTS:
            raise ParseRejected("unsupported-format-or-host-limit")
        alerts: list[dict[str, Any]] = []
        assets: set[str] = set()
        pointer_index = 0
        for host_index, host in enumerate(data):
            if not isinstance(host, dict) or not isinstance(host.get("vulnerabilities"), list):
                raise ParseRejected("invalid-host-record")
            origin: str | None = None
            for item_index, item in enumerate(host["vulnerabilities"]):
                pointer_index += 1
                if (
                    pointer_index > MAX_OBSERVATIONS
                    or not isinstance(item, dict)
                    or not isinstance(item.get("url"), str)
                ):
                    raise ParseRejected("observation-limit-or-shape")
                reported_uri = item["url"]
                reported_parts = urlsplit(reported_uri)
                if reported_parts.scheme:
                    uri = canonical(reported_uri)
                else:
                    if reported_parts.netloc or not reported_parts.path:
                        raise ParseRejected("invalid-observation-url-or-method")
                    if origin is None:
                        origin = _report_origin(host)
                    relative_path = reported_parts.path
                    if not relative_path.startswith("/"):
                        relative_path = "/" + relative_path
                    uri = canonical(
                        origin.rstrip("/")
                        + relative_path
                        + ("?" + reported_parts.query if reported_parts.query else "")
                    )
                parsed = urlsplit(uri)
                method = str(item.get("method", "GET")).upper()
                if (
                    parsed.scheme not in {"http", "https"}
                    or not parsed.hostname
                    or method not in _METHODS
                ):
                    raise ParseRejected("invalid-observation-url-or-method")
                # Query strings can carry credentials or personal data; keep them only
                # in the encrypted original evidence and scope against the safe endpoint.
                safe_uri = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
                assets.add(safe_uri)
                references = item.get("references")
                reference_text = references if isinstance(references, str) else ""
                cve_references = sorted(
                    {match.group(0).upper() for match in _CVE_REFERENCE.finditer(reference_text)}
                )
                cwe_references = sorted(
                    {match.group(0).upper() for match in _CWE_REFERENCE.finditer(reference_text)}
                )
                alerts.append(
                    {
                        "classification": "server-configuration-observation",
                        "plugin_id": str(item.get("id", ""))[:100],
                        "alert_ref": str(references or "")[:100],
                        # These are identifiers explicitly reported by Nikto, not
                        # independently validated CVE/CWE assignments. Leave an
                        # ambiguous multi-reference value unmapped for correlation.
                        "cve": cve_references[0] if len(cve_references) == 1 else None,
                        "cwe": cwe_references[0] if len(cwe_references) == 1 else None,
                        "cve_references": cve_references,
                        "cwe_references": cwe_references,
                        "name": str(item.get("msg", "Nikto server observation"))[:500],
                        "risk": "unknown",
                        "confidence_label": "unknown",
                        "instances": [
                            {
                                "uri": safe_uri,
                                "origin": f"{parsed.scheme}://{parsed.netloc}",
                                "path": parsed.path or "/",
                                "method": method,
                                "pointer": f"/{host_index}/vulnerabilities/{item_index}",
                            }
                        ],
                        "pointer": f"/{host_index}/vulnerabilities/{item_index}",
                    }
                )
        if len(assets) > MAX_ASSETS:
            raise ParseRejected("asset-limit")
        result.update(
            state="normalized",
            code="ok" if alerts else "no-observations",
            alerts=alerts,
            assets=sorted(assets),
            parsed_records=len(alerts),
        )
    except ParseRejected as error:
        result.update(code=str(error), alerts=[], assets=[], parsed_records=0)
    except (ValueError, KeyError, UnicodeError, RecursionError):
        result.update(code="malformed", alerts=[], assets=[], parsed_records=0)
    except Exception:
        result.update(code="unsafe-or-malformed", alerts=[], assets=[], parsed_records=0)
    return result

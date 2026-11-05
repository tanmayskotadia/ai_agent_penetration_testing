"""Bounded OWASP ZAP Alerts JSON normalizer for privately supplied evidence."""

import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit

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

MAX_ALERTS = 1000
MAX_INSTANCES = 5000
_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_VERSION = re.compile(r"^2\.\d{1,2}\.\d{1,3}(?:[-+][A-Za-z0-9.-]{1,40})?$")
_PARAMETER_NAME = re.compile(r"^[A-Za-z0-9_.\[\]-]{1,100}$")
_CVE = re.compile(r"^CVE-[0-9]{4}-[0-9]{4,}$", re.IGNORECASE)
_CWE = re.compile(r"^CWE-[0-9]{1,6}$", re.IGNORECASE)


def _source_cwe(value: Any) -> str | None:
    if type(value) is int and 1 <= value <= 999999:
        return f"CWE-{value}"
    if isinstance(value, str) and _CWE.fullmatch(value.strip()):
        return value.strip().upper()
    return None


def _source_cve(value: Any) -> str | None:
    if isinstance(value, str) and _CVE.fullmatch(value.strip()):
        return value.strip().upper()
    return None


def _parameter_names(uri: str, *labels: Any) -> list[str]:
    """Return bounded parameter names only; never copy their values to normalized data."""
    names: set[str] = set()
    try:
        names.update(
            key
            for key, _ in parse_qsl(urlsplit(uri).query, keep_blank_values=True, max_num_fields=50)
        )
    except ValueError:
        return []
    for label in labels:
        if not isinstance(label, str):
            continue
        # ZAP's `param` is normally a name, but may contain an assignment. Treat anything
        # after the first equals sign as secret evidence and discard it.
        candidate = label.split("=", 1)[0].strip()
        if candidate:
            names.add(candidate)
    return sorted(name for name in names if _PARAMETER_NAME.fullmatch(name))[:50]


def _traditional_alerts(data: Any) -> dict[str, Any] | None:
    """Project ZAP's traditional report onto the Alerts API shape without payload fields."""
    if not isinstance(data, dict) or set(data) - {
        "@version",
        "@generated",
        "created",
        "site",
        "insights",
        "sequences",
        "about",
        "statistics",
        "reportParameters",
    }:
        return None
    sites = data.get("site")
    if not isinstance(sites, list) or len(sites) > MAX_ASSETS:
        return None
    projected: list[dict[str, Any]] = []
    instance_count = 0
    for site in sites:
        if not isinstance(site, dict) or not isinstance(site.get("alerts", []), list):
            return None
        alerts = site.get("alerts", [])
        if len(alerts) > MAX_ALERTS:
            return None
        for alert in alerts:
            if not isinstance(alert, dict) or not isinstance(alert.get("instances", []), list):
                return None
            instances = []
            for instance in alert.get("instances", []):
                instance_count += 1
                if instance_count > MAX_INSTANCES or not isinstance(instance, dict):
                    return None
                # Do not copy `attack`, `evidence`, `otherinfo`, descriptions or responses.
                instances.append(
                    {
                        "uri": instance.get("uri"),
                        "method": instance.get("method", "GET"),
                        "param": instance.get("param"),
                    }
                )
            projected.append(
                {
                    "id": alert.get("pluginid", ""),
                    "pluginId": alert.get("pluginid", ""),
                    "alertRef": alert.get("alertRef", ""),
                    "alert": alert.get("alert", alert.get("name", "Unlabelled ZAP alert")),
                    "riskdesc": alert.get("riskdesc", "unknown"),
                    "confidence": alert.get("confidence", "unknown"),
                    "cweid": alert.get("cweid", alert.get("cwe")),
                    "cve": alert.get("cve"),
                    "instances": instances,
                }
            )
    return {"alerts": projected}


def normalize_zap(raw: bytes, version: str) -> dict[str, Any]:
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
        if isinstance(data, dict) and set(data) == {"alerts"}:
            pass
        else:
            data = _traditional_alerts(data)
            if data is None:
                raise ParseRejected("unsupported-format")
        if not isinstance(data.get("alerts"), list):
            raise ParseRejected("unsupported-format")
        if len(data["alerts"]) > MAX_ALERTS:
            raise ParseRejected("alert-limit")
        alerts: list[dict[str, Any]] = []
        assets: set[str] = set()
        instance_count = 0
        for index, alert in enumerate(data["alerts"]):
            if not isinstance(alert, dict) or not isinstance(alert.get("instances", []), list):
                raise ParseRejected("invalid-alert")
            instances = alert.get("instances", [])
            if not instances and isinstance(alert.get("url"), str):
                instances = [{"uri": alert["url"], "method": "GET"}]
            normalized_instances = []
            for occurrence, instance in enumerate(instances):
                instance_count += 1
                if instance_count > MAX_INSTANCES or not isinstance(instance, dict):
                    raise ParseRejected("instance-limit-or-shape")
                uri = instance.get("uri", alert.get("url"))
                method = str(instance.get("method", "GET")).upper()
                if not isinstance(uri, str) or method not in _METHODS:
                    raise ParseRejected("invalid-instance")
                canonical_uri = canonical(uri)
                parsed = urlsplit(canonical_uri)
                if parsed.scheme not in {"http", "https"} or not parsed.hostname:
                    raise ParseRejected("invalid-instance-url")
                origin = f"{parsed.scheme}://{parsed.netloc}"
                safe_uri = f"{origin}{parsed.path or '/'}"
                assets.add(safe_uri)
                normalized_instances.append(
                    {
                        "uri": safe_uri,
                        "origin": origin,
                        "path": parsed.path or "/",
                        "method": method,
                        "parameter_names": _parameter_names(
                            canonical_uri, instance.get("param"), alert.get("param")
                        ),
                        "request_response_evidence": "encrypted-original-only",
                        "pointer": f"/alerts/{index}/instances/{occurrence}",
                    }
                )
            if not normalized_instances:
                continue
            # Retain scanner identifiers and source labels. Descriptions, request/response
            # bodies, parameters and URLs with query strings stay only in encrypted evidence.
            alerts.append(
                {
                    "alert_id": str(alert.get("id", ""))[:100],
                    "plugin_id": str(alert.get("pluginId", ""))[:100],
                    "alert_ref": str(alert.get("alertRef", ""))[:100],
                    "name": str(alert.get("alert", "Unlabelled ZAP alert"))[:500],
                    "risk": str(alert.get("riskdesc", alert.get("risk", "unknown")))[:100],
                    "confidence_label": str(alert.get("confidence", "unknown"))[:100],
                    "cwe": _source_cwe(alert.get("cweid", alert.get("cwe"))),
                    "cve": _source_cve(alert.get("cve")),
                    "parameter_names": sorted(
                        {name for item in normalized_instances for name in item["parameter_names"]}
                    )[:50],
                    "instances": normalized_instances,
                    "pointer": f"/alerts/{index}",
                }
            )
        if not assets:
            raise ParseRejected("asset-mapping-unavailable")
        result.update(
            state="normalized",
            code="ok",
            alerts=alerts,
            assets=sorted(assets)[:MAX_ASSETS],
            parsed_records=len(alerts),
        )
        if len(assets) > MAX_ASSETS:
            raise ParseRejected("asset-limit")
    except ParseRejected as error:
        result.update(code=str(error), alerts=[], assets=[], parsed_records=0)
    except (ValueError, KeyError, UnicodeError, RecursionError):
        result.update(code="malformed", alerts=[], assets=[], parsed_records=0)
    except Exception:
        result.update(code="unsafe-or-malformed", alerts=[], assets=[], parsed_records=0)
    return result

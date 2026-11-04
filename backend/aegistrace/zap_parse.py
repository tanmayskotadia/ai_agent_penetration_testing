"""Bounded OWASP ZAP Alerts JSON normalizer for privately supplied evidence."""

import json
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

MAX_ALERTS = 1000
MAX_INSTANCES = 5000
_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}


def normalize_zap(raw: bytes, version: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "state": "quarantined",
        "code": "malformed",
        "alerts": [],
        "assets": [],
        "parsed_records": 0,
    }
    try:
        if not 0 < len(raw) <= MAX_BYTES or not version.startswith("2."):
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
        if (
            not isinstance(data, dict)
            or set(data) != {"alerts"}
            or not isinstance(data["alerts"], list)
        ):
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
                assets.add(canonical_uri)
                normalized_instances.append(
                    {
                        "uri": canonical_uri,
                        "origin": origin,
                        "path": parsed.path or "/",
                        "method": method,
                        "pointer": f"/alerts/{index}/instances/{occurrence}",
                    }
                )
            if not normalized_instances:
                continue
            # Retain scanner identifiers and source labels. Descriptions, request/response
            # bodies, parameters and URLs with query strings stay only in encrypted evidence.
            alerts.append(
                {
                    "plugin_id": str(alert.get("pluginId", ""))[:100],
                    "alert_ref": str(alert.get("alertRef", ""))[:100],
                    "name": str(alert.get("alert", "Unlabelled ZAP alert"))[:500],
                    "risk": str(alert.get("riskdesc", alert.get("risk", "unknown")))[:100],
                    "confidence_label": str(alert.get("confidence", "unknown"))[:100],
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

"""Offline OpenAPI 3.x operation catalog extraction; no URL is fetched."""

import json
from typing import Any
from urllib.parse import urlsplit, urlunsplit

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

_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
MAX_OPERATIONS = 200


def server_bases(servers: Any) -> list[str]:
    """Validate each effective server, including operation/path overrides."""
    if not isinstance(servers, list) or not servers or len(servers) > MAX_ASSETS:
        raise ParseRejected("server-list-required-or-limit")
    bases = []
    for server in servers:
        if not isinstance(server, dict) or not isinstance(server.get("url"), str):
            raise ParseRejected("invalid-server")
        template = server["url"]
        if "{" in template or "}" in template:
            raise ParseRejected("server-variables-unsupported")
        base = canonical(template)
        parsed = urlsplit(base)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.query:
            raise ParseRejected("invalid-server-url")
        bases.append(urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rstrip("/"), "", "")))
    return bases


def parse_openapi(raw: bytes, version: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "state": "quarantined",
        "code": "malformed",
        "operations": [],
        "assets": [],
        "parsed_records": 0,
        "security_schemes": [],
    }
    try:
        if not 0 < len(raw) <= MAX_BYTES:
            raise ParseRejected("size-limit")
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
            or data.get("openapi") != version
            or not version.startswith(("3.0.", "3.1."))
            or not isinstance(data.get("paths"), dict)
        ):
            raise ParseRejected("unsupported-openapi-version-or-shape")
        servers = data.get("servers")
        bases = server_bases(servers)
        # Include declared servers even when an operation overrides them: scope
        # review must see every declared destination, not only selected URLs.
        declared_assets = set(bases)
        security_schemes = (
            data.get("components", {}).get("securitySchemes", {})
            if isinstance(data.get("components", {}), dict)
            else {}
        )
        if not isinstance(security_schemes, dict) or len(security_schemes) > 100:
            raise ParseRejected("invalid-security-schemes")
        operations = []
        assets: set[str] = set()
        global_security = data.get("security", [])
        for path, path_item in data["paths"].items():
            if (
                not isinstance(path, str)
                or not path.startswith("/")
                or not isinstance(path_item, dict)
            ):
                raise ParseRejected("invalid-path-item")
            if "$ref" in path_item:
                raise ParseRejected("path-references-unsupported")
            path_servers = path_item.get("servers", servers)
            declared_assets.update(server_bases(path_servers))
            for method, operation in path_item.items():
                if method.lower() not in _METHODS:
                    continue
                if not isinstance(operation, dict):
                    raise ParseRejected("invalid-operation")
                operation_bases = server_bases(operation.get("servers", path_servers))
                declared_assets.update(operation_bases)
                security = operation.get("security", global_security)
                if not isinstance(security, list):
                    raise ParseRejected("invalid-operation-security")
                if any(not isinstance(item, dict) for item in security):
                    raise ParseRejected("invalid-operation-security")
                if any(
                    not isinstance(scopes, list)
                    or any(not isinstance(scope, str) for scope in scopes)
                    for item in security
                    for scopes in item.values()
                ):
                    raise ParseRejected("invalid-operation-security")
                auth_names = sorted(
                    {
                        name
                        for item in security
                        if isinstance(item, dict)
                        for name in item
                        if isinstance(name, str)
                    }
                )
                if any(name not in security_schemes for name in auth_names):
                    raise ParseRejected("unresolved-security-scheme")
                for server_index, base in enumerate(operation_bases):
                    full = canonical(base.rstrip("/") + path)
                    parsed = urlsplit(full)
                    origin = f"{parsed.scheme}://{parsed.netloc}"
                    assets.add(full)
                    operations.append(
                        {
                            "url": full,
                            "origin": origin,
                            "path": parsed.path or "/",
                            "method": method.upper(),
                            "authentication_required": bool(security) and {} not in security,
                            "security_alternatives": security,
                            "security_schemes": auth_names,
                            "pointer": f"/paths/{path}/{method}",
                            "server_index": server_index,
                        }
                    )
                    if len(operations) > MAX_OPERATIONS:
                        raise ParseRejected("operation-limit")
        if not operations:
            raise ParseRejected("no-supported-operations")
        assets.update(declared_assets)
        if len(assets) > MAX_ASSETS:
            raise ParseRejected("asset-limit")
        result.update(
            state="normalized",
            code="ok",
            operations=operations,
            assets=sorted(assets),
            parsed_records=len(operations),
            security_schemes=sorted(security_schemes),
            security_scheme_definitions={
                name: {
                    field: scheme[field]
                    for field in ("type", "scheme", "in", "name")
                    if field in scheme and isinstance(scheme[field], str)
                }
                for name, scheme in security_schemes.items()
                if isinstance(scheme, dict)
            },
        )
    except ParseRejected as error:
        result.update(
            code=str(error), operations=[], assets=[], parsed_records=0, security_schemes=[]
        )
    except (ValueError, KeyError, UnicodeError, RecursionError):
        result.update(
            code="malformed", operations=[], assets=[], parsed_records=0, security_schemes=[]
        )
    except Exception:
        result.update(
            code="unsafe-or-malformed",
            operations=[],
            assets=[],
            parsed_records=0,
            security_schemes=[],
        )
    return result

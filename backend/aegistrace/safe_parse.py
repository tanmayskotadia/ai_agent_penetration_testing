"""Bounded container inspection only: never normalize findings or execute file content."""

import io
import ipaddress
import json
import multiprocessing as mp
import os
import socket
import sys
from multiprocessing.connection import Connection
from typing import Any
from urllib.parse import unquote, urlsplit

from defusedxml import ElementTree as SafeET

MAX_BYTES = 2097152
MAX_DEPTH = 32
MAX_NODES = 20000
MAX_ASSETS = 200
MAX_RESULT = 131072


class ParseRejected(ValueError):
    pass


def canonical(value: str) -> str:
    if not value or len(value) > 500 or any(ord(c) < 32 for c in value):
        raise ParseRejected("invalid-asset")
    if "://" in value:
        url = urlsplit(value)
        if (
            url.scheme not in {"http", "https"}
            or not url.hostname
            or url.username
            or url.password
            or url.fragment
        ):
            raise ParseRejected("invalid-url")
        host = url.hostname.lower().rstrip(".")
        decoded_path = url.path
        for _ in range(3):
            decoded_path = unquote(decoded_path)
        if "\\" in decoded_path or any(part in {".", ".."} for part in decoded_path.split("/")):
            raise ParseRejected("ambiguous-url-path")
        port = url.port
        host = f"[{host}]" if ":" in host else host
        authority = host if port is None else f"{host}:{port}"
        return f"{url.scheme}://{authority}{url.path or '/'}" + (
            "?" + url.query if url.query else ""
        )
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return value.lower().rstrip(".")


def matches(asset: str, target: str) -> bool:
    asset, target = canonical(asset), canonical(target)
    if asset == target:
        return True
    if "/" in target and "://" not in target:
        try:
            address = urlsplit(asset).hostname if "://" in asset else asset
            return ipaddress.ip_address(address or "") in ipaddress.ip_network(target, strict=True)
        except ValueError:
            return False
    if "://" in asset:
        url = urlsplit(asset)
        if "://" not in target:
            return url.hostname == target
        scope = urlsplit(target)
        if (url.scheme, url.hostname, url.port or (443 if url.scheme == "https" else 80)) != (
            scope.scheme,
            scope.hostname,
            scope.port or (443 if scope.scheme == "https" else 80),
        ):
            return False
        if scope.query and scope.query != url.query:
            return False
        base = scope.path.rstrip("/")
        return url.path == base or url.path.startswith(base + "/")
    return False


def mapped_assets(
    assets: list[str], targets: list[str], exclusions: list[str], mapping: dict[str, str]
) -> tuple[list[str], list[str]]:
    accepted, rejected = [], []
    for source in assets:
        mapped = mapping.get(source, source)
        if any(
            matches(source, exclusion) or matches(mapped, exclusion) for exclusion in exclusions
        ) or not any(matches(mapped, target) for target in targets):
            rejected.append(source)
        else:
            accepted.append(source)
    return accepted, rejected


def _json_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ParseRejected("duplicate-json-key")
        result[key] = value
    return result


def _bad_constant(_: str) -> None:
    raise ParseRejected("invalid-json-number")


def _json_depth(raw: str) -> None:
    depth = 0
    quoted = escaped = False
    for char in raw:
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


def inspect_container(raw: bytes, tool: str, format_name: str, tool_version: str) -> dict[str, Any]:
    assets: set[str] = set()
    records = 0
    result: dict[str, Any] = {
        "state": "quarantined",
        "code": "malformed",
        "assets": [],
        "parsed_records": 0,
    }
    try:
        if not 0 < len(raw) <= MAX_BYTES:
            raise ParseRejected("size-limit")
        if raw.startswith((b"PK", b"\x1f\x8b", b"BZh", b"\xfd7zXZ")):
            raise ParseRejected("archives-unsupported")
        if (tool, format_name) == ("Nmap", "nmap-xml"):
            if not tool_version.startswith("7."):
                raise ParseRejected("unsupported-tool-version")
            depth = nodes = 0
            finished = False
            for event, node in SafeET.iterparse(
                io.BytesIO(raw),
                events=("start", "end"),
                forbid_dtd=False,
                forbid_entities=True,
                forbid_external=True,
            ):
                if event == "start":
                    depth += 1
                    nodes += 1
                    if depth > MAX_DEPTH or nodes > MAX_NODES or len(node.attrib) > 128:
                        raise ParseRejected("structure-limit")
                    if nodes == 1 and (
                        node.tag != "nmaprun"
                        or node.get("scanner") != "nmap"
                        or node.get("version") != tool_version
                        or node.get("xmloutputversion") not in {"1.03", "1.04", "1.05"}
                    ):
                        raise ParseRejected("unsupported-format-or-version")
                    if any(
                        len(value) > 65536 or any(ord(c) < 32 and c not in "\t\n\r" for c in value)
                        for value in node.attrib.values()
                    ):
                        raise ParseRejected("invalid-string")
                    if node.tag == "address" and node.get("addrtype") in {"ipv4", "ipv6"}:
                        assets.add(str(ipaddress.ip_address(node.attrib["addr"])))
                    if node.tag == "host":
                        records += 1
                    if node.tag == "finished":
                        finished = node.get("exit") == "success"
                else:
                    if node.text and len(node.text) > 65536:
                        raise ParseRejected("string-limit")
                    depth -= 1
                    node.clear()
                if len(assets) > MAX_ASSETS:
                    raise ParseRejected("asset-limit")
            if not finished:
                raise ParseRejected("partial-run")
        elif (tool, format_name) == ("OWASP ZAP", "zap-alerts-json"):
            if not tool_version.startswith("2."):
                raise ParseRejected("unsupported-tool-version")
            text = raw.decode("utf-8")
            _json_depth(text)
            data = json.loads(text, object_pairs_hook=_json_pairs, parse_constant=_bad_constant)
            stack = [data]
            nodes = 0
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
            for alert in data["alerts"]:
                if not isinstance(alert, dict) or not isinstance(alert.get("url"), str):
                    raise ParseRejected("missing-asset")
                assets.add(canonical(alert["url"]))
                records += 1
                if len(assets) > MAX_ASSETS:
                    raise ParseRejected("asset-limit")
        else:
            raise ParseRejected("unsupported-format")
        if not assets:
            raise ParseRejected("asset-mapping-unavailable")
        result.update(state="container-validated", code="normalizer-not-enabled")
    except ParseRejected as error:
        result["code"] = str(error)
    except (ValueError, KeyError, UnicodeError, SafeET.ParseError):
        result["code"] = "malformed"
    except Exception:
        # Parser exception messages can include untrusted source bytes; never return them.
        result["code"] = "unsafe-or-malformed"
    result.update(assets=sorted(assets)[:MAX_ASSETS], parsed_records=records)
    return result


def _deny_network(*_: Any, **__: Any) -> Any:
    raise RuntimeError("parser network access denied")


def _worker(pipe: Connection, raw: bytes, tool: str, format_name: str, version: str) -> None:
    os.environ.clear()
    socket.socket = _deny_network  # type: ignore[assignment,misc]
    socket.create_connection = _deny_network
    socket.getaddrinfo = _deny_network
    try:
        if sys.platform != "win32":
            import resource

            resource.setrlimit(resource.RLIMIT_CPU, (2, 3))
            resource.setrlimit(resource.RLIMIT_AS, (384 * 1024 * 1024, 384 * 1024 * 1024))
        payload = json.dumps(inspect_container(raw, tool, format_name, version)).encode()
        if len(payload) > MAX_RESULT:
            payload = (
                b'{"state":"quarantined","code":"result-limit","assets":[],"parsed_records":0}'
            )
        pipe.send_bytes(payload)
    finally:
        pipe.close()


def isolated_inspection(
    raw: bytes, tool: str, format_name: str, version: str, timeout: float = 3.0
) -> dict[str, Any]:
    if not 0 < len(raw) <= MAX_BYTES:
        return {"state": "quarantined", "code": "size-limit", "assets": [], "parsed_records": 0}
    context = mp.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(
        target=_worker, args=(child, raw, tool, format_name, version), daemon=True
    )
    process.start()
    child.close()
    try:
        if not parent.poll(timeout):
            return {
                "state": "quarantined",
                "code": "parse-timeout",
                "assets": [],
                "parsed_records": 0,
            }
        data = json.loads(parent.recv_bytes(MAX_RESULT))
        return dict(data)
    except (EOFError, OSError, ValueError):
        return {"state": "quarantined", "code": "parser-failed", "assets": [], "parsed_records": 0}
    finally:
        parent.close()
        process.join(0.1)
        if process.is_alive():
            process.terminate()
            process.join(1)
        if process.is_alive():
            process.kill()
            process.join(1)
        process.close()

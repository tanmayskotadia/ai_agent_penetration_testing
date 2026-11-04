"""Bounded candidate native XML normalizer. Does not execute Nmap or infer vulnerabilities."""

import io
import ipaddress
from typing import Any

from defusedxml import ElementTree as SafeET

from aegistrace.safe_parse import MAX_ASSETS, MAX_BYTES, MAX_DEPTH, MAX_NODES, ParseRejected


def normalize_nmap(raw: bytes, version: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "state": "quarantined",
        "code": "malformed",
        "hosts": [],
        "assets": [],
        "parsed_records": 0,
    }
    if not 0 < len(raw) <= MAX_BYTES or not version.startswith("7."):
        return result | {"code": "unsupported-version-or-size"}
    depth = nodes = ports = 0
    finished = False
    try:
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
                if nodes > MAX_NODES or depth > MAX_DEPTH or len(node.attrib) > 128:
                    raise ParseRejected("structure-limit")
                if nodes == 1 and (
                    node.tag != "nmaprun"
                    or node.get("scanner") != "nmap"
                    or node.get("version") != version
                    or node.get("xmloutputversion") not in {"1.03", "1.04", "1.05"}
                ):
                    raise ParseRejected("metadata-mismatch")
                if any(
                    len(value) > 4096 or any(ord(c) < 32 and c not in "\n\t\r" for c in value)
                    for value in node.attrib.values()
                ):
                    raise ParseRejected("string-limit")
            else:
                if node.tag == "finished":
                    finished = node.get("exit") == "success"
                if node.tag == "host":
                    addresses = sorted(
                        {
                            str(ipaddress.ip_address(value.attrib["addr"]))
                            for value in node.findall("address")
                            if value.get("addrtype") in {"ipv4", "ipv6"}
                        }
                    )
                    if not addresses or len(result["hosts"]) >= MAX_ASSETS:
                        raise ParseRejected("missing-address-or-host-limit")
                    entries = []
                    for index, port in enumerate(node.findall("./ports/port"), 1):
                        ports += 1
                        if ports > 256:
                            raise ParseRejected("port-limit")
                        protocol, number = port.get("protocol"), int(port.get("portid", "0"))
                        if protocol not in {"tcp", "udp"} or not 1 <= number <= 65535:
                            raise ParseRejected("unsupported-port")
                        state = port.find("state")
                        service = port.find("service")
                        state_name = (
                            state.get("state", "unknown") if state is not None else "unknown"
                        )
                        if state_name not in {
                            "open",
                            "closed",
                            "filtered",
                            "unfiltered",
                            "open|filtered",
                            "closed|filtered",
                            "unknown",
                        }:
                            state_name = "unknown"
                        entries.append(
                            {
                                "port": number,
                                "protocol": protocol,
                                "state": state_name,
                                "service": {
                                    key: service.get(key)
                                    for key in ["name", "product", "version", "method", "conf"]
                                }
                                if service is not None
                                else {},
                                "pointer": f"/nmaprun/host[{len(result['hosts']) + 1}]/ports/port[{index}]",
                            }
                        )
                    status = node.find("status")
                    result["hosts"].append(
                        {
                            "addresses": addresses,
                            "status": status.get("state", "unknown")
                            if status is not None
                            else "unknown",
                            "ports": entries,
                            "summarized_ports": [
                                {
                                    "state": value.get("state", "unknown"),
                                    "count": value.get("count"),
                                }
                                for value in node.findall("./ports/extraports")
                            ],
                        }
                    )
                    node.clear()
                depth -= 1
        result.update(
            state="normalized" if finished else "partial",
            code="ok" if finished else "tool-incomplete-or-error",
        )
    except SafeET.ParseError:
        result.update(
            state="partial" if result["hosts"] else "quarantined", code="truncated-or-malformed-xml"
        )
    except Exception:
        # Unsafe structures never publish even previously collected host data.
        return result | {
            "state": "quarantined",
            "code": "unsafe-or-unsupported",
            "hosts": [],
            "assets": [],
            "parsed_records": 0,
        }
    result["assets"] = sorted(
        {address for host in result["hosts"] for address in host["addresses"]}
    )
    if len(result["assets"]) > MAX_ASSETS:
        return result | {"state": "quarantined", "code": "asset-limit", "hosts": [], "assets": []}
    result["parsed_records"] = ports
    return result

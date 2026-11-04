"""Privileged namespace firewall. Fixed argv only; worker never receives NET_ADMIN."""

import ipaddress
import json
import os
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path


def rule(*args: str) -> None:
    subprocess.run(["iptables", "--wait", "5", *args], check=True)


def main() -> None:
    manifest = Path("/etc/aegistrace/egress.json")
    if manifest.stat().st_size > 65536:
        raise ValueError("oversized firewall manifest")
    config = json.loads(manifest.read_text())
    if config.get("schema_version") != "1.0" or not 1 <= len(config["allow"]) <= 256:
        raise ValueError("invalid firewall configuration")
    fixture = os.environ.get("CI_EGRESS_FIXTURE") == "1" and config.get("purpose", "").startswith(
        "CI connectivity fixture"
    )
    expiry = (
        None if fixture else datetime.fromisoformat(config["valid_until"].replace("Z", "+00:00"))
    )
    if expiry is not None and (expiry.tzinfo is None or expiry <= datetime.now(UTC)):
        raise ValueError("expired firewall manifest")
    # Fail closed before adding any exceptions. Worker starts only after ready marker.
    for chain in ["OUTPUT", "INPUT", "FORWARD"]:
        rule("-P", chain, "DROP")
    for chain in ["OUTPUT", "INPUT"]:
        rule("-F", chain)
        rule("-A", chain, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT")
    for entry in config["allow"]:
        address = ipaddress.ip_address(entry["address"])
        if (
            address.version != 4
            or address.is_link_local
            or address.is_loopback
            or address.is_multicast
            or address.is_unspecified
        ):
            raise ValueError("unsupported/protected firewall destination")
        if (
            type(entry["port"]) is not int
            or not 1 <= entry["port"] <= 65535
            or entry["protocol"] not in {"tcp", "udp"}
        ):
            raise ValueError("invalid firewall port or protocol")
        rule(
            "-A",
            "OUTPUT",
            "-d",
            str(address),
            "-p",
            entry["protocol"],
            "--dport",
            str(entry["port"]),
            "-j",
            "ACCEPT",
        )
    rule("-A", "OUTPUT", "-j", "REJECT")
    if Path("/proc/sys/net/ipv6/conf/all/disable_ipv6").read_text().strip() != "1":
        raise RuntimeError("IPv6 must be disabled in this IPv4-only worker profile")
    subprocess.run(["iptables", "--version"], check=True)
    Path("/run/aegistrace/ready").write_text("firewall-installed\n")
    while True:
        if expiry is not None and datetime.now(UTC) >= expiry:
            for chain in ["OUTPUT", "INPUT"]:
                rule("-F", chain)
            Path("/run/aegistrace/ready").unlink(missing_ok=True)
            return
        time.sleep(1)


if __name__ == "__main__":
    main()

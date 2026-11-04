"""Compile reviewed policy into exact IPv4 L4 permissions, never shell fragments."""

import ipaddress
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from aegistrace.policy import ExecutionPolicy, PolicyError, address_value, policy_digest


class CollectorEndpoint(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    address: str
    port: int = Field(ge=1, le=65535, strict=True)
    transport: Literal["mutual-tls"] = "mutual-tls"
    trust_reference: str = Field(min_length=1, max_length=500)


def compile_egress(
    policy: ExecutionPolicy, collector: CollectorEndpoint, protected_networks: tuple[str, ...]
) -> dict[str, Any]:
    rules = set()
    for target in policy.targets:
        for address in target.pinned_addresses:
            pin = ipaddress.ip_address(address_value(address))
            if pin.version != 4:
                raise PolicyError("IPv6 is disabled in this worker deployment profile")
            if any(
                pin in ipaddress.ip_network(network, strict=True) for network in protected_networks
            ):
                raise PolicyError("control-plane target forbidden")
            rules.add((str(pin), target.port, "udp" if target.protocol == "udp" else "tcp"))
    collector_ip = ipaddress.ip_address(address_value(collector.address))
    if collector_ip.version != 4 or not collector_ip.is_private:
        raise PolicyError("collector must be a private pinned IPv4 endpoint")
    rules.add((str(collector_ip), collector.port, "tcp"))
    return {
        "schema_version": "1.0",
        "assessment_id": str(policy.assessment_id),
        "scope_revision": policy.scope_revision,
        "policy_digest": policy_digest(policy),
        "valid_until": policy.valid_until.isoformat(),
        "collector_trust_reference": collector.trust_reference,
        "allow": [
            {"address": address, "port": port, "protocol": protocol}
            for address, port, protocol in sorted(rules)
        ],
    }

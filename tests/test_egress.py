"""Policy compiler tests; actual Linux kernel probes execute in hosted CI."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
import yaml
from aegistrace.egress import CollectorEndpoint, compile_egress
from aegistrace.policy import ExecutionPolicy, PolicyError


def test_compiler_pins_ports_requires_private_collector_and_denies_control_plane():
    now = datetime.now(UTC)
    policy = ExecutionPolicy(
        assessment_id=uuid4(),
        scope_id=uuid4(),
        scope_revision=1,
        context="general",
        authorization_source="asset-owner",
        authorization_reference="TEST ONLY",
        authorization_document_sha256="a" * 64,
        reviewed_by="TEST ONLY",
        valid_from=now - timedelta(minutes=1),
        valid_until=now + timedelta(hours=1),
        targets=(
            {
                "host": "192.0.2.10",
                "protocol": "http",
                "port": 8080,
                "pinned_addresses": ["192.0.2.10"],
            },
        ),
        allowed_networks=("192.0.2.0/24",),
        allowed_profiles=("discovery",),
        requests_per_second=2,
        concurrent_jobs=1,
    )
    collector = CollectorEndpoint(
        address="10.254.240.20",
        port=8443,
        trust_reference="TEST ONLY; real TLS provisioned separately",
    )
    rules = compile_egress(policy, collector, ())
    assert len(rules["allow"]) == 2 and {r["port"] for r in rules["allow"]} == {8080, 8443}
    with pytest.raises(PolicyError):
        compile_egress(policy, collector, ("192.0.2.0/24",))
    with pytest.raises(PolicyError):
        compile_egress(policy, collector.model_copy(update={"address": "8.8.8.8"}), ())


def test_worker_profile_has_no_socket_or_privileged_capabilities():
    from pathlib import Path

    config = yaml.safe_load(Path("compose.security.yaml").read_text())
    worker = config["services"]["probe"]
    assert worker["cap_drop"] == ["ALL"] and worker["read_only"]
    assert worker["network_mode"] == "service:gateway" and "networks" not in worker
    assert all("docker.sock" not in volume for volume in worker["volumes"])
    assert config["networks"]["lab"]["internal"]

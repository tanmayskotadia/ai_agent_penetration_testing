"""Fixed native argv templates. No caller/model-selected executable or shell string."""

import hashlib
import ipaddress
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from aegistrace.approval_schema import claims, grants
from aegistrace.approvals import ActionRequest, reviewer_current, verify_snapshot
from aegistrace.capabilities import DEFAULT_REGISTRY, CapabilityRegistry
from aegistrace.control import require_running
from aegistrace.control_schema import executions
from aegistrace.policy import Destination, PolicyError, authorize, load_policy
from aegistrace.settings import Settings
from sqlalchemy import Connection, select


@dataclass(frozen=True)
class RegisteredExecutable:
    path: Path
    sha256: str
    version: str


@dataclass(frozen=True)
class BuiltCommand:
    claim_id: UUID
    argv: tuple[str, ...]
    max_runtime_seconds: float
    action_digest: str


def nmap_arguments(path: Path, destination: Destination, timeout_seconds: int) -> tuple[str, ...]:
    if (
        destination.protocol == "udp"
        or not destination.pinned_addresses
        or type(timeout_seconds) is not int
        or not 1 <= timeout_seconds <= 30
    ):
        raise PolicyError("unsupported Nmap transport or timeout")
    pins = tuple(str(ipaddress.ip_address(value)) for value in destination.pinned_addresses)
    if any(ipaddress.ip_address(value).version != 4 for value in pins):
        raise PolicyError("IPv6 execution is not enabled in this runtime profile")
    return (
        str(path),
        "-sT",
        "-Pn",
        "-n",
        "--max-retries",
        "1",
        "--host-timeout",
        str(timeout_seconds) + "s",
        "-p",
        str(destination.port),
        "-oX",
        "-",
        "--",
        *pins,
    )


def build_command(
    connection: Connection,
    config: Settings,
    claim_id: UUID,
    worker_id: UUID,
    epoch: int,
    executables: Mapping[str, RegisteredExecutable],
    registry: CapabilityRegistry = DEFAULT_REGISTRY,
) -> BuiltCommand:
    row = connection.execute(select(claims).where(claims.c.id == str(claim_id))).mappings().one()
    payload = row["payload"]
    assessment_id = UUID(row["assessment_id"])
    require_running(connection, assessment_id)
    execution = (
        connection.execute(select(executions).where(executions.c.claim_id == str(claim_id)))
        .mappings()
        .one_or_none()
    )
    if (
        execution is None
        or execution["worker_id"] != str(worker_id)
        or execution["epoch"] != epoch
        or execution["lease_until"] <= time.time()
        or execution["state"] != "running"
        or payload["state"] != "running"
    ):
        raise PolicyError("current worker lease required")
    approval = (
        connection.execute(select(grants).where(grants.c.id == row["approval_id"])).mappings().one()
    )
    verify_snapshot(approval)
    if (
        approval["state"] != "consumed"
        or not reviewer_current(connection, approval, config)
        or approval["action_digest"] != payload["action_digest"]
        or approval["payload"]["action"] != payload["action"]
    ):
        raise PolicyError("human authority changed")
    action = ActionRequest.model_validate(payload["action"])
    policy = load_policy(connection, assessment_id, action.policy_id)
    destination = authorize(
        policy,
        action.destination_url,
        action.profile,
        protected_networks=config.control_plane_networks,
    )
    capability = next(value for value in registry.snapshot() if value["name"] == action.tool)
    if (
        capability["mode"] != "live"
        or action.template != "nmap.connect.v1"
        or set(action.parameters) - {"timeout_seconds"}
    ):
        raise PolicyError("verified native template unavailable; execution stays disabled")
    executable = executables.get(action.tool)
    if (
        executable is None
        or executable.version != capability["installed_version"]
        or not executable.path.is_absolute()
        or executable.path.is_symlink()
        or not executable.path.is_file()
        or executable.path.stat().st_size > 52428800
        or hashlib.sha256(executable.path.read_bytes()).hexdigest() != executable.sha256
    ):
        raise PolicyError("registered executable identity unavailable or changed")
    remaining = min(execution["deadline"] - time.time(), action.max_runtime_seconds)
    if remaining <= 0:
        raise PolicyError("execution deadline expired")
    return BuiltCommand(
        claim_id,
        nmap_arguments(
            executable.path,
            destination,
            min(action.parameters.get("timeout_seconds", 5), max(1, int(remaining))),
        ),
        remaining,
        payload["action_digest"],
    )

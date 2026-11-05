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
from aegistrace.policy import destination as parse_destination
from aegistrace.settings import Settings
from sqlalchemy import Connection, select

from aegistrace_workers.adapters.web_scanners import (
    PinnedBinary,
    nikto_arguments,
    serialize_zap_plan,
    zap_arguments,
    zap_automation_plan,
)


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
    artifact_path: Path | None = None


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
    *,
    output_directory: Path | None = None,
    proxy_url: str | None = None,
    har_filename: str | None = None,
    allow_unverified_web_candidate: bool = False,
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
    supported_templates = {
        "Nmap": {"nmap.connect.v1"},
        "Nikto": {"nikto.active.v1"},
        "OWASP ZAP": {"zap.passive.v1", "zap.active.v1"},
    }
    verified_live = capability["mode"] == "live"
    explicitly_enabled_candidate = (
        allow_unverified_web_candidate
        and capability["mode"] == "planned"
        and action.tool in {"Nikto", "OWASP ZAP"}
        and action.template in {"nikto.active.v1", "zap.passive.v1", "zap.active.v1"}
    )
    if (
        not (verified_live or explicitly_enabled_candidate)
        or action.template not in supported_templates.get(action.tool, set())
    ):
        raise PolicyError("verified native template unavailable; execution stays disabled")
    executable = executables.get(action.tool)
    if (
        executable is None
        or (
            capability["installed_version"] is not None
            and executable.version != capability["installed_version"]
        )
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
    if action.template == "nmap.connect.v1":
        if set(action.parameters) - {"timeout_seconds"}:
            raise PolicyError("unsupported Nmap parameters")
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

    if output_directory is None or not output_directory.is_absolute() or output_directory.is_symlink():
        raise PolicyError("private scanner output workspace required")
    if not output_directory.is_dir():
        raise PolicyError("scanner output workspace must already exist")
    if not 1 <= int(remaining) <= 300:
        raise PolicyError("scanner runtime limit")
    excluded_paths = tuple(
        rule.path
        for value in policy.exclusions
        if "://" in value
        for rule in (parse_destination(value),)
        if (rule.host, rule.protocol, rule.port)
        == (destination.host, destination.protocol, destination.port)
    )
    scanner_binary = PinnedBinary(executable.path, executable.sha256)
    if action.template == "nikto.active.v1":
        if set(action.parameters) - {"timeout_seconds", "max_redirects"}:
            raise PolicyError("unsupported Nikto parameters")
        if destination.path != "/" or excluded_paths:
            raise PolicyError("Nikto cannot enforce this path scope")
        if proxy_url is None:
            raise PolicyError("per-job pinned egress proxy required")
        artifact = output_directory / "nikto.json"
        if artifact.exists() or artifact.is_symlink():
            raise PolicyError("scanner artifact path is not fresh")
        argv = nikto_arguments(
            scanner_binary,
            destination,
            artifact,
            proxy_url,
            runtime_seconds=max(1, int(remaining)),
            requests_per_second=policy.requests_per_second,
            excluded_paths=excluded_paths,
        )
    elif action.template in {"zap.passive.v1", "zap.active.v1"}:
        if set(action.parameters) - {"timeout_seconds", "max_redirects"}:
            raise PolicyError("unsupported ZAP parameters")
        passive = action.template == "zap.passive.v1"
        if passive and (proxy_url is not None or not har_filename):
            raise PolicyError("passive ZAP requires a recorded HAR and no network proxy")
        if not passive and proxy_url is None:
            raise PolicyError("per-job pinned egress proxy required")
        artifact = output_directory / "zap-report.json"
        if artifact.exists() or artifact.is_symlink():
            raise PolicyError("scanner artifact path is not fresh")
        plan = zap_automation_plan(
            destination,
            "passive-web" if passive else "active-web",
            report_directory=output_directory,
            included_paths=(destination.path,),
            excluded_paths=excluded_paths,
            runtime_seconds=max(1, int(remaining)),
            requests_per_second=policy.requests_per_second,
            proxy_url=proxy_url,
            har_filename=har_filename,
        )
        plan_path = output_directory / "zap-plan.yaml"
        serialize_zap_plan(plan, plan_path)
        argv = zap_arguments(scanner_binary, plan_path)
    else:
        raise PolicyError("unavailable scanner template")
    return BuiltCommand(
        claim_id,
        argv,
        remaining,
        payload["action_digest"],
        artifact,
    )

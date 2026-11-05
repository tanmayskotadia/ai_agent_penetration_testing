"""Fixed, bounded command plans for optional Nikto and ZAP worker runtimes.

These helpers never infer permission from their presence. Callers must verify the
single-use approval, current scope, egress gate and registered tool capability
before dispatch. The deployment network must deny direct scanner egress and route
target traffic through the per-job policy gateway.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit, urlunsplit

import yaml
from aegistrace.policy import Destination, PolicyError

from aegistrace_workers.process_control import ProcessOutcome, run_managed

MAX_ARTIFACT_BYTES = 2 * 1024 * 1024
_NIKTO_VERSION = re.compile(r"\bNikto\s+(2\.6\.\d{1,3})\b", re.IGNORECASE)
_ZAP_VERSION = re.compile(r"\bZAP\s+Version\s*:?\s*(2\.\d{1,2}\.\d{1,3})\b", re.IGNORECASE)


@dataclass(frozen=True)
class PinnedBinary:
    path: Path
    sha256: str


@dataclass(frozen=True)
class ScannerVersion:
    tool: Literal["Nikto", "OWASP ZAP"]
    version: str


def verify_binary(binary: PinnedBinary) -> Path:
    """Check an operator-pinned launcher without printing its path or contents."""
    path = binary.path
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not path.is_file()
        or not 0 < path.stat().st_size <= 52_428_800
        or not re.fullmatch(r"[a-f0-9]{64}", binary.sha256)
    ):
        raise PolicyError("pinned scanner launcher required")
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    if digest != binary.sha256:
        raise PolicyError("scanner launcher digest changed")
    return path


def discover_version(binary: PinnedBinary, tool: Literal["Nikto", "OWASP ZAP"]) -> ScannerVersion:
    path = verify_binary(binary)
    argv = (str(path), "-Version") if tool == "Nikto" else (str(path), "-version")
    env = {
        name: value
        for name, value in os.environ.items()
        if name in {"PATH", "SYSTEMROOT", "WINDIR", "LANG", "LC_ALL", "JAVA_HOME"}
    }
    try:
        result = subprocess.run(
            argv,
            shell=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=8,
            check=False,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PolicyError("scanner version probe failed") from error
    output = result.stdout[:65536].decode("utf-8", errors="replace")
    pattern = _NIKTO_VERSION if tool == "Nikto" else _ZAP_VERSION
    match = pattern.search(output)
    if result.returncode != 0 or match is None:
        raise PolicyError("scanner version is unsupported or unverifiable")
    return ScannerVersion(tool, match.group(1))


def _target(destination: Destination) -> str:
    if destination.protocol not in {"http", "https"} or not destination.pinned_addresses:
        raise PolicyError("pinned HTTP(S) target required")
    if not destination.path.startswith("/") or any(char in destination.path for char in "?#\\"):
        raise PolicyError("path-only target required")
    host = f"[{destination.host}]" if ":" in destination.host else destination.host
    default_port = 443 if destination.protocol == "https" else 80
    authority = host if destination.port == default_port else f"{host}:{destination.port}"
    return urlunsplit((destination.protocol, authority, destination.path, "", ""))


def nikto_arguments(
    binary: PinnedBinary,
    destination: Destination,
    output_file: Path,
    proxy_url: str,
    *,
    runtime_seconds: int,
    requests_per_second: int,
    excluded_paths: tuple[str, ...] = (),
) -> tuple[str, ...]:
    """Return a bounded Nikto plan; unsupported exclusions are refused, never guessed."""
    executable = verify_binary(binary)
    target = _target(destination)
    proxy = urlsplit(proxy_url)
    if (
        type(runtime_seconds) is not int
        or not 1 <= runtime_seconds <= 300
        or type(requests_per_second) is not int
        or not 1 <= requests_per_second <= 10
        or excluded_paths
        or not output_file.is_absolute()
        or output_file.is_symlink()
        or not output_file.parent.is_dir()
        or proxy.scheme != "http"
        or proxy.hostname != "127.0.0.1"
        or proxy.port is None
        or proxy.path not in {"", "/"}
        or proxy.query
        or proxy.fragment
    ):
        raise PolicyError("unsupported Nikto scope or unbounded runtime setting")
    return (
        str(executable),
        "-host",
        target,
        "-useproxy",
        proxy_url,
        "-nocheck",
        "-nointeractive",
        "-nolookup",
        "-timeout",
        "5",
        "-maxtime",
        f"{runtime_seconds}s",
        "-Pause",
        str(max(0.1, 1 / requests_per_second)),
        "-Tuning",
        "123b",
        "-Format",
        "json",
        "-output",
        str(output_file),
    )


def zap_automation_plan(
    destination: Destination,
    profile: Literal["passive-web", "active-web"],
    *,
    report_directory: Path,
    included_paths: tuple[str, ...],
    excluded_paths: tuple[str, ...],
    runtime_seconds: int,
    requests_per_second: int,
    proxy_url: str | None = None,
    har_filename: str | None = None,
) -> dict[str, Any]:
    """Build an AF plan where passive HAR import cannot send or replay requests."""
    target = _target(destination)
    if (
        not report_directory.is_absolute()
        or not included_paths
        or len(included_paths) > 100
        or len(excluded_paths) > 100
        or type(runtime_seconds) is not int
        or not 1 <= runtime_seconds <= 300
        or type(requests_per_second) is not int
        or not 1 <= requests_per_second <= 10
    ):
        raise PolicyError("bounded ZAP scope and runtime required")
    for path in (*included_paths, *excluded_paths):
        if (
            not path.startswith("/")
            or any(char in path for char in "?#\\")
            or any(part == ".." for part in path.split("/"))
        ):
            raise PolicyError("invalid ZAP context path")

    parts = urlsplit(target)
    origin = urlunsplit((parts.scheme, parts.netloc, "", "", ""))
    escaped_origin = re.escape(origin)
    context = {
        "name": "aegistrace-action",
        "urls": [origin],
        "includePaths": [f"^{escaped_origin}{re.escape(path)}(?:$|/)" for path in included_paths],
        "excludePaths": [f"^{escaped_origin}{re.escape(path)}(?:$|/)" for path in excluded_paths],
        "authentication": {"method": "manual"},
        "sessionManagement": {"method": "cookie"},
    }
    jobs: list[dict[str, Any]]
    if profile == "passive-web":
        if not har_filename or Path(har_filename).name != har_filename:
            raise PolicyError("passive ZAP requires a private local HAR filename")
        jobs = [
            {
                "type": "import",
                "parameters": {
                    "type": "har",
                    "fileName": har_filename,
                    "sendRequests": False,
                    "maxMessages": 200,
                },
            },
            {
                "type": "passiveScan-wait",
                "parameters": {"maxDuration": max(1, (runtime_seconds + 59) // 60)},
            },
        ]
        config = {"pscans.scanOnlyInScope": "true", "pscans.maxBodySizeInBytes": "1048576"}
        env: dict[str, Any] = {
            "contexts": [context],
            "configs": config,
            "parameters": {
                "failOnError": True,
                "failOnWarning": False,
                "continueOnFailure": False,
                "maxDuration": runtime_seconds,
            },
        }
    elif profile == "active-web":
        proxy = urlsplit(proxy_url or "")
        if (
            proxy.scheme != "http"
            or proxy.hostname != "127.0.0.1"
            or proxy.port is None
            or proxy.path not in {"", "/"}
            or proxy.query
            or proxy.fragment
        ):
            raise PolicyError("active ZAP requires the per-job pinned egress proxy")
        duration_minutes = max(1, (runtime_seconds + 59) // 60)
        jobs = [
            {
                "type": "activeScan",
                "parameters": {
                    "context": context["name"],
                    "url": target,
                    "maxRuleDurationInMins": duration_minutes,
                    "maxScanDurationInMins": duration_minutes,
                    "threadPerHost": 1,
                    "delayInMs": max(100, 1000 // requests_per_second),
                    "defaultStrength": "Low",
                    "addQueryParam": False,
                    "handleAntiCSRFTokens": False,
                },
            }
        ]
        env = {
            "contexts": [context],
            "proxy": {"hostname": proxy.hostname, "port": proxy.port},
            "parameters": {
                "failOnError": True,
                "failOnWarning": False,
                "continueOnFailure": False,
                "maxDuration": runtime_seconds,
            },
        }
    else:
        raise PolicyError("unsupported ZAP profile")
    jobs.append(
        {
            "type": "report",
            "parameters": {
                "template": "traditional-json",
                "reportDir": str(report_directory),
                "reportFile": "zap-report.json",
                "displayReport": False,
            },
            "risks": ["high", "medium", "low", "info"],
            "confidences": ["high", "medium", "low", "falsepositive"],
        }
    )
    return {"env": env, "jobs": jobs}


def zap_arguments(binary: PinnedBinary, plan_file: Path) -> tuple[str, ...]:
    executable = verify_binary(binary)
    if not plan_file.is_absolute() or plan_file.is_symlink() or not plan_file.is_file():
        raise PolicyError("private ZAP Automation Framework plan required")
    return (str(executable), "-cmd", "-autorun", str(plan_file))


def validate_json_artifact(raw: bytes) -> None:
    if not 0 < len(raw) <= MAX_ARTIFACT_BYTES:
        raise PolicyError("scanner artifact missing or exceeds evidence limit")
    try:
        json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PolicyError("scanner artifact is not valid JSON") from error


def validate_har_input(
    raw: bytes,
    destination: Destination,
    included_paths: tuple[str, ...],
    excluded_paths: tuple[str, ...],
) -> None:
    """Accept a bounded HAR only when every recorded request stays in approved scope."""
    if not 0 < len(raw) <= MAX_ARTIFACT_BYTES:
        raise PolicyError("passive HAR input is missing or too large")
    try:
        value = json.loads(raw)
        entries = value["log"]["entries"]
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as error:
        raise PolicyError("passive input is not a supported HAR") from error
    if not isinstance(entries, list) or not 1 <= len(entries) <= 200:
        raise PolicyError("passive HAR requires 1 to 200 request records")
    origin = (destination.protocol, destination.host.lower(), destination.port)
    for entry in entries:
        try:
            parts = urlsplit(entry["request"]["url"])
            port = parts.port or (443 if parts.scheme == "https" else 80)
            path = parts.path or "/"
        except (KeyError, TypeError, ValueError) as error:
            raise PolicyError("passive HAR contains an invalid request URL") from error
        if (
            parts.scheme not in {"http", "https"}
            or parts.hostname is None
            or (parts.scheme, parts.hostname.lower(), port) != origin
            or parts.username is not None
            or parts.password is not None
            or parts.fragment
            or "\\" in path
            or any(segment == ".." for segment in path.split("/"))
        ):
            raise PolicyError("passive HAR contains a request outside the approved origin")
        normalized = "/" + "/".join(part for part in path.split("/") if part not in {"", "."})
        if path.endswith("/") and normalized != "/":
            normalized += "/"

        def within(candidate: str, root: str) -> bool:
            root = root.rstrip("/") or "/"
            return candidate == root or root == "/" or candidate.startswith(root + "/")

        if not any(within(normalized, root) for root in included_paths) or any(
            within(normalized, root) for root in excluded_paths
        ):
            raise PolicyError("passive HAR contains a request outside the approved paths")


def execute_json_artifact(
    argv: tuple[str, ...],
    artifact_path: Path,
    runtime_seconds: float,
    cancelled: Callable[[], bool],
    *,
    executor: Callable[[tuple[str, ...], float, Callable[[], bool]], ProcessOutcome] = run_managed,
) -> tuple[bytes, ProcessOutcome]:
    """Run a fixed plan, then collect only a bounded JSON file from its private workspace."""
    if (
        not argv
        or not artifact_path.is_absolute()
        or artifact_path.is_symlink()
        or artifact_path.exists()
        or not artifact_path.parent.is_dir()
        or type(runtime_seconds) not in {int, float}
        or not 0 < runtime_seconds <= 300
    ):
        raise PolicyError("bounded scanner command and fresh private artifact path required")
    outcome = executor(argv, runtime_seconds, cancelled)
    if outcome.state != "finished" or outcome.exit_code != 0:
        raise PolicyError("scanner did not complete with a clean exit")
    try:
        raw = artifact_path.read_bytes()
    except OSError as error:
        raise PolicyError("scanner artifact unavailable") from error
    validate_json_artifact(raw)
    return raw, outcome


def serialize_zap_plan(plan: dict[str, Any], path: Path) -> None:
    if not path.is_absolute() or path.is_symlink() or not path.parent.is_dir():
        raise PolicyError("private absolute ZAP plan path required")
    path.write_text(yaml.safe_dump(plan, sort_keys=False), encoding="utf-8")

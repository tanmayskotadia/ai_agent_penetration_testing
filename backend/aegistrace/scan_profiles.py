"""Versioned impact rules shared by review and dispatch; a catalogue is not consent."""

import hashlib
import json
from typing import Literal

from pydantic import BaseModel, ConfigDict

from aegistrace.lab import Profile
from aegistrace.policy import PolicyError


class ScanProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    profile: Profile
    schema_version: Literal["2.0"] = "2.0"
    impact: Literal["no-network", "network-requests", "disabled"]
    requests_generated: bool
    explicit_human_approval_required: bool
    execution_enabled: Literal[False] = False
    enforcement_state: Literal["review-bound"] = "review-bound"
    api_check_execution_available: bool = False
    allowed_parameters: tuple[str, ...] = ("timeout_seconds",)
    runtime_limit_seconds: int = 300
    timeout_limit_seconds: int = 30
    redirect_limit: int = 0
    rate_limit_source: Literal["reviewed-policy"] = "reviewed-policy"
    side_effects: tuple[str, ...] = ()
    prohibited_behaviors: tuple[str, ...] = (
        "wildcard-expansion",
        "arbitrary-command",
        "unreviewed-targets",
    )
    description: str
    suggested_rate_per_second: int
    maximum_concurrency: int
    limitations: tuple[str, ...]


CATALOG = (
    ScanProfile(
        profile="discovery",
        side_effects=("Connection attempts and service logs; no exploitation permission",),
        impact="network-requests",
        requests_generated=True,
        explicit_human_approval_required=True,
        description="Bounded host and service discovery against an explicit reviewed target policy.",
        suggested_rate_per_second=1,
        maximum_concurrency=8,
        limitations=(
            "No scan runs are enabled by this service",
            "Current Nmap adapter builds a request contract only",
        ),
    ),
    ScanProfile(
        profile="passive-web",
        side_effects=("Private captured-data processing only; no target requests",),
        prohibited_behaviors=(
            "crawl",
            "spider",
            "fetch",
            "redirect-following",
            "active-scan",
            "arbitrary-command",
        ),
        impact="no-network",
        requests_generated=False,
        explicit_human_approval_required=True,
        description="Analyze an already captured or proxied HTTP conversation; importing or reviewing evidence itself sends no requests.",
        suggested_rate_per_second=0,
        maximum_concurrency=1,
        limitations=(
            "A future ZAP passive runner must not crawl or fetch targets under this profile",
            "Current ZAP path accepts offline Alerts JSON only",
        ),
    ),
    ScanProfile(
        profile="active-web",
        redirect_limit=3,
        api_check_execution_available=True,
        allowed_parameters=("timeout_seconds", "max_redirects"),
        side_effects=(
            "Target requests may change state even for GET",
            "Explicit impact and reset instructions required",
        ),
        impact="network-requests",
        requests_generated=True,
        explicit_human_approval_required=True,
        description="Active web checks may send test payloads and can alter target state; require a fresh human approval bound to scope, policy, evidence and plan.",
        suggested_rate_per_second=1,
        maximum_concurrency=8,
        limitations=(
            "Only reviewed concrete API operation checks have an execution path; native ZAP/Nikto scanners remain unavailable",
            "Crawling and automatic route discovery are unsupported and never inferred from passive-web permission",
        ),
    ),
    ScanProfile(
        profile="controlled-validation",
        allowed_parameters=(),
        side_effects=("Offensive validation may alter state; execution is disabled",),
        impact="disabled",
        requests_generated=False,
        explicit_human_approval_required=True,
        description="Offensive validation is disabled; no Metasploit module or exploit is executed.",
        suggested_rate_per_second=0,
        maximum_concurrency=0,
        limitations=(
            "Cannot be approved or consumed as an execution grant",
            "Requires later isolated-lab implementation and human approval",
        ),
    ),
)


def profile_snapshot() -> list[dict[str, object]]:
    return [profile.model_dump(mode="json") for profile in CATALOG]


def profile_rule(name: str) -> ScanProfile:
    for rule in CATALOG:
        if rule.profile == name:
            return rule
    raise PolicyError("unknown impact profile denied")


def profile_digest(name: str) -> str:
    return hashlib.sha256(
        json.dumps(
            profile_rule(name).model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode()
    ).hexdigest()


def validate_profile_action(
    template: str, tool: str, profile: str, parameters: dict[str, int], runtime: int
) -> ScanProfile:
    rule = profile_rule(profile)
    combinations = {
        "nmap.connect.v1": ("Nmap", "discovery"),
        "zap.passive.v1": ("OWASP ZAP", "passive-web"),
        "zap.active.v1": ("OWASP ZAP", "active-web"),
        "metasploit.disabled": ("Metasploit", "controlled-validation"),
    }
    if combinations.get(template) != (tool, profile):
        raise PolicyError("tool/template/profile mismatch")
    if type(runtime) is not int or not 1 <= runtime <= rule.runtime_limit_seconds:
        raise PolicyError("profile runtime limit")
    if any(name not in rule.allowed_parameters for name in parameters):
        raise PolicyError("prohibited profile option")
    for name, value in parameters.items():
        maximum = (
            min(rule.timeout_limit_seconds, runtime)
            if name == "timeout_seconds"
            else rule.redirect_limit
        )
        minimum = 1 if name == "timeout_seconds" else 0
        if type(value) is not int or not minimum <= value <= maximum:
            raise PolicyError("profile parameter limit")
    return rule

"""Read-only scan-impact catalogue; it never grants an execution capability."""

from typing import Literal

from pydantic import BaseModel, ConfigDict

from aegistrace.lab import Profile


class ScanProfile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    profile: Profile
    impact: Literal["no-network", "network-requests", "disabled"]
    requests_generated: bool
    explicit_human_approval_required: bool
    execution_enabled: Literal[False] = False
    enforcement_state: Literal["catalogue-only"] = "catalogue-only"
    description: str
    suggested_rate_per_second: int
    maximum_concurrency: int
    limitations: tuple[str, ...]


CATALOG = (
    ScanProfile(
        profile="discovery",
        impact="network-requests",
        requests_generated=True,
        explicit_human_approval_required=True,
        description="Bounded host and service discovery against an explicit reviewed target policy.",
        suggested_rate_per_second=1,
        maximum_concurrency=1,
        limitations=(
            "No scan runs are enabled by this service",
            "Current Nmap adapter builds a request contract only",
        ),
    ),
    ScanProfile(
        profile="passive-web",
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
        impact="network-requests",
        requests_generated=True,
        explicit_human_approval_required=True,
        description="Active web checks may send test payloads and can alter target state; require a fresh human approval bound to scope, policy, evidence and plan.",
        suggested_rate_per_second=1,
        maximum_concurrency=1,
        limitations=(
            "No active scanner execution is enabled",
            "A future adapter must enforce exclusions, rate limits, timeouts, redirects, cancellation and reset instructions",
        ),
    ),
    ScanProfile(
        profile="controlled-validation",
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

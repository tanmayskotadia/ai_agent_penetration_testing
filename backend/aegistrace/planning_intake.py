"""Deterministic assessment intake. This module never authorizes or executes scans."""

import ipaddress
import re
from collections.abc import Sequence
from typing import Any
from urllib.parse import urlsplit

from aegistrace.capabilities import capability_snapshot

_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_HOST = re.compile(
    r"(?<![\w.-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}(?![\w.-])"
)
_IP = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")


def _canonical_target(value: str) -> str:
    candidate = value.strip()
    parsed = urlsplit(candidate if "://" in candidate else f"//{candidate}")
    host = (parsed.hostname or "").rstrip(".").lower()
    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        try:
            return host.encode("idna").decode("ascii")
        except UnicodeError:
            return host.casefold()


def _mentioned_targets(message: str) -> list[str]:
    candidates: list[str] = []
    candidates.extend(match.rstrip(".,);]}") for match in _URL.findall(message))
    candidates.extend(_IP.findall(message))
    candidates.extend(_HOST.findall(_URL.sub(" ", message)))
    results: list[str] = []
    for candidate in candidates:
        try:
            normalized = _canonical_target(candidate)
        except (UnicodeError, ValueError):
            continue
        if normalized and normalized not in results:
            results.append(normalized)
    return results


def build_intake_plan(
    message: str,
    *,
    scope: dict[str, Any] | None = None,
    constraints: Sequence[str] = (),
    prior_results: Sequence[dict[str, Any]] = (),
    capabilities: Sequence[dict[str, Any]] | None = None,
) -> dict[str, object]:
    """Create explainable import-only steps from explicit scope and user intent.

    The planner does not call an LLM, resolve DNS, fetch URLs, infer authorization,
    create scanner commands, or change live-scan capability.
    """
    text = " ".join(message.split())
    registry = list(capabilities if capabilities is not None else capability_snapshot())
    configured = {str(item["name"]): item for item in registry}
    mentions = _mentioned_targets(text)
    clarifications: list[str] = []
    blockers: list[str] = []
    if scope is None:
        blockers.append("scope-required")
        clarifications.append(
            "Choose or define an assessment scope with explicit in-scope targets and exclusions."
        )
        scope_targets: list[str] = []
        exclusions: list[str] = []
    else:
        scope_targets = [str(item) for item in scope.get("targets", [])]
        exclusions = [str(item) for item in scope.get("exclusions", [])]
        allowed = {_canonical_target(item) for item in scope_targets if _canonical_target(item)}
        excluded = {_canonical_target(item) for item in exclusions if _canonical_target(item)}
        if len(allowed) != len(scope_targets):
            blockers.append("invalid-scope-target")
            clarifications.append(
                "One or more scope targets cannot be normalized; review the scope record."
            )
        outside = [item for item in mentions if item not in allowed or item in excluded]
        if outside:
            blockers.append("target-outside-scope")
            clarifications.append(
                "The request names target(s) outside this exact scope or in its exclusions: "
                + ", ".join(outside)
                + ". Update scope through an explicit reviewer action before planning those targets."
            )
        if not scope_targets:
            blockers.append("empty-scope")
            clarifications.append("At least one explicit target is required before planning.")

    lowered = text.casefold()
    wants_web = any(term in lowered for term in ("web", "website", "api", "endpoint", "openapi"))
    wants_network = any(term in lowered for term in ("network", "host", "port", "service", "nmap"))
    requested_tools: list[str] = []
    if "nmap" in lowered or wants_network:
        requested_tools.append("Nmap")
    if "zap" in lowered or "owasp" in lowered or wants_web:
        requested_tools.append("OWASP ZAP")
    if "nikto" in lowered:
        requested_tools.append("Nikto")
    for tool, terms in {
        "Nessus": ("nessus",),
        "Greenbone": ("greenbone", "openvas"),
        "Burp Suite": ("burp",),
        "Metasploit": ("metasploit",),
    }.items():
        if any(term in lowered for term in terms):
            requested_tools.append(tool)
    if wants_web and any(word in lowered for word in ("api", "endpoint", "openapi")):
        requested_tools.append("OpenAPI")
    if not requested_tools:
        blockers.append("assessment-intent-required")
        clarifications.append(
            "Specify whether this review is for network services, web behavior, or an API definition. "
            "The planner will not select every tool when the request is ambiguous."
        )
    requested_tools = list(dict.fromkeys(requested_tools))
    completed_for_scope = {
        str(item.get("tool"))
        for item in prior_results
        if item.get("same_scope") is True and item.get("state") == "normalized"
    }
    reused_tools = [tool for tool in requested_tools if tool in completed_for_scope]
    requested_tools = [tool for tool in requested_tools if tool not in completed_for_scope]
    for tool in reused_tools:
        clarifications.append(
            f"A normalized {tool} revision already exists for this exact scope; the plan will not repeat that import."
        )
    if any(item.get("same_scope") is False for item in prior_results):
        clarifications.append(
            "One or more prior result revisions belong to a different scope revision and were not used to plan these targets."
        )
    failed_tools = sorted(
        {
            str(item.get("tool"))
            for item in prior_results
            if item.get("same_scope") is True and item.get("state") != "normalized"
        }
    )
    for tool in failed_tools:
        clarifications.append(
            f"A prior {tool} source revision for this scope is not normalized; review its failure before supplying a new capture."
        )

    steps: list[dict[str, object]] = []
    if scope is not None:
        steps.append(
            {
                "order": 1,
                "action": "review-scope",
                "mode": "recorded-import",
                "rationale": "Bind every supplied artifact to the current explicit scope revision and enforce exclusions.",
                "requires": ["scope revision", "participant-provided authorization context"],
                "evidence": ["scope id", "scope revision", "audit event"],
            }
        )
    for offset, tool in enumerate(requested_tools, start=len(steps) + 1):
        formats = {
            "Nmap": "Nmap XML supplied by the participant",
            "OWASP ZAP": "ZAP Alerts JSON supplied by the participant",
            "Nikto": "Nikto JSON supplied by the participant",
            "OpenAPI": "OpenAPI JSON supplied by the participant; URLs are not fetched",
        }
        entry = configured.get(tool)
        if tool not in formats or (
            tool != "OpenAPI"
            and (
                entry is None
                or entry.get("mode") == "unsupported"
                or not entry.get("guarded_containers")
            )
        ):
            blockers.append("requested-tool-unavailable")
            clarifications.append(
                f"{tool} has no available configured import capability. Supply a supported source or revise the request."
            )
            continue
        capability_status = (
            "OpenAPI JSON parser is implemented; live API discovery and authenticated coverage remain unverified"
            if tool == "OpenAPI"
            else "Recorded import parser is implemented; native execution, edition and license remain unverified"
        )
        steps.append(
            {
                "order": offset,
                "action": "import-recorded-evidence",
                "tool": tool,
                "mode": "recorded-import",
                "capability_status": capability_status,
                "registry_mode": entry.get("mode", "planned") if entry else "definition-parser",
                "scope_id": str(scope["id"]) if scope is not None else None,
                "scope_revision": scope.get("revision") if scope is not None else None,
                "targets": scope_targets,
                "exclusions": exclusions,
                "profile": "recorded-import-only",
                "limits": ["No network traffic, scanner execution or DNS resolution", *constraints],
                "alternatives": [
                    "Reuse an existing same-scope result",
                    "Defer until a supported source is available",
                ],
                "rationale": (
                    f"{tool} is selected because it matches the stated "
                    + ("web/API" if tool in {"OWASP ZAP", "OpenAPI"} else "network/web evidence")
                    + " review intent; only a supplied artifact is processed."
                ),
                "requires": [
                    formats[tool],
                    "source version and capture time",
                    "scope-matching target list",
                ],
                "evidence": [
                    "encrypted source artifact",
                    "SHA-256",
                    "source-linked normalized observations",
                ],
            }
        )

    if scope is None:
        steps = []
    if any(term in lowered for term in ("exploit", "exploit it", "metasploit", "active scan")):
        blockers.append("active-validation-not-enabled")
        clarifications.append(
            "Active validation is not enabled by conversational intake. It requires a separate, "
            "action-bound human approval and a verified isolated runtime; no action is scheduled."
        )
    if scope is not None and scope.get("authorization_reference") is None:
        clarifications.append(
            "No authorization reference is recorded. A scope entry is participant-supplied context, "
            "not independent proof or permission to run a scan."
        )
    return {
        "planner": "deterministic-intake-v1",
        "information_kind": "deterministic proposal; not observed evidence or AI inference",
        "capability_snapshot": registry,
        "request_text": text,
        "scope_id": str(scope["id"]) if scope is not None else None,
        "scope_revision": scope.get("revision") if scope is not None else None,
        "scope_targets": scope_targets,
        "scope_exclusions": exclusions,
        "mentioned_targets": mentions,
        "constraints": list(constraints),
        "prior_result_revisions": [
            {
                "id": str(item.get("id", "")),
                "tool": item.get("tool"),
                "state": item.get("state"),
                "same_scope": item.get("same_scope"),
            }
            for item in prior_results
        ],
        "intent": {"network": wants_network, "web_api": wants_web},
        "steps": steps,
        "clarifications": clarifications,
        "blockers": list(dict.fromkeys(blockers)),
        "execution": "never-executes; recorded-input-only",
        "authorization": "not-inferred-from-conversation-or-scope-fields",
        "assumptions": [
            "All targets and exclusions are interpreted exactly as recorded in the selected scope.",
            "No URL is fetched and no DNS lookup is performed during planning.",
            "Source files are not authenticated by their declared tool name, version, or rights reference.",
        ],
    }

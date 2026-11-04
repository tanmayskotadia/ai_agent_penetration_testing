"""Deterministic, review-only observation correlation and source-scored ordering."""

import re
from collections import defaultdict
from collections.abc import Iterable
from typing import Any


def _title_key(value: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9]+", " ", value.casefold()).split())


def _correlation_key(value: dict[str, Any]) -> tuple[str, ...] | None:
    cve = value.get("cve")
    if isinstance(cve, str) and cve.strip():
        return ("cve", cve.strip().upper())
    cwe, title = value.get("cwe"), value.get("title")
    if isinstance(cwe, str) and cwe.strip() and isinstance(title, str) and title.strip():
        return ("cwe-title", cwe.strip().upper(), _title_key(title))
    return None


def correlate_observations(
    observations: Iterable[dict[str, Any]], run_tools: dict[str, str]
) -> dict[str, Any]:
    """Group only explicit identifier matches; never turn observations into findings."""
    groups: dict[tuple[str, ...], list[dict[str, Any]]] = defaultdict(list)
    ordered = []
    for observation in observations:
        run_id = str(observation.get("run_id", ""))
        item = {
            "observation_id": str(observation.get("id", "")),
            "evidence_id": str(observation.get("evidence_id", "")),
            "asset_id": str(observation.get("asset_id", "")),
            "source_tool": run_tools.get(run_id, "unknown"),
            "source_key": observation.get("source_key"),
            "title": observation.get("title", ""),
            "cve": observation.get("cve"),
            "cwe": observation.get("cwe"),
            "source_cvss_score": observation.get("cvss_score"),
            "source_cvss_version": observation.get("cvss_version"),
            "source_severity": observation.get("source_severity"),
            "validation_state": observation.get("validation_state", "unknown"),
        }
        ordered.append(item)
        key = _correlation_key(observation)
        if key is not None:
            groups[key].append(item)

    correlated = []
    for key, members in sorted(groups.items()):
        tools = sorted({member["source_tool"] for member in members})
        if len(tools) < 2:
            continue
        scores = [
            member["source_cvss_score"]
            for member in members
            if isinstance(member["source_cvss_score"], (float, int))
            and not isinstance(member["source_cvss_score"], bool)
        ]
        correlated.append(
            {
                "match_basis": "CVE" if key[0] == "cve" else "CWE and normalized title",
                "match_value": key[1:],
                "source_tools": tools,
                "observation_count": len(members),
                "asset_ids": sorted({member["asset_id"] for member in members}),
                "observations": sorted(members, key=lambda item: item["observation_id"]),
                "source_cvss_range": [min(scores), max(scores)] if scores else None,
                "review_state": "candidate-correlation-review-required",
            }
        )

    # Source CVSS is the only numeric ordering signal. Missing scores remain at the end.
    ordered.sort(
        key=lambda item: (
            not isinstance(item["source_cvss_score"], (float, int))
            or isinstance(item["source_cvss_score"], bool),
            -item["source_cvss_score"]
            if isinstance(item["source_cvss_score"], (float, int))
            and not isinstance(item["source_cvss_score"], bool)
            else 0,
            item["observation_id"],
        )
    )
    return {
        "correlation_method": "exact CVE; otherwise exact CWE plus normalized title",
        "ranking_method": "source-reported CVSS descending; unscored observations follow",
        "ranked_observations": ordered,
        "cross_tool_candidate_groups": correlated,
        "candidate_group_count": len(correlated),
        "limitations": [
            "Correlation groups are candidates, not confirmed duplicate findings",
            "Every source observation and asset occurrence is retained in the response",
            "CVSS values and severity labels come from source imports and are not recalculated",
            "Observations without explicit CVE or CWE and title identifiers are not correlated",
        ],
    }

"""Immutable reviewer decisions over source observations; originals are never rewritten."""

import hashlib
from collections.abc import Sequence
from typing import Any


def cluster_id(observation_ids: Sequence[str]) -> str:
    """Return a stable opaque ID for the exact sorted member set."""
    members = sorted(set(observation_ids))
    if len(members) < 2:
        raise ValueError("reviewed duplicate cluster requires at least two observations")
    return hashlib.sha256("\n".join(members).encode("utf-8")).hexdigest()


def normalize_clusters(value: Any, known_ids: set[str]) -> list[dict[str, Any]]:
    """Validate immutable cluster snapshots and normalize their order."""
    if not isinstance(value, list) or len(value) > 100:
        raise ValueError("reviewed cluster snapshot is invalid")
    result: list[dict[str, Any]] = []
    claimed: set[str] = set()
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("reviewed cluster is invalid")
        members = item.get("observation_ids")
        rationale = item.get("rationale")
        if (
            not isinstance(members, list)
            or len(members) < 2
            or len(members) > 100
            or any(not isinstance(member, str) or member not in known_ids for member in members)
            or len(set(members)) != len(members)
            or claimed.intersection(members)
            or not isinstance(rationale, str)
            or not rationale.strip()
            or len(rationale) > 2000
        ):
            raise ValueError("reviewed cluster contains invalid or overlapping observations")
        ordered = sorted(members)
        claimed.update(ordered)
        result.append(
            {
                "cluster_id": cluster_id(ordered),
                "observation_ids": ordered,
                "rationale": rationale.strip(),
            }
        )
    return sorted(result, key=lambda item: item["cluster_id"])


def merge_clusters(
    current: list[dict[str, Any]],
    selected_ids: set[str],
    rationale: str,
    known_ids: set[str],
) -> list[dict[str, Any]]:
    if len(selected_ids) < 2 or not selected_ids <= known_ids:
        raise ValueError("merge requires at least two observations from this assessment")
    intersecting = [
        group for group in current if selected_ids.intersection(group["observation_ids"])
    ]
    if any(not set(group["observation_ids"]) <= selected_ids for group in intersecting):
        raise ValueError("merge must select every member of an existing reviewed cluster")
    retained = [
        group for group in current if not selected_ids.intersection(group["observation_ids"])
    ]
    retained.append(
        {
            "cluster_id": cluster_id(sorted(selected_ids)),
            "observation_ids": sorted(selected_ids),
            "rationale": rationale.strip(),
        }
    )
    return normalize_clusters(retained, known_ids)


def split_cluster(
    current: list[dict[str, Any]],
    target_cluster_id: str,
    partitions: list[list[str]],
    rationale: str,
    known_ids: set[str],
) -> list[dict[str, Any]]:
    target = next((group for group in current if group["cluster_id"] == target_cluster_id), None)
    if target is None:
        raise ValueError("reviewed cluster not found")
    expected = set(target["observation_ids"])
    groups = [set(group) for group in partitions]
    if (
        len(groups) < 2
        or any(not group for group in groups)
        or any(not group <= known_ids for group in groups)
        or set.union(*groups) != expected
        or sum(len(group) for group in groups) != len(expected)
    ):
        raise ValueError("split partitions must cover the current cluster exactly without overlap")
    replacement = [
        {
            "cluster_id": cluster_id(sorted(group)),
            "observation_ids": sorted(group),
            "rationale": rationale.strip(),
        }
        for group in groups
        if len(group) >= 2
    ]
    return normalize_clusters(
        [group for group in current if group["cluster_id"] != target_cluster_id] + replacement,
        known_ids,
    )


def materialize_clusters(
    clusters: list[dict[str, Any]], observations: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Join reviewed membership to immutable observations without changing their state."""
    by_id = {str(value.get("id", value.get("observation_id"))): value for value in observations}
    rendered: list[dict[str, Any]] = []
    for group in clusters:
        members = [by_id[item] for item in group["observation_ids"] if item in by_id]
        if len(members) != len(group["observation_ids"]):
            continue
        rendered.append(
            {
                "cluster_id": group["cluster_id"],
                "review_state": "reviewer-merged",
                "information_kind": "reviewer-decision",
                "rationale": group["rationale"],
                "observation_ids": group["observation_ids"],
                "observations": members,
                "asset_ids": sorted({str(value.get("asset_id", "")) for value in members}),
                "source_tools": sorted(
                    {str(value.get("source_tool", "unknown")) for value in members}
                ),
                "occurrence_count": len(members),
            }
        )
    return rendered


def materialize_splits(
    splits: list[dict[str, Any]], observations: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    by_id = {str(value.get("id", value.get("observation_id"))): value for value in observations}
    rendered: list[dict[str, Any]] = []
    for split in splits:
        members = [by_id[item] for item in split["observation_ids"] if item in by_id]
        if len(members) != len(split["observation_ids"]):
            continue
        rendered.append(
            {
                "cluster_id": split["cluster_id"],
                "review_state": "reviewer-split",
                "information_kind": "reviewer-decision",
                "rationale": split["rationale"],
                "observation_ids": split["observation_ids"],
                "partitions": split["partitions"],
                "observations": members,
                "asset_ids": sorted({str(value.get("asset_id", "")) for value in members}),
                "source_tools": sorted(
                    {str(value.get("source_tool", "unknown")) for value in members}
                ),
            }
        )
    return rendered

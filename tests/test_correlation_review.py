import pytest
from aegistrace.correlation_review import (
    cluster_id,
    materialize_clusters,
    materialize_splits,
    merge_clusters,
    normalize_clusters,
    split_cluster,
)


def test_merge_is_an_explicit_reviewer_cluster_and_does_not_rewrite_observations():
    known = {"obs-a", "obs-b", "obs-c"}
    first = merge_clusters([], {"obs-a", "obs-b"}, "Same issue across sources", known)

    assert first == [
        {
            "cluster_id": cluster_id(["obs-a", "obs-b"]),
            "observation_ids": ["obs-a", "obs-b"],
            "rationale": "Same issue across sources",
        }
    ]
    rendered = materialize_clusters(
        first,
        [
            {"id": "obs-a", "asset_id": "asset-1", "source_tool": "OWASP ZAP"},
            {"id": "obs-b", "asset_id": "asset-2", "source_tool": "Nikto"},
        ],
    )
    assert rendered[0]["review_state"] == "reviewer-merged"
    assert rendered[0]["information_kind"] == "reviewer-decision"
    assert rendered[0]["asset_ids"] == ["asset-1", "asset-2"]
    assert rendered[0]["occurrence_count"] == 2
    assert {row["id"] for row in rendered[0]["observations"]} == {"obs-a", "obs-b"}


def test_merge_requires_all_members_of_any_existing_reviewed_cluster():
    known = {"a", "b", "c"}
    current = merge_clusters([], {"a", "b"}, "Reviewer confirmed duplicate", known)

    with pytest.raises(ValueError, match="every member"):
        merge_clusters(current, {"a", "c"}, "Incomplete selection", known)
    merged = merge_clusters(current, {"a", "b", "c"}, "Joined reviewed clusters", known)
    assert merged[0]["observation_ids"] == ["a", "b", "c"]


def test_split_must_partition_a_reviewed_cluster_exactly_and_keeps_occurrences():
    known = {"a", "b", "c", "d"}
    current = merge_clusters([], known, "Initial review", known)
    target = current[0]["cluster_id"]

    with pytest.raises(ValueError, match="exactly without overlap"):
        split_cluster(current, target, [["a", "b"], ["c"]], "Split", known)
    split = split_cluster(
        current, target, [["a", "b"], ["c", "d"]], "Different underlying issues", known
    )
    assert [group["observation_ids"] for group in split] == [["a", "b"], ["c", "d"]]


def test_split_can_separate_a_two_observation_merge_into_singletons():
    known = {"a", "b"}
    current = merge_clusters([], known, "Initial review", known)
    split = split_cluster(
        current,
        current[0]["cluster_id"],
        [["a"], ["b"]],
        "Different underlying issues",
        known,
    )

    assert split == []
    materialized = materialize_splits(
        [
            {
                "cluster_id": current[0]["cluster_id"],
                "observation_ids": ["a", "b"],
                "partitions": [["a"], ["b"]],
                "rationale": "Different underlying issues",
            }
        ],
        [
            {"id": "a", "asset_id": "asset-a", "source_tool": "OWASP ZAP"},
            {"id": "b", "asset_id": "asset-a", "source_tool": "Nikto"},
        ],
    )
    assert materialized[0]["partitions"] == [["a"], ["b"]]


def test_cluster_snapshot_rejects_unknown_overlapping_or_singleton_members():
    with pytest.raises(ValueError, match="invalid or overlapping"):
        normalize_clusters(
            [
                {"observation_ids": ["a", "b"], "rationale": "Duplicate"},
                {"observation_ids": ["b", "c"], "rationale": "Duplicate"},
            ],
            {"a", "b", "c"},
        )
    with pytest.raises(ValueError, match="invalid or overlapping"):
        normalize_clusters([{"observation_ids": ["a", "missing"], "rationale": "Duplicate"}], {"a"})

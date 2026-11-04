import hashlib
import json
from pathlib import Path

import pytest
from aegistrace.fixtures import inspect_corpus


def write_test_metadata(tmp_path: Path, changes: dict | None = None) -> tuple[Path, Path]:
    artifact = tmp_path / "tests/fixtures/parser-test.txt"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("HANDCRAFTED PARSER TEST ONLY; not scanner output or proof.")
    record = {
        "id": "parser-only",
        "path": "tests/fixtures/parser-test.txt",
        "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest(),
        "tool": "Nmap",
        "tool_version": "TEST-ONLY",
        "format": "malformed-test-text",
        "provenance": "handcrafted_test",
        "split": "parser_test",
        "captured_at": None,
        "target_pseudonym": "NO-REAL-TARGET",
        "capture_reference": None,
        "organizer_authorization_reference": None,
        "redistribution_allowed": True,
        "rights_basis": "handcrafted test data authored for this unit test",
        "redaction_reviewed": True,
        "used_for_tuning": False,
    }
    record.update(changes or {})
    manifest, labels = tmp_path / "manifest.json", tmp_path / "labels.json"
    manifest.write_text(json.dumps({"schema_version": 1, "records": [record]}))
    labels.write_text(json.dumps({"schema_version": 1, "labels": []}))
    return manifest, labels


def test_empty_corpus_is_honestly_not_ready(tmp_path: Path) -> None:
    manifest, labels = tmp_path / "manifest.json", tmp_path / "labels.json"
    manifest.write_text('{"schema_version":1,"records":[]}')
    labels.write_text('{"schema_version":1,"labels":[]}')
    result = inspect_corpus(manifest, labels, tmp_path)
    assert result["metadata_valid"] and not result["ready"]
    assert result["genuine_fixtures"] == 0 and not result["calibration_ready"]


@pytest.mark.parametrize(
    "changes",
    [
        {"split": "held_out"},
        {"path": "../../outside.txt"},
        {"sha256": "0" * 64},
        {"redistribution_allowed": False},
        {"provenance": "live_capture"},
    ],
)
def test_invalid_or_misrepresented_fixture_is_rejected(tmp_path: Path, changes: dict) -> None:
    manifest, labels = write_test_metadata(tmp_path, changes)
    assert not inspect_corpus(manifest, labels, tmp_path)["metadata_valid"]


def test_handcrafted_data_never_counts_as_genuine_or_ground_truth(tmp_path: Path) -> None:
    manifest, labels = write_test_metadata(tmp_path)
    result = inspect_corpus(manifest, labels, tmp_path)
    assert result["metadata_valid"] and result["genuine_fixtures"] == 0 and not result["ready"]
    labels.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "labels": [
                    {
                        "fixture_id": "parser-only",
                        "reviewer_id": "TEST-ONLY",
                        "independent_review": True,
                        "outcome": "confirmed",
                        "scenario": "clean_control",
                        "evidence_references": ["TEST-ONLY; not genuine evidence"],
                    }
                ],
            }
        )
    )
    assert not inspect_corpus(manifest, labels, tmp_path)["metadata_valid"]

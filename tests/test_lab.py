import hashlib
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml
from aegistrace.lab import check_lab


def contract_files(tmp_path: Path) -> tuple[Path, Path, dict]:
    # Handcrafted policy-test data, not organizer permission or scanner output.
    document = tmp_path / "test-only-authorization.txt"
    document.write_text("TEST ONLY: not an organizer authorization", encoding="utf-8")
    data = {
        "schema_version": 1,
        "status": "approved",
        "authorization": {
            "source": "organizer",
            "reference": "TEST-ONLY",
            "document_sha256": hashlib.sha256(document.read_bytes()).hexdigest(),
            "reviewed_by": "TEST-ONLY",
        },
        "valid_from": "2026-11-01T00:00:00Z",
        "valid_until": "2026-11-08T00:00:00Z",
        "lab_networks": ["192.0.2.0/24"],
        "targets": [
            {
                "asset_id": "test-only",
                "host": "assessment.test",
                "approved_addresses": ["192.0.2.10"],
            }
        ],
        "exclusions": [],
        "allowed_profiles": ["discovery", "controlled-validation"],
        "rate_limits": {"requests_per_second": 1, "concurrent_jobs": 1},
    }
    manifest = tmp_path / "manifest.yaml"
    return manifest, document, data


@pytest.mark.parametrize(
    "case,expected",
    [
        ("pending", "missing-authorization"),
        ("expired", "expired-or-not-current"),
        ("excluded", "excluded-target"),
        ("excluded-ip", "excluded-target"),
        ("out-of-scope", "out-of-scope"),
        ("profile", "profile-not-permitted"),
        ("tampered", "authorization-document-mismatch"),
        ("broad", "invalid-manifest"),
        ("metadata", "invalid-manifest"),
        ("naive-time", "invalid-manifest"),
        ("unknown-field", "invalid-manifest"),
    ],
)
def test_denial_cases(tmp_path: Path, case: str, expected: str) -> None:
    manifest, document, data = contract_files(tmp_path)
    target, profile = "assessment.test", "discovery"
    if case == "pending":
        data["status"] = "pending"
    elif case == "expired":
        data["valid_until"] = "2026-11-02T00:00:00Z"
    elif case == "excluded":
        data["exclusions"] = ["192.0.2.0/24"]
    elif case == "excluded-ip":
        data["exclusions"] = ["192.0.2.10"]
    elif case == "out-of-scope":
        target = "outside.test"
    elif case == "profile":
        profile = "active-web"
    elif case == "tampered":
        document.write_text("changed TEST ONLY document")
    elif case == "broad":
        data["lab_networks"] = ["0.0.0.0/0"]
    elif case == "metadata":
        data["targets"][0]["approved_addresses"] = ["169.254.169.254"]
    elif case == "naive-time":
        data["valid_from"] = "2026-11-01T00:00:00"
    elif case == "unknown-field":
        data["bypass"] = True
    manifest.write_text(yaml.safe_dump(data), encoding="utf-8")
    decision = check_lab(manifest, document, target, profile, now=datetime(2026, 11, 4, tzinfo=UTC))
    assert not decision.ready and decision.code == expected
    assert not decision.live_execution_enabled


def test_missing_manifest_and_test_only_positive_consistency(tmp_path: Path) -> None:
    manifest, document, data = contract_files(tmp_path)
    assert check_lab(manifest, None, "assessment.test", "discovery").code == "missing-manifest"
    manifest.write_text(yaml.safe_dump(data), encoding="utf-8")
    now = datetime(2026, 11, 4, tzinfo=UTC)
    assert (
        check_lab(manifest, None, "assessment.test", "discovery", now=now).code
        == "missing-authorization-document"
    )
    allowed = check_lab(manifest, document, "assessment.test", "discovery", now=now)
    assert allowed.ready and not allowed.live_execution_enabled
    assert (
        check_lab(manifest, document, "assessment.test", "controlled-validation", now=now).code
        == "runtime-human-approval-required"
    )


@pytest.mark.parametrize(
    "target",
    [
        "http://assessment.test",
        "a@assessment.test",
        "127.1",
        "a\tb",
        "2001:db8::1%zone",
        "assessment.test..",
    ],
)
def test_ambiguous_or_non_host_targets_are_rejected(tmp_path: Path, target: str) -> None:
    manifest, document, data = contract_files(tmp_path)
    manifest.write_text(yaml.safe_dump(data), encoding="utf-8")
    decision = check_lab(
        manifest, document, target, "discovery", now=datetime(2026, 11, 4, tzinfo=UTC)
    )
    assert not decision.ready and decision.code == "invalid-target"


def test_yaml_aliases_and_literal_address_mismatch_are_rejected(tmp_path: Path) -> None:
    manifest, document, data = contract_files(tmp_path)
    manifest.write_text("x: &entry 1\ny: *entry\n", encoding="utf-8")
    assert check_lab(manifest, document, "assessment.test", "discovery").code == "invalid-manifest"
    data["targets"][0]["host"] = "192.0.2.11"
    manifest.write_text(yaml.safe_dump(data), encoding="utf-8")
    assert check_lab(manifest, document, "192.0.2.11", "discovery").code == "invalid-manifest"

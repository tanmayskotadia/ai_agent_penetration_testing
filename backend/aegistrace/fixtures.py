"""Provenance and split checks for an offline corpus; never manufactures scanner proof."""

import hashlib
from datetime import datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

Tool = Literal["Nmap", "OWASP ZAP", "Nikto", "Nessus", "Greenbone", "Burp Suite", "Metasploit"]


class Fixture(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,80}$")
    path: str
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    tool: Tool
    tool_version: str = Field(min_length=1)
    format: str = Field(min_length=1)
    provenance: Literal["live_capture", "recorded_import", "handcrafted_test"]
    split: Literal["parser_test", "training", "held_out"]
    captured_at: datetime | None
    target_pseudonym: str = Field(min_length=1)
    capture_reference: str | None
    organizer_authorization_reference: str | None
    redistribution_allowed: bool
    rights_basis: str = Field(min_length=1)
    redaction_reviewed: bool
    used_for_tuning: bool

    @model_validator(mode="after")
    def provenance_rules(self) -> "Fixture":
        if self.provenance == "handcrafted_test" and self.split != "parser_test":
            raise ValueError(
                "handcrafted parser data cannot be training or held-out scanner evidence"
            )
        if self.split == "held_out" and self.used_for_tuning:
            raise ValueError("held-out data must not be used for prompt/threshold tuning")
        if self.provenance != "handcrafted_test":
            if (
                self.captured_at is None
                or self.captured_at.tzinfo is None
                or not self.capture_reference
                or not self.organizer_authorization_reference
            ):
                raise ValueError(
                    "genuine capture needs dated provenance and authorization references"
                )
        if self.path.startswith("tests/fixtures/") and not self.redistribution_allowed:
            raise ValueError("public fixture path needs documented redistribution permission")
        return self


class FixtureManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1]
    records: list[Fixture]


class GroundTruth(BaseModel):
    model_config = ConfigDict(extra="forbid")
    fixture_id: str
    reviewer_id: str = Field(min_length=1)
    independent_review: bool
    outcome: Literal["confirmed", "suspected", "false_positive", "clean", "contradictory"]
    scenario: Literal[
        "cross_tool_duplicate", "distinct_assets", "contradictory_evidence", "clean_control"
    ]
    evidence_references: list[str] = Field(min_length=1)


class LabelSet(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1]
    labels: list[GroundTruth]


def inspect_corpus(manifest_path: Path, labels_path: Path, root: Path) -> dict[str, object]:
    errors: list[str] = []
    blockers: list[str] = []
    try:
        for file in [manifest_path, labels_path]:
            if file.stat().st_size > 1048576:
                raise ValueError("metadata file too large")
        manifest = FixtureManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
        labels = LabelSet.model_validate_json(labels_path.read_text(encoding="utf-8"))
    except (ValueError, OSError, ValidationError):
        return {
            "metadata_valid": False,
            "ready": False,
            "errors": ["Invalid or missing bounded fixture/label metadata; values not printed."],
            "blockers": [],
            "genuine_fixtures": 0,
            "calibration_ready": False,
        }
    by_id = {fixture.id: fixture for fixture in manifest.records}
    if len(by_id) != len(manifest.records):
        errors.append("Fixture IDs must be unique.")
    hashes: dict[str, set[str]] = {}
    genuine = []
    for fixture in manifest.records:
        path = (root / fixture.path).resolve()
        permitted_roots = [root.resolve() / "data/fixtures", root.resolve() / "tests/fixtures"]
        if not any(
            path.is_relative_to(base) for base in permitted_roots
        ) or not fixture.path.startswith(("data/fixtures/", "tests/fixtures/")):
            errors.append(f"{fixture.id}: fixture path escapes the permitted corpus directories.")
            continue
        if not path.is_file() or path.stat().st_size > 52428800:
            errors.append(f"{fixture.id}: original artifact missing or exceeds 50 MiB.")
            continue
        if hashlib.sha256(path.read_bytes()).hexdigest() != fixture.sha256:
            errors.append(f"{fixture.id}: original artifact digest mismatch.")
            continue
        hashes.setdefault(fixture.sha256, set()).add(fixture.split)
        if not fixture.redaction_reviewed:
            blockers.append(f"{fixture.id}: redaction review pending.")
        if fixture.provenance != "handcrafted_test":
            genuine.append(fixture)
    if any("training" in splits and "held_out" in splits for splits in hashes.values()):
        errors.append("The same artifact bytes cannot appear in both training and held-out splits.")
    for label in labels.labels:
        label_fixture = by_id.get(label.fixture_id)
        if label_fixture is None or label_fixture.provenance == "handcrafted_test":
            errors.append("Ground-truth label must reference a genuine captured fixture.")
        if not label.independent_review:
            blockers.append(f"{label.fixture_id}: independent ground-truth review pending.")
    tools = {f.tool for f in genuine}
    for tool in ["Nmap", "OWASP ZAP", "Nikto"]:
        if tool not in tools:
            blockers.append(f"Missing genuine permitted {tool} capture.")
    for split in ["training", "held_out"]:
        if not any(f.split == split for f in genuine):
            blockers.append(f"Missing genuine {split} split.")
    for scenario in [
        "cross_tool_duplicate",
        "distinct_assets",
        "contradictory_evidence",
        "clean_control",
    ]:
        if not any(
            label.scenario == scenario and label.independent_review for label in labels.labels
        ):
            blockers.append(f"Missing independently reviewed {scenario} case.")
    return {
        "metadata_valid": not errors,
        "ready": not errors and not blockers,
        "errors": errors,
        "blockers": sorted(set(blockers)),
        "genuine_fixtures": len(genuine),
        "handcrafted_parser_fixtures": sum(
            f.provenance == "handcrafted_test" for f in manifest.records
        ),
        "labels": len(labels.labels),
        "calibration_ready": False,
        "limitations": "Metadata consistency cannot authenticate captures, legal rights or reviewer independence. No accuracy/calibration claim is produced; T48 must evaluate representative held-out outcomes.",
    }

"""Check T01 source/coverage integrity without claiming product verification."""

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

from export_requirements import render, render_scorecard, render_submission_gates

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_POINTS = {
    "J01": 15,
    "J02": 20,
    "J03": 15,
    "J04": 15,
    "J05": 10,
    "J06": 10,
    "J07": 10,
    "J08": 5,
}
CLASSES = {
    "required",
    "full-target",
    "conditional",
    "advanced",
    "quality",
    "event",
    "reference",
    "participant",
}
STATES = {"planned", "in-progress", "implemented", "verified", "blocked", "not-applicable"}
EVIDENCE_STATES = {"not-collected", "collected", "reviewed"}


def validate(register, sources, pdf=None):
    errors = []
    checks = []

    def check(ok, message):
        (checks if ok else errors).append(message)

    requirements = register.get("requirements", [])
    tasks = register.get("tasks", {})
    source_map = {s["id"]: s for s in sources.get("sources", [])}
    ids = [r["id"] for r in requirements]
    check(bool(ids) and len(set(ids)) == len(ids), "Requirement IDs are present and unique.")
    required_fields = [
        "id",
        "source_id",
        "source_locator",
        "source_anchor",
        "requirement",
        "owner_role",
        "implementation_tasks",
        "verification_tasks",
        "required_evidence",
        "report_or_delivery_location",
        "classification",
        "implementation_status",
        "evidence_status",
    ]
    legacy = set()
    for row in requirements:
        rid = row["id"]
        for field in required_fields:
            check(bool(row.get(field)), f"{rid}: required {field} is populated.")
        check(row["source_id"] in source_map, f"{rid}: reviewed source exists.")
        check(row["classification"] in CLASSES, f"{rid}: classification is recognized.")
        check(row["implementation_status"] in STATES, f"{rid}: implementation state is recognized.")
        check(row["evidence_status"] in EVIDENCE_STATES, f"{rid}: evidence state is recognized.")
        for task in row["implementation_tasks"] + row["verification_tasks"]:
            check(
                task in tasks
                and bool(
                    re.fullmatch(
                        r"https://github\.com/tanmayskotadia/ai_agent_penetration_testing/issues/\d+",
                        tasks.get(task, {}).get("url", ""),
                    )
                ),
                f"{rid}: {task} resolves to a repository issue.",
            )
        if row["source_id"] == "S-PDF":
            check(
                bool(re.search(r"\bp(?:[1-9]|10)(?:-[1-9][0-9]?)?\b", row["source_locator"])),
                f"{rid}: PDF page locator exists.",
            )
        for criterion in row["judging_criteria"]:
            check(criterion in EXPECTED_POINTS, f"{rid}: criterion {criterion} exists.")
        for demo in row["demo_checks"]:
            check(demo in {f"D{i:02d}" for i in range(1, 8)}, f"{rid}: demo {demo} exists.")
        actual = row.get("actual_evidence", [])
        if row["evidence_status"] == "not-collected":
            check(not actual, f"{rid}: no uncollected evidence is represented as actual.")
        if row["implementation_status"] == "verified":
            check(
                bool(actual)
                and row["evidence_status"] == "reviewed"
                and bool(row.get("reviewer_role")),
                f"{rid}: verified claim has reviewed proof and reviewer.",
            )
        if row["evidence_status"] in {"collected", "reviewed"}:
            check(bool(actual), f"{rid}: evidence claim has inspectable actual references.")
        if row["implementation_status"] == "not-applicable":
            check(
                row["classification"] == "conditional" and bool(row.get("applicability_rationale")),
                f"{rid}: not-applicable decision is conditional and justified.",
            )
        legacy.update(row["legacy_groups"])
    expected_legacy = (
        {f"R{i:02d}" for i in range(1, 37)} | {f"W{i:02d}" for i in range(1, 8)} | {"PARTICIPANT"}
    )
    check(
        expected_legacy <= legacy,
        "All 43 legacy source groups and participant constraints are covered.",
    )
    points = {c["id"]: c["points"] for c in register.get("judging_criteria", [])}
    check(
        len(register.get("judging_criteria", [])) == 8
        and points == EXPECTED_POINTS
        and sum(points.values()) == 100,
        "All eight exact published weights total 100.",
    )
    for criterion in register.get("judging_criteria", []):
        check(
            any(criterion["id"] in r["judging_criteria"] for r in requirements),
            f"{criterion['id']}: requirement evidence coverage exists.",
        )
        check(
            criterion.get("achieved_score") is None or criterion.get("actual_evidence"),
            f"{criterion['id']}: no unsupported achieved score.",
        )
    demos = register.get("demo_checks", [])
    check(
        len(demos) == 7 and {d["id"] for d in demos} == {f"D{i:02d}" for i in range(1, 8)},
        "All seven distinct live-demo checks are registered.",
    )
    for demo in demos:
        check(demo["requirement_id"] in ids, f"{demo['id']}: source-backed demo obligation exists.")
    gates = register.get("submission_gates", [])
    check(
        len(gates) == 3 and {g["id"] for g in gates} == {"SUB-PPT", "SUB-VIDEO", "SUB-REPO"},
        "Three distinct PPT/video/repository submission gates exist.",
    )
    for gate in gates:
        check(
            bool(gate["requirement_ids"]) and set(gate["requirement_ids"]) <= set(ids),
            f"{gate['id']}: source requirement exists.",
        )
        check(
            gate["owner_task"] in tasks and gate["verification_task"] in tasks,
            f"{gate['id']}: owner and verifier issue links exist.",
        )
        if gate["status"] == "verified":
            check(
                bool(gate["artifact_url"])
                and gate["access_checked"]
                and bool(gate["actual_evidence"]),
                f"{gate['id']}: verified release has artifact/access proof.",
            )
    tool_rows = [r for r in requirements if r["id"].startswith("INT-")]
    check(len(tool_rows) == 7, "All seven expected tools have separate requirement rows.")
    check(
        len([r for r in requirements if r["id"].startswith("STD-")]) == 7,
        "All seven reference frameworks have applicability requirements.",
    )
    csv_path = ROOT / "docs/compliance-matrix.csv"
    check(
        csv_path.exists() and csv_path.read_text(encoding="utf-8-sig") == render(register),
        "Reviewable CSV matches canonical register exactly.",
    )
    for path, expected in [
        ("docs/judging-scorecard.md", render_scorecard(register)),
        ("docs/submission-gates.md", render_submission_gates(register)),
    ]:
        target = ROOT / path
        check(
            target.exists() and target.read_text(encoding="utf-8") == expected,
            f"{path}: generated documentation matches canonical register.",
        )
    if pdf:
        path = Path(pdf)
        check(path.is_file(), "Supplied original PDF is readable.")
        if path.is_file():
            check(
                hashlib.sha256(path.read_bytes()).hexdigest() == source_map["S-PDF"]["sha256"],
                "Supplied PDF bytes match reviewed SHA-256.",
            )
    return {
        "status": "passed" if not errors else "failed",
        "scope": "T01 requirements-register consistency, not product acceptance",
        "requirements": len(requirements),
        "classification_counts": dict(Counter(r["classification"] for r in requirements)),
        "checks_passed": len(checks),
        "errors": errors,
        "source_pdf_digest_checked": bool(pdf),
        "product_requirements_verified": sum(
            r["implementation_status"] == "verified" for r in requirements
        ),
        "judging_points": sum(points.values()),
        "demo_checks": len(demos),
        "submission_gates": len(gates),
        "limitations": [
            "Structural checks do not establish semantic completeness; the source review record is also required.",
            "No product behavior, live scan, lab permission, license or current private organizer update is verified by this command.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pdf", help="Optional original supplied PDF; verify its byte digest.")
    parser.add_argument("--output", type=Path, help="Optional local JSON verification record.")
    args = parser.parse_args()
    register = json.loads((ROOT / "docs/requirements-register.json").read_text(encoding="utf-8"))
    sources = json.loads((ROOT / "docs/sources/source-register.json").read_text(encoding="utf-8"))
    result = validate(register, sources, args.pdf)
    if args.output:
        target = args.output.resolve()
        if not target.is_relative_to(ROOT):
            raise SystemExit("Output must remain inside the workspace.")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())

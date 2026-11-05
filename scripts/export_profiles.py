"""Export packaged enforcement rules for review; JSON is not execution consent."""

import argparse
import difflib
import hashlib
import json
from pathlib import Path

from aegistrace.scan_profiles import profile_digest, profile_snapshot


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    profiles = [
        {**rule, "digest": profile_digest(str(rule["profile"]))} for rule in profile_snapshot()
    ]
    content = (
        json.dumps({"schema_version": "2.0", "profiles": profiles}, indent=2, sort_keys=True) + "\n"
    )
    path = Path(__file__).resolve().parents[1] / "config" / "scan-profiles.json"
    if args.check:
        current = path.read_text(encoding="utf-8") if path.exists() else ""
        if current != content:
            diff = "".join(
                difflib.unified_diff(
                    current.splitlines(keepends=True),
                    content.splitlines(keepends=True),
                    fromfile="config/scan-profiles.json",
                    tofile="generated scan profile export",
                )
            )
            raise SystemExit(
                "Scan profile export drift; run scripts/export_profiles.py\n"
                f"current_sha256={hashlib.sha256(current.encode()).hexdigest()} "
                f"expected_sha256={hashlib.sha256(content.encode()).hexdigest()}\n"
                f"{''.join(diff.splitlines(keepends=True)[:80])}"
            )
    else:
        path.write_text(content, encoding="utf-8")


if __name__ == "__main__":
    main()


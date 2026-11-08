"""Export the pinned standards catalogue embedded in frozen report snapshots."""

import argparse
import json
from pathlib import Path

from aegistrace.standards import catalogue_payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    arguments = parser.parse_args()
    target = Path(__file__).resolve().parents[1] / "schemas/standards-catalog.json"
    expected = (json.dumps(catalogue_payload(), indent=2, sort_keys=True) + "\n").encode()
    if arguments.check:
        if not target.is_file() or target.read_bytes() != expected:
            raise SystemExit(f"Standards catalogue drift: {target.name}")
    else:
        target.write_bytes(expected)


if __name__ == "__main__":
    main()

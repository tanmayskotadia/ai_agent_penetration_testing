"""Publish deterministic JSON Schema from executable domain contracts."""

import argparse
import json
from pathlib import Path

from aegistrace.domain import CONTRACTS


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1] / "schemas" / "domain"
    root.mkdir(parents=True, exist_ok=True)
    for name, contract in CONTRACTS.items():
        path = root / f"{name}.json"
        value = json.dumps(contract.model_json_schema(), indent=2, sort_keys=True) + "\n"
        if args.check:
            if not path.is_file() or path.read_text(encoding="utf-8") != value:
                raise SystemExit(f"schema drift: {path.name}")
        else:
            path.write_text(value, encoding="utf-8")


if __name__ == "__main__":
    main()

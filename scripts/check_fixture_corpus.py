"""Check corpus hashes/provenance/splits without scanning targets or inventing labels."""

import argparse
import json
from pathlib import Path

from aegistrace.fixtures import inspect_corpus


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=root / "tests/fixtures/manifest.json")
    parser.add_argument("--labels", type=Path, default=root / "evaluation/ground-truth.json")
    args = parser.parse_args()
    result = inspect_corpus(args.manifest, args.labels, root)
    print(json.dumps(result, indent=2))
    return 0 if result["ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())

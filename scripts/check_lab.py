"""Check local organizer-lab manifest consistency without starting or contacting targets."""

import argparse
from pathlib import Path

from aegistrace.lab import check_lab


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path("config/authorized-lab.yaml"))
    parser.add_argument("--authorization-document", type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument(
        "--profile",
        required=True,
        choices=["discovery", "passive-web", "active-web", "controlled-validation"],
    )
    args = parser.parse_args()
    decision = check_lab(args.manifest, args.authorization_document, args.target, args.profile)
    print(decision.model_dump_json(indent=2))
    return 0 if decision.ready else 2


if __name__ == "__main__":
    raise SystemExit(main())

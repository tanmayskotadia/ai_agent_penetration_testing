"""Export a signed audit anchor outside the working database without printing secrets."""

import argparse
import json
from pathlib import Path
from uuid import UUID

from aegistrace.audit import checkpoint
from aegistrace.db import make_engine
from aegistrace.settings import Settings


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("assessment_id", type=UUID)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    config = Settings()  # type: ignore[call-arg]
    engine = make_engine(config)
    with engine.begin() as connection:
        anchor = checkpoint(connection, args.assessment_id, config.app_secret.get_secret_value())
    engine.dispose()
    # Exclusive creation: never overwrite a previously retained anchor.
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(anchor, stream, indent=2)
        stream.write("\n")
    print("Signed checkpoint exported; retain a copy in independently controlled storage.")


if __name__ == "__main__":
    main()

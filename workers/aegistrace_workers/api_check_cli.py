"""Run one approved job on a private isolated worker, with no HTTP execution route."""

import argparse
import json
import time
from uuid import UUID

from aegistrace.api_check_schema import api_checks
from aegistrace.api_check_worker import execute_check, reconcile_expired
from aegistrace.db import make_engine
from aegistrace.policy import PolicyError
from aegistrace.settings import Settings
from sqlalchemy import select


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("assessment_id", type=UUID, nargs="?")
    parser.add_argument("check_id", type=UUID, nargs="?")
    parser.add_argument(
        "--poll",
        action="store_true",
        help="Consume the durable approved queue on this private runner",
    )
    args = parser.parse_args()
    config = Settings()  # type: ignore[call-arg]
    engine = make_engine(config)
    try:
        if not args.poll and (args.assessment_id is None or args.check_id is None):
            parser.error("supply assessment_id and check_id, or --poll")
        while True:
            reconcile_expired(engine)
            if args.poll:
                with engine.connect() as connection:
                    row = connection.execute(
                        select(api_checks.c.assessment_id, api_checks.c.id)
                        .where(api_checks.c.state == "queued")
                        .order_by(api_checks.c.id)
                        .limit(1)
                    ).first()
                if row is None:
                    time.sleep(2)
                    continue
                assessment_id, check_id = UUID(row[0]), UUID(row[1])
            else:
                assessment_id, check_id = args.assessment_id, args.check_id
            try:
                result = execute_check(engine, config, assessment_id, check_id)
                print(
                    json.dumps({"check_id": str(check_id), "result_sha256": result.get("sha256")})
                )
            except PolicyError:
                with engine.begin() as connection:
                    connection.execute(
                        api_checks.update()
                        .where(api_checks.c.id == str(check_id), api_checks.c.state == "queued")
                        .values(state="denied")
                    )
            if not args.poll:
                break
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()

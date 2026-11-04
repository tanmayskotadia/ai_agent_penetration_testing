"""Operator bootstrap in a trusted runtime; credentials never printed or passed in argv."""

import argparse
import getpass

from aegistrace.db import make_engine
from aegistrace.identity_service import create_principal
from aegistrace.settings import Settings


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("username")
    parser.add_argument(
        "--role", choices=["analyst", "reviewer", "admin", "auditor"], default="analyst"
    )
    args = parser.parse_args()
    password = getpass.getpass("New password (12–128 characters): ")
    if password != getpass.getpass("Confirm password: "):
        raise SystemExit("Passwords differ; no user created")
    engine = make_engine(Settings())  # type: ignore[call-arg]
    with engine.begin() as connection:
        create_principal(connection, args.username, password, args.role)
    engine.dispose()
    print("Identity created; password not printed. Sign in through the API.")


if __name__ == "__main__":
    main()

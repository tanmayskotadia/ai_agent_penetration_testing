"""Create local development configuration without displaying secrets or overwriting it."""

import argparse
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--smoke", action="store_true", help="SQLite API smoke mode; not PostgreSQL/queue proof"
    )
    args = parser.parse_args()
    target = ROOT / ".env"
    if target.exists():
        raise SystemExit(".env already exists; refusing to overwrite private configuration.")
    password = secrets.token_hex(32)
    database = f"postgresql+psycopg://aegistrace:{password}@127.0.0.1:5432/aegistrace"
    if args.smoke:
        (ROOT / "data").mkdir(exist_ok=True)
        database = "sqlite:///data/smoke.db"
    target.write_text(
        f"APP_SECRET={secrets.token_hex(32)}\nPOSTGRES_PASSWORD={password}\n"
        f"DATABASE_URL={database}\nREDIS_URL=redis://127.0.0.1:6379/0\nENVIRONMENT=development\n",
        encoding="utf-8",
        newline="\n",
    )
    try:
        target.chmod(0o600)
    except OSError:
        pass  # Windows access is governed by the user's existing directory ACLs.
    print("Created ignored .env; no secrets printed. Live scanning remains unavailable.")


if __name__ == "__main__":
    main()

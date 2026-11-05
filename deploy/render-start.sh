#!/bin/sh
set -eu

uv run --no-sync alembic upgrade head
exec uv run --no-sync uvicorn aegistrace.api:create_app --factory \
  --host 0.0.0.0 --port "${PORT:-8000}"

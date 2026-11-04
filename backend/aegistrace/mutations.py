"""Atomic idempotency: receipt and domain change commit or roll back together."""

import hashlib
import json
from collections.abc import Callable
from typing import Any
from uuid import UUID

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import Connection, Engine, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import IntegrityError

from aegistrace.api_schema import receipts
from aegistrace.auth import Identity
from aegistrace.repository import require_owner


def mutation(
    engine: Engine,
    request: Request,
    actor: Identity,
    payload: object,
    operation: Callable[[Connection], dict[str, Any]],
    status: int = 201,
) -> JSONResponse:
    if actor.role == "auditor":
        raise HTTPException(403, "Read-only role")
    try:
        UUID(request.headers["X-Request-ID"])
        key = request.headers["Idempotency-Key"]
        if not 8 <= len(key) <= 128 or not key.isascii() or any(ord(c) < 33 for c in key):
            raise ValueError("invalid key")
    except (KeyError, ValueError) as error:
        raise HTTPException(
            422, "Mutations require a UUID X-Request-ID and an 8–128 character Idempotency-Key"
        ) from error
    route = request.method + " " + request.url.path
    request_digest = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()
    key_digest = hashlib.sha256(key.encode()).hexdigest()
    condition = (
        (receipts.c.actor_id == actor.subject)
        & (receipts.c.route == route)
        & (receipts.c.key_digest == key_digest)
    )
    try:
        with engine.begin() as connection:
            parts = request.url.path.split("/")
            if len(parts) > 4 and parts[3] == "assessments":
                require_owner(connection, UUID(parts[4]), actor.subject)
            insert = pg_insert if connection.dialect.name == "postgresql" else sqlite_insert
            connection.execute(
                insert(receipts)
                .values(
                    actor_id=actor.subject,
                    route=route,
                    key_digest=key_digest,
                    request_digest=request_digest,
                )
                .on_conflict_do_nothing()
            )
            row = (
                connection.execute(select(receipts).where(condition).with_for_update())
                .mappings()
                .one()
            )
            if row["request_digest"] != request_digest:
                raise HTTPException(409, "Idempotency key already used with different input")
            if row["response"] is not None:
                return JSONResponse(
                    row["response"], row["status_code"], headers={"Idempotent-Replay": "true"}
                )
            response = operation(connection)
            connection.execute(
                receipts.update().where(condition).values(response=response, status_code=status)
            )
        return JSONResponse(response, status)
    except LookupError as error:
        raise HTTPException(404, "Resource not found") from error
    except IntegrityError as error:
        raise HTTPException(409, "Conflicting resource or revision") from error
    except ValueError as error:
        raise HTTPException(422, str(error)) from error

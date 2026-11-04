"""Attributable, sequenced history with external-checkpoint verification."""

import hashlib
import json
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field
from sqlalchemy import Connection, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from aegistrace.audit_schema import events, heads
from aegistrace.auth import seal, unseal

GENESIS = "0" * 64
request_context: ContextVar[tuple[UUID, UUID] | None] = ContextVar(
    "audit_request_context", default=None
)


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["1.0"] = "1.0"
    event_id: UUID = Field(default_factory=uuid4)
    assessment_id: UUID
    actor_id: str = Field(min_length=1, max_length=200)
    actor_kind: Literal["human", "service", "ai-proposal"] = "human"
    created_at: AwareDatetime = Field(default_factory=lambda: datetime.now(UTC))
    correlation_id: UUID
    request_id: UUID
    action: str = Field(pattern=r"^[a-z][a-z0-9.-]{0,99}$")
    action_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    resource_id: UUID | None = None
    policy_version: str = Field(default="m02-v1", min_length=1, max_length=100)
    scope_revision: int | None = Field(default=None, ge=1)
    plan_revision: int | None = Field(default=None, ge=1)
    outcome: Literal[
        "requested", "accepted", "denied", "pending", "completed", "partial", "failed", "unknown"
    ]


def digest(previous: str, sequence: int, payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        {"previous": previous, "sequence": sequence, "event": payload},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def append_event(connection: Connection, event: AuditEvent) -> dict[str, Any]:
    insert = pg_insert if connection.dialect.name == "postgresql" else sqlite_insert
    connection.execute(
        insert(heads)
        .values(assessment_id=str(event.assessment_id), sequence=0, digest=GENESIS)
        .on_conflict_do_nothing(index_elements=[heads.c.assessment_id])
    )
    head = (
        connection.execute(
            select(heads).where(heads.c.assessment_id == str(event.assessment_id)).with_for_update()
        )
        .mappings()
        .one()
    )
    if connection.execute(
        select(events.c.event_id).where(events.c.event_id == str(event.event_id))
    ).first():
        raise ValueError("audit event replay rejected")
    sequence = head["sequence"] + 1
    payload = event.model_dump(mode="json")
    value = digest(head["digest"], sequence, payload)
    row = dict(
        assessment_id=str(event.assessment_id),
        sequence=sequence,
        event_id=str(event.event_id),
        payload=payload,
        previous_digest=head["digest"],
        digest=value,
    )
    connection.execute(events.insert().values(**row))
    connection.execute(
        heads.update()
        .where(heads.c.assessment_id == str(event.assessment_id))
        .values(sequence=sequence, digest=value)
    )
    return row


def read_events(
    connection: Connection, assessment_id: UUID, after: int = 0, limit: int = 100
) -> list[dict[str, Any]]:
    if after < 0 or not 1 <= limit <= 1000:
        raise ValueError("invalid event cursor or limit")
    return [
        dict(row)
        for row in connection.execute(
            select(events)
            .where(events.c.assessment_id == str(assessment_id), events.c.sequence > after)
            .order_by(events.c.sequence)
            .limit(limit)
        ).mappings()
    ]


def verify_chain(rows: list[dict[str, Any]], expected_sequence: int, expected_digest: str) -> bool:
    previous = GENESIS
    seen: set[str] = set()
    for sequence, row in enumerate(rows, 1):
        try:
            event = AuditEvent.model_validate(row["payload"])
            if (
                str(event.event_id) in seen
                or row["sequence"] != sequence
                or row["previous_digest"] != previous
                or str(event.event_id) != row["event_id"]
                or str(event.assessment_id) != row["assessment_id"]
            ):
                return False
            seen.add(str(event.event_id))
            previous = digest(previous, sequence, row["payload"])
            if previous != row["digest"]:
                return False
        except (ValueError, KeyError, TypeError):
            return False
    return len(rows) == expected_sequence and previous == expected_digest


def checkpoint(connection: Connection, assessment_id: UUID, secret: str) -> dict[str, Any]:
    head = (
        connection.execute(select(heads).where(heads.c.assessment_id == str(assessment_id)))
        .mappings()
        .one_or_none()
    )
    # Signed checkpoint is for external retention, not an expiring access credential.
    payload = {
        "assessment_id": str(assessment_id),
        "sequence": head["sequence"] if head else 0,
        "digest": head["digest"] if head else GENESIS,
        "created_at": datetime.now(UTC).isoformat(),
        "expires": 253402300799,
    }
    return {
        "checkpoint": payload,
        "signature": seal(secret, "audit-checkpoint", payload),
        "external_retention": "required to detect administrator rollback beyond this database",
    }


def verify_checkpoint(
    rows: list[dict[str, Any]], token: str, secret: str, assessment_id: UUID
) -> bool:
    try:
        anchor = unseal(secret, "audit-checkpoint", token)
        if anchor["assessment_id"] != str(assessment_id):
            return False
        count = int(anchor["sequence"])  # type: ignore[call-overload]
        return verify_chain(rows, count, str(anchor["digest"]))
    except (ValueError, KeyError, TypeError):
        return False

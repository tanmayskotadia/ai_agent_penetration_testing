"""Canonical persistence; all access is explicitly assessment-bound."""

from typing import Any
from uuid import UUID

from sqlalchemy import Connection, select

from aegistrace import schema_v1 as db
from aegistrace.domain import CONTRACTS, Assessment, Contract, Finding, Observation, Occurrence


def insert_record(connection: Connection, collection: str, record: Contract) -> None:
    expected = CONTRACTS[collection]
    if not isinstance(record, expected):
        raise ValueError("collection/contract mismatch")
    table = db.metadata.tables[collection]
    payload = record.model_dump(mode="json")
    values = {name: payload[name] for name in table.c.keys() if name != "payload"}
    if isinstance(record, Observation):
        evidence = get_record(
            connection, "evidence_references", record.assessment_id, record.evidence_id
        )
        if evidence["run_id"] != str(record.run_id):
            raise ValueError("observation evidence belongs to another run")
    if isinstance(record, Occurrence):
        observation = get_record(
            connection, "observations", record.assessment_id, record.observation_id
        )
        if observation["asset_id"] != str(record.asset_id):
            raise ValueError("occurrence asset differs from source observation")
    if isinstance(record, Finding) and record.decision_id is not None:
        decision = get_record(connection, "decisions", record.assessment_id, record.decision_id)
        if decision["information_kind"] != "reviewer-decision":
            raise ValueError("an AI decision cannot confirm a finding")
    connection.execute(table.insert().values(**values, payload=payload))


def get_record(
    connection: Connection, collection: str, assessment_id: UUID, record_id: UUID
) -> dict[str, Any]:
    table = db.metadata.tables[collection]
    condition = table.c.id == str(record_id)
    condition &= (
        table.c.id == str(assessment_id)
        if collection == "assessments"
        else table.c.assessment_id == str(assessment_id)
    )
    payload = connection.execute(select(table.c.payload).where(condition)).scalar_one_or_none()
    if payload is None:
        raise LookupError("resource not found")
    return dict(payload)


def require_owner(connection: Connection, assessment_id: UUID, actor_id: str) -> Assessment:
    payload = connection.execute(
        select(db.assessments.c.payload).where(
            db.assessments.c.id == str(assessment_id), db.assessments.c.owner_id == actor_id
        )
    ).scalar_one_or_none()
    if payload is None:
        raise LookupError("resource not found")
    return Assessment.model_validate(payload)

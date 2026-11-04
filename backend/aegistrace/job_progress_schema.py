"""Persisted, append-only telemetry for truthful worker progress."""

import sqlalchemy as sa

from aegistrace.job_schema import jobs
from aegistrace.schema_v1 import assessments, metadata

progress_events = sa.Table(
    "job_progress_events",
    metadata,
    sa.Column("job_id", sa.String(36), sa.ForeignKey(jobs.c.id), primary_key=True),
    sa.Column("sequence", sa.Integer(), primary_key=True),
    sa.Column("assessment_id", sa.String(36), sa.ForeignKey(assessments.c.id), nullable=False),
    sa.Column("schema_version", sa.String(10), nullable=False),
    sa.Column("event_id", sa.String(36), nullable=False, unique=True),
    sa.Column("kind", sa.String(40), nullable=False),
    sa.Column("state", sa.String(30), nullable=False),
    sa.Column("attempt", sa.Integer(), nullable=False),
    sa.Column("created_at", sa.Float(), nullable=False),
    sa.Column("worker_id", sa.String(36)),
    sa.Column("epoch", sa.Integer()),
    sa.Column("elapsed_ms", sa.Integer()),
    sa.Column("tool_version", sa.String(80)),
    sa.Column("exit_code", sa.Integer()),
    sa.Column("diagnostic_code", sa.String(50)),
    sa.Column("diagnostic", sa.String(300)),
    sa.CheckConstraint("sequence >= 1"),
    sa.CheckConstraint("attempt >= 0"),
)


def protect_progress(connection: sa.Connection) -> None:
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(
            "CREATE FUNCTION aegis_progress_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'job progress history is immutable'; END $$"
        )
        connection.exec_driver_sql(
            "CREATE TRIGGER job_progress_immutable BEFORE UPDATE OR DELETE ON job_progress_events FOR EACH ROW EXECUTE FUNCTION aegis_progress_immutable()"
        )
    else:
        for action in ["UPDATE", "DELETE"]:
            connection.exec_driver_sql(
                f"CREATE TRIGGER job_progress_no_{action.lower()} BEFORE {action} ON job_progress_events BEGIN SELECT RAISE(ABORT, 'job progress history is immutable'); END"
            )

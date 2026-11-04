"""Frozen migration 0016: immutable result/export revisions and quarantined late bytes."""

import sqlalchemy as sa

from aegistrace.schema_v1 import metadata

revisions = sa.Table(
    "result_revisions",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessments.id"), nullable=False),
    sa.Column("run_id", sa.String(36), sa.ForeignKey("tool_runs.id"), nullable=False),
    sa.Column("revision", sa.Integer(), nullable=False),
    sa.Column("input_key", sa.String(64), nullable=False),
    sa.Column("payload", sa.JSON(), nullable=False),
    sa.UniqueConstraint("run_id", "revision"),
    sa.UniqueConstraint("run_id", "input_key"),
)
exports = sa.Table(
    "result_exports",
    metadata,
    sa.Column("id", sa.String(36), sa.ForeignKey("report_snapshots.id"), primary_key=True),
    sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessments.id"), nullable=False),
    sa.Column("sha256", sa.String(64), nullable=False),
    sa.Column("payload", sa.JSON(), nullable=False),
)
late_outputs = sa.Table(
    "late_job_outputs",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("job_id", sa.String(36), sa.ForeignKey("scan_jobs.id"), nullable=False),
    sa.Column("sha256", sa.String(64), nullable=False),
    sa.Column("size", sa.Integer(), nullable=False),
    sa.Column("nonce", sa.LargeBinary(), nullable=False),
    sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
    sa.Column("key_id", sa.String(100), nullable=False),
    sa.Column("expires_at", sa.Float(), nullable=False),
    sa.Column("state", sa.String(50), nullable=False),
    sa.Column("evidence_id", sa.String(36), sa.ForeignKey("evidence_references.id")),
    sa.Column("worker_id", sa.String(36), nullable=False),
    sa.Column("epoch", sa.Integer(), nullable=False),
    sa.UniqueConstraint("job_id", "sha256"),
)


def protect_results(connection: sa.Connection) -> None:
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(
            "CREATE FUNCTION aegis_results_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'result/export revisions are immutable'; END $$"
        )
    for name in ["result_revisions", "result_exports"]:
        if connection.dialect.name == "postgresql":
            connection.exec_driver_sql(
                f"CREATE TRIGGER {name}_immutable BEFORE UPDATE OR DELETE ON {name} FOR EACH ROW EXECUTE FUNCTION aegis_results_immutable()"
            )
        else:
            for action in ["UPDATE", "DELETE"]:
                connection.exec_driver_sql(
                    f"CREATE TRIGGER {name}_no_{action.lower()} BEFORE {action} ON {name} BEGIN SELECT RAISE(ABORT, 'result/export revisions are immutable'); END"
                )

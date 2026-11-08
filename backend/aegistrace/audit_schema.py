"""Frozen migration 0004 definitions and append-only database guards."""

import sqlalchemy as sa

from aegistrace.schema_v1 import metadata

heads = sa.Table(
    "audit_heads",
    metadata,
    sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessments.id"), primary_key=True),
    sa.Column("sequence", sa.Integer(), nullable=False),
    sa.Column("digest", sa.String(64), nullable=False),
)
events = sa.Table(
    "audit_events",
    metadata,
    sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessments.id"), primary_key=True),
    sa.Column("sequence", sa.Integer(), primary_key=True),
    sa.Column("event_id", sa.String(36), nullable=False, unique=True),
    sa.Column("payload", sa.JSON(), nullable=False),
    sa.Column("previous_digest", sa.String(64), nullable=False),
    sa.Column("digest", sa.String(64), nullable=False),
    sa.CheckConstraint("sequence >= 1"),
)


def install_guards(connection: sa.Connection) -> None:
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql("""CREATE FUNCTION aegistrace_deny_audit_mutation() RETURNS trigger
        LANGUAGE plpgsql SET search_path = pg_catalog
        AS $$ BEGIN RAISE EXCEPTION 'audit history is append-only'; END; $$""")
        connection.exec_driver_sql(
            "CREATE TRIGGER audit_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON audit_events FOR EACH STATEMENT EXECUTE FUNCTION aegistrace_deny_audit_mutation()"
        )
    elif connection.dialect.name == "sqlite":
        for action in ["UPDATE", "DELETE"]:
            connection.exec_driver_sql(
                f"CREATE TRIGGER audit_no_{action.lower()} BEFORE {action} ON audit_events BEGIN SELECT RAISE(ABORT, 'audit history is append-only'); END"
            )


def remove_guards(connection: sa.Connection) -> None:
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql("DROP TRIGGER audit_append_only ON audit_events")
        connection.exec_driver_sql("DROP FUNCTION aegistrace_deny_audit_mutation()")
    elif connection.dialect.name == "sqlite":
        for action in ["update", "delete"]:
            connection.exec_driver_sql(f"DROP TRIGGER audit_no_{action}")

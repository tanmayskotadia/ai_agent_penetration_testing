"""Frozen migration 0015: append-only content-bound recorded replay manifests."""

import sqlalchemy as sa

from aegistrace.schema_v1 import metadata

manifests = sa.Table(
    "replay_manifests",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessments.id"), nullable=False),
    sa.Column("sha256", sa.String(64), nullable=False),
    sa.Column("signature", sa.String(64), nullable=False),
    sa.Column("payload", sa.JSON(), nullable=False),
)


def protect_replays(connection: sa.Connection) -> None:
    if connection.dialect.name == "postgresql":
        connection.exec_driver_sql(
            "CREATE FUNCTION aegis_replay_immutable() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'replay manifests are immutable'; END $$"
        )
        connection.exec_driver_sql(
            "CREATE TRIGGER replay_immutable BEFORE UPDATE OR DELETE ON replay_manifests FOR EACH ROW EXECUTE FUNCTION aegis_replay_immutable()"
        )
    else:
        for action in ["UPDATE", "DELETE"]:
            connection.exec_driver_sql(
                f"CREATE TRIGGER replay_no_{action.lower()} BEFORE {action} ON replay_manifests BEGIN SELECT RAISE(ABORT, 'replay manifests are immutable'); END"
            )

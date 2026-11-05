"""Link normalized observations to their exact web endpoint when available."""

import sqlalchemy as sa
from alembic import op

revision = "0019_observation_locations"
down_revision = "0018_api_checks"
branch_labels = None
depends_on = None


def upgrade() -> None:
    existing = {column["name"] for column in sa.inspect(op.get_bind()).get_columns("observations")}
    # The initial schema migration imports the current domain metadata when a database is
    # created from scratch. Older databases already at 0018 do not have these columns.
    if {"service_id", "endpoint_id"} <= existing:
        return
    with op.batch_alter_table(
        "observations",
        naming_convention={"fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s"},
    ) as batch:
        if "service_id" not in existing:
            batch.add_column(sa.Column("service_id", sa.String(36), nullable=True))
        if "endpoint_id" not in existing:
            batch.add_column(sa.Column("endpoint_id", sa.String(36), nullable=True))
        batch.create_foreign_key(
            "fk_observations_assessment_service",
            "services",
            ["assessment_id", "service_id"],
            ["assessment_id", "id"],
        )
        batch.create_foreign_key(
            "fk_observations_assessment_endpoint",
            "endpoints",
            ["assessment_id", "endpoint_id"],
            ["assessment_id", "id"],
        )


def downgrade() -> None:
    inspector = sa.inspect(op.get_bind())
    existing = {column["name"] for column in inspector.get_columns("observations")}
    if not {"service_id", "endpoint_id"} & existing:
        return
    foreign_keys = inspector.get_foreign_keys("observations")
    endpoint_constraint = next(
        (
            key["name"] or "fk_observations_assessment_id_endpoints"
            for key in foreign_keys
            if key["referred_table"] == "endpoints" and "endpoint_id" in key["constrained_columns"]
        ),
        "fk_observations_assessment_id_endpoints",
    )
    service_constraint = next(
        (
            key["name"] or "fk_observations_assessment_id_services"
            for key in foreign_keys
            if key["referred_table"] == "services" and "service_id" in key["constrained_columns"]
        ),
        "fk_observations_assessment_id_services",
    )
    with op.batch_alter_table(
        "observations",
        naming_convention={"fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s"},
    ) as batch:
        if "endpoint_id" in existing:
            batch.drop_constraint(endpoint_constraint, type_="foreignkey")
            batch.drop_column("endpoint_id")
        if "service_id" in existing:
            batch.drop_constraint(service_constraint, type_="foreignkey")
            batch.drop_column("service_id")

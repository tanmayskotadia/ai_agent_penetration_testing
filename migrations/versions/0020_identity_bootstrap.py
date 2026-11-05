"""Add the single-use first-admin bootstrap claim."""

import sqlalchemy as sa
from alembic import op

revision = "0020_identity_bootstrap"
down_revision = "0019_observation_locations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "identity_bootstrap_state",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("consumed", sa.Boolean(), nullable=False),
    )
    op.bulk_insert(
        sa.table(
            "identity_bootstrap_state",
            sa.column("id", sa.Integer()),
            sa.column("consumed", sa.Boolean()),
        ),
        [{"id": 1, "consumed": False}],
    )


def downgrade() -> None:
    op.drop_table("identity_bootstrap_state")

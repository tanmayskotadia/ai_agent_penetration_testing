"""Persist container diagnostics without manufacturing normalized findings."""

from aegistrace.ingestion_schema import inspections
from alembic import op

revision = "0006_ingestion"
down_revision = "0005_api"
branch_labels = None
depends_on = None


def upgrade() -> None:
    inspections.create(op.get_bind())


def downgrade() -> None:
    inspections.drop(op.get_bind())

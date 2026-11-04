"""Versioned execution policy and usage reservations."""

from aegistrace.policy_schema import policies, usage
from alembic import op

revision = "0007_policy"
down_revision = "0006_ingestion"
branch_labels = None
depends_on = None


def upgrade() -> None:
    policies.create(op.get_bind())
    usage.create(op.get_bind())


def downgrade() -> None:
    usage.drop(op.get_bind())
    policies.drop(op.get_bind())

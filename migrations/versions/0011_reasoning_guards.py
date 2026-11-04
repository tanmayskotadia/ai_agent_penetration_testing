"""Guarded inference proposals without execution authority."""

from aegistrace.reasoning_schema import proposals
from alembic import op

revision = "0011_reasoning_guards"
down_revision = "0010_control"
branch_labels = None
depends_on = None


def upgrade() -> None:
    proposals.create(op.get_bind())


def downgrade() -> None:
    proposals.drop(op.get_bind())

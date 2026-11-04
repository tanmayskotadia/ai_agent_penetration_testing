"""Transactional idempotency receipts and honest workflow request states."""

from aegistrace.api_schema import receipts, resources
from alembic import op

revision = "0005_api"
down_revision = "0004_audit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    receipts.create(op.get_bind())
    resources.create(op.get_bind())


def downgrade() -> None:
    resources.drop(op.get_bind())
    receipts.drop(op.get_bind())

"""Human action approvals and single-use dispatch claims."""

from aegistrace.approval_schema import claims, grants
from alembic import op

revision = "0009_approvals"
down_revision = "0008_identity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    grants.create(op.get_bind())
    claims.create(op.get_bind())


def downgrade() -> None:
    claims.drop(op.get_bind())
    grants.drop(op.get_bind())

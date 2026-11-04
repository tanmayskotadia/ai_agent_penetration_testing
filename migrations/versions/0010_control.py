"""Persistent emergency stop and execution leases."""

from aegistrace.control_schema import controls, executions
from alembic import op

revision = "0010_control"
down_revision = "0009_approvals"
branch_labels = None
depends_on = None


def upgrade() -> None:
    controls.create(op.get_bind())
    executions.create(op.get_bind())


def downgrade() -> None:
    executions.drop(op.get_bind())
    controls.drop(op.get_bind())

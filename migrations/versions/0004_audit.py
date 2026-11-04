"""Sequenced audit chain and database append-only guards."""

from aegistrace.audit_schema import events, heads, install_guards, remove_guards
from alembic import op

revision = "0004_audit"
down_revision = "0003_evidence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    connection = op.get_bind()
    heads.create(connection)
    events.create(connection)
    install_guards(connection)


def downgrade() -> None:
    connection = op.get_bind()
    remove_guards(connection)
    events.drop(connection)
    heads.drop(connection)

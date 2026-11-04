"""Encrypted evidence and attributed access/redaction records."""

from aegistrace.evidence_schema import access_events, objects
from alembic import op

revision = "0003_evidence"
down_revision = "0002_domain"
branch_labels = None
depends_on = None


def upgrade() -> None:
    objects.create(op.get_bind())
    access_events.create(op.get_bind())


def downgrade() -> None:
    access_events.drop(op.get_bind())
    objects.drop(op.get_bind())

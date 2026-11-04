"""Canonical domain; frozen versioned table definitions, no assessment seed data."""

from aegistrace.schema_v1 import DOMAIN_TABLES, metadata
from alembic import op

revision = "0002_domain"
down_revision = "0001_foundation"
branch_labels = None
depends_on = None


def upgrade() -> None:
    metadata.create_all(op.get_bind(), tables=DOMAIN_TABLES, checkfirst=False)


def downgrade() -> None:
    metadata.drop_all(op.get_bind(), tables=DOMAIN_TABLES, checkfirst=False)

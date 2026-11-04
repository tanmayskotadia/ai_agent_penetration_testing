"""Candidate source-linked Nmap normalization."""

from aegistrace.normalization_schema import normalizations
from alembic import op

revision = "0013_normalizations"
down_revision = "0012_jobs"
branch_labels = None
depends_on = None


def upgrade() -> None:
    normalizations.create(op.get_bind())


def downgrade() -> None:
    normalizations.drop(op.get_bind())

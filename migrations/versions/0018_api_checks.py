"""Encrypted API credentials and persisted approved operation checks."""

from aegistrace.api_check_schema import api_checks, api_secrets
from alembic import op

revision = "0018_api_checks"
down_revision = "0017_job_progress"
branch_labels = None
depends_on = None


def upgrade() -> None:
    api_secrets.create(op.get_bind())
    api_checks.create(op.get_bind())


def downgrade() -> None:
    api_checks.drop(op.get_bind())
    api_secrets.drop(op.get_bind())

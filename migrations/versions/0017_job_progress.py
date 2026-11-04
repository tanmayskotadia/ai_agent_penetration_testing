"""Append-only worker status events with sanitized diagnostics."""

from aegistrace.job_progress_schema import progress_events, protect_progress
from alembic import op

revision = "0017_job_progress"
down_revision = "0016_results"
branch_labels = None
depends_on = None


def upgrade() -> None:
    progress_events.create(op.get_bind())
    protect_progress(op.get_bind())


def downgrade() -> None:
    progress_events.drop(op.get_bind())
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP FUNCTION aegis_progress_immutable()")

"""Durable approved jobs and transactional dispatch."""

from aegistrace.job_schema import chunks, jobs, outbox
from alembic import op

revision = "0012_jobs"
down_revision = "0011_reasoning_guards"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table in [jobs, outbox, chunks]:
        table.create(op.get_bind())


def downgrade() -> None:
    for table in [chunks, outbox, jobs]:
        table.drop(op.get_bind())

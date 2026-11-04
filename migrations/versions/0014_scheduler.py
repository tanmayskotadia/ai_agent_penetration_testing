"""Bounded shared job admission and scheduling."""

from aegistrace.scheduler_schema import admissions, buckets, scheduler_lock
from alembic import op

revision = "0014_scheduler"
down_revision = "0013_normalizations"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table in [scheduler_lock, buckets, admissions]:
        table.create(op.get_bind())


def downgrade() -> None:
    for table in [admissions, buckets, scheduler_lock]:
        table.drop(op.get_bind())

"""Immutable recorded replay manifests."""

from aegistrace.replay_schema import manifests, protect_replays
from alembic import op

revision = "0015_replay"
down_revision = "0014_scheduler"
branch_labels = None
depends_on = None


def upgrade() -> None:
    manifests.create(op.get_bind())
    protect_replays(op.get_bind())


def downgrade() -> None:
    manifests.drop(op.get_bind())
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP FUNCTION aegis_replay_immutable()")

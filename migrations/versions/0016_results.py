"""Immutable result versions and late output quarantine."""

from aegistrace.result_schema import exports, late_outputs, protect_results, revisions
from alembic import op

revision = "0016_results"
down_revision = "0015_replay"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table in [revisions, exports, late_outputs]:
        table.create(op.get_bind())
    protect_results(op.get_bind())


def downgrade() -> None:
    for table in [late_outputs, exports, revisions]:
        table.drop(op.get_bind())
    if op.get_bind().dialect.name == "postgresql":
        op.execute("DROP FUNCTION aegis_results_immutable()")

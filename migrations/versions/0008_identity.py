"""Revocable identities and resource membership."""

from aegistrace.identity_schema import attempts, members, principals, sessions
from alembic import op

revision = "0008_identity"
down_revision = "0007_policy"
branch_labels = None
depends_on = None


def upgrade() -> None:
    for table in [principals, sessions, members, attempts]:
        table.create(op.get_bind())


def downgrade() -> None:
    for table in [attempts, members, sessions, principals]:
        table.drop(op.get_bind())

"""Frozen migration 0011: inferred proposals are not confirmed findings or approvals."""

import sqlalchemy as sa

from aegistrace.schema_v1 import metadata

proposals = sa.Table(
    "reasoning_proposals",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessments.id"), nullable=False),
    sa.Column("payload", sa.JSON(), nullable=False),
)

"""Frozen migration 0009: action-bound review and one dispatch claim per approval."""

import sqlalchemy as sa

from aegistrace.schema_v1 import metadata

grants = sa.Table(
    "action_approvals",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessments.id"), nullable=False),
    sa.Column("policy_id", sa.String(36), sa.ForeignKey("execution_policies.id"), nullable=False),
    sa.Column("state", sa.String(30), nullable=False),
    sa.Column("action_digest", sa.String(64), nullable=False),
    sa.Column("payload", sa.JSON(), nullable=False),
    sa.Column("reviewer", sa.String(200)),
    sa.Column("reviewer_epoch", sa.Integer()),
    sa.Column("reviewer_session", sa.String(36)),
)
claims = sa.Table(
    "dispatch_claims",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column(
        "approval_id",
        sa.String(36),
        sa.ForeignKey("action_approvals.id"),
        nullable=False,
        unique=True,
    ),
    sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessments.id"), nullable=False),
    sa.Column("payload", sa.JSON(), nullable=False),
)

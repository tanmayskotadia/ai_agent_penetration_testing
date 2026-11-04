"""Frozen migration 0010: persistent stop epoch and worker cancellation fences."""

import sqlalchemy as sa

from aegistrace.schema_v1 import metadata

controls = sa.Table(
    "assessment_controls",
    metadata,
    sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessments.id"), primary_key=True),
    sa.Column("stopped", sa.Boolean(), nullable=False),
    sa.Column("epoch", sa.Integer(), nullable=False),
)
executions = sa.Table(
    "execution_controls",
    metadata,
    sa.Column("claim_id", sa.String(36), sa.ForeignKey("dispatch_claims.id"), primary_key=True),
    sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessments.id"), nullable=False),
    sa.Column("worker_id", sa.String(36), nullable=False),
    sa.Column("epoch", sa.Integer(), nullable=False),
    sa.Column("lease_until", sa.Float(), nullable=False),
    sa.Column("deadline", sa.Float(), nullable=False),
    sa.Column("started_at", sa.Float(), nullable=False),
    sa.Column("state", sa.String(40), nullable=False),
    sa.Column("kind", sa.String(20), nullable=False),
    sa.Column("reset_required", sa.Boolean(), nullable=False),
    sa.Column("reset_evidence_id", sa.String(36)),
    sa.Column("termination_evidence_id", sa.String(36)),
)

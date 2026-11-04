"""Frozen migration 0007: reviewed, immutable execution policies and atomic usage."""

import sqlalchemy as sa

from aegistrace.schema_v1 import metadata

policies = sa.Table(
    "execution_policies",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessments.id"), nullable=False),
    sa.Column("scope_id", sa.String(36), nullable=False, unique=True),
    sa.Column("payload", sa.JSON(), nullable=False),
    sa.ForeignKeyConstraint(
        ["assessment_id", "scope_id"], ["scope_versions.assessment_id", "scope_versions.id"]
    ),
)
usage = sa.Table(
    "policy_usage",
    metadata,
    sa.Column("policy_id", sa.String(36), sa.ForeignKey("execution_policies.id"), primary_key=True),
    sa.Column("window_start", sa.Float(), nullable=False),
    sa.Column("requests", sa.Integer(), nullable=False),
    sa.Column("in_flight", sa.Integer(), nullable=False),
    sa.CheckConstraint("requests >= 0 AND in_flight >= 0"),
)

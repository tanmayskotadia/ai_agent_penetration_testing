"""Frozen migration 0014: shared admission mutex, budgets and freshness fingerprints."""

import sqlalchemy as sa

from aegistrace.schema_v1 import metadata

scheduler_lock = sa.Table(
    "scheduler_lock", metadata, sa.Column("id", sa.Integer(), primary_key=True)
)
buckets = sa.Table(
    "scheduler_buckets",
    metadata,
    sa.Column("key", sa.String(100), primary_key=True),
    sa.Column("tokens", sa.Float(), nullable=False),
    sa.Column("updated_at", sa.Float(), nullable=False),
    sa.Column("rate", sa.Float(), nullable=False),
)
admissions = sa.Table(
    "scheduler_admissions",
    metadata,
    sa.Column("job_id", sa.String(36), sa.ForeignKey("scan_jobs.id"), primary_key=True),
    sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessments.id"), nullable=False),
    sa.Column("fingerprint", sa.String(64), nullable=False, index=True),
    sa.Column("targets", sa.JSON(), nullable=False),
    sa.Column("admitted_at", sa.Float(), nullable=False),
    sa.Column("validation", sa.Boolean(), nullable=False),
    sa.Column("priority", sa.Integer(), nullable=False),
)

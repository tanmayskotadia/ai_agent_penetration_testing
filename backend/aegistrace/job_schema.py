"""Frozen migration 0012: durable jobs, transactional outbox and encrypted partial output."""

import sqlalchemy as sa

from aegistrace.schema_v1 import metadata

jobs = sa.Table(
    "scan_jobs",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessments.id"), nullable=False),
    sa.Column(
        "claim_id", sa.String(36), sa.ForeignKey("dispatch_claims.id"), nullable=False, unique=True
    ),
    sa.Column("state", sa.String(30), nullable=False),
    sa.Column("attempt", sa.Integer(), nullable=False),
    sa.Column("worker_id", sa.String(36)),
    sa.Column("epoch", sa.Integer()),
    sa.Column("lease_until", sa.Float()),
    sa.Column("external_scan_id", sa.String(200)),
    sa.Column("created_at", sa.Float(), nullable=False),
    sa.Column("updated_at", sa.Float(), nullable=False),
    sa.Column("reason", sa.String(200)),
)
outbox = sa.Table(
    "job_outbox",
    metadata,
    sa.Column("job_id", sa.String(36), sa.ForeignKey("scan_jobs.id"), primary_key=True),
    sa.Column("attempts", sa.Integer(), nullable=False),
    sa.Column("available_at", sa.Float(), nullable=False),
    sa.Column("published_at", sa.Float()),
)
chunks = sa.Table(
    "job_output_chunks",
    metadata,
    sa.Column("job_id", sa.String(36), sa.ForeignKey("scan_jobs.id"), primary_key=True),
    sa.Column("sequence", sa.Integer(), primary_key=True),
    sa.Column("sha256", sa.String(64), nullable=False),
    sa.Column("size", sa.Integer(), nullable=False),
    sa.Column("nonce", sa.LargeBinary(), nullable=False),
    sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
    sa.Column("key_id", sa.String(100), nullable=False),
    sa.Column("expires_at", sa.Float(), nullable=False),
)

"""Frozen migration 0003 definitions. Original bytes are encrypted in private DB rows."""

import sqlalchemy as sa

from aegistrace.schema_v1 import metadata

objects = sa.Table(
    "evidence_objects",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("assessment_id", sa.String(36), nullable=False),
    sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
    sa.Column("nonce", sa.LargeBinary(12), nullable=False),
    sa.Column("key_id", sa.String(100), nullable=False),
    sa.Column("sha256", sa.String(64), nullable=False),
    sa.Column("size", sa.Integer(), nullable=False),
    sa.Column("expires_at", sa.String(50), nullable=False),
    sa.Column("redacted", sa.Text()),
    sa.Column("redaction_reviewed", sa.Boolean(), nullable=False, server_default=sa.false()),
    sa.ForeignKeyConstraint(
        ["assessment_id", "id"], ["evidence_references.assessment_id", "evidence_references.id"]
    ),
    sa.CheckConstraint("size > 0 AND size <= 2097152"),
)
access_events = sa.Table(
    "evidence_access_events",
    metadata,
    sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
    sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessments.id"), nullable=False),
    sa.Column("evidence_id", sa.String(36), nullable=False),
    sa.Column("actor_id", sa.String(200), nullable=False),
    sa.Column("action", sa.String(50), nullable=False),
    sa.Column("created_at", sa.String(50), nullable=False),
)

"""Migration 0018: assessment-bound encrypted secrets and durable API checks."""

import sqlalchemy as sa

from aegistrace.schema_v1 import metadata

api_secrets = sa.Table(
    "api_check_secrets",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessments.id"), nullable=False),
    sa.Column("origin", sa.String(2000), nullable=False),
    sa.Column("expires_at", sa.Float(), nullable=False),
    sa.Column("revoked", sa.Boolean(), nullable=False),
    sa.Column("key_id", sa.String(100), nullable=False),
    sa.Column("nonce", sa.LargeBinary(), nullable=False),
    sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
)
api_checks = sa.Table(
    "api_checks",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessments.id"), nullable=False),
    sa.Column("state", sa.String(30), nullable=False),
    sa.Column("payload", sa.JSON(), nullable=False),
    sa.Column("result", sa.JSON()),
)

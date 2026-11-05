"""Frozen migration 0008: identities, revocable sessions and assessment membership."""

import sqlalchemy as sa

from aegistrace.schema_v1 import metadata

bootstrap_state = sa.Table(
    "identity_bootstrap_state",
    metadata,
    sa.Column("id", sa.Integer(), primary_key=True),
    sa.Column("consumed", sa.Boolean(), nullable=False),
)

principals = sa.Table(
    "principals",
    metadata,
    sa.Column("id", sa.String(200), primary_key=True),
    sa.Column("username", sa.String(200), nullable=False, unique=True),
    sa.Column("password_hash", sa.Text()),
    sa.Column("kind", sa.String(20), nullable=False),
    sa.Column("role", sa.String(20), nullable=False),
    sa.Column("active", sa.Boolean(), nullable=False),
    sa.Column("epoch", sa.Integer(), nullable=False),
)
sessions = sa.Table(
    "identity_sessions",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("subject", sa.String(200), sa.ForeignKey("principals.id"), nullable=False),
    sa.Column("token_digest", sa.String(64), nullable=False),
    sa.Column("expires", sa.Float(), nullable=False),
    sa.Column("revoked", sa.Boolean(), nullable=False),
    sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessments.id")),
)
members = sa.Table(
    "assessment_members",
    metadata,
    sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessments.id"), primary_key=True),
    sa.Column("subject", sa.String(200), sa.ForeignKey("principals.id"), primary_key=True),
    sa.Column("role", sa.String(20), nullable=False),
    sa.Column("active", sa.Boolean(), nullable=False),
)
attempts = sa.Table(
    "login_attempts",
    metadata,
    sa.Column("key", sa.String(64), primary_key=True),
    sa.Column("window", sa.Float(), nullable=False),
    sa.Column("count", sa.Integer(), nullable=False),
)

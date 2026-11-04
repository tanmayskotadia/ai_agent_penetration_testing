"""Frozen migration 0005 definitions for atomic mutation receipts and workflow requests."""

import sqlalchemy as sa

from aegistrace.schema_v1 import metadata

receipts = sa.Table(
    "mutation_receipts",
    metadata,
    sa.Column("actor_id", sa.String(200), primary_key=True),
    sa.Column("route", sa.String(500), primary_key=True),
    sa.Column("key_digest", sa.String(64), primary_key=True),
    sa.Column("request_digest", sa.String(64), nullable=False),
    sa.Column("response", sa.JSON()),
    sa.Column("status_code", sa.Integer()),
)
resources = sa.Table(
    "workflow_resources",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessments.id"), nullable=False),
    sa.Column("kind", sa.String(30), nullable=False),
    sa.Column("payload", sa.JSON(), nullable=False),
)

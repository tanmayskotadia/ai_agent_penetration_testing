"""Frozen migration 0013: source-linked candidate native normalization snapshots."""

import sqlalchemy as sa

from aegistrace.schema_v1 import metadata

normalizations = sa.Table(
    "native_normalizations",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessments.id"), nullable=False),
    sa.Column(
        "import_id",
        sa.String(36),
        sa.ForeignKey("workflow_resources.id"),
        nullable=False,
        unique=True,
    ),
    sa.Column(
        "evidence_id", sa.String(36), sa.ForeignKey("evidence_references.id"), nullable=False
    ),
    sa.Column("payload", sa.JSON(), nullable=False),
)

"""Frozen migration 0006: quarantined/inspected imports, separate from findings."""

import sqlalchemy as sa

from aegistrace.schema_v1 import metadata

inspections = sa.Table(
    "ingestion_inspections",
    metadata,
    sa.Column("import_id", sa.String(36), sa.ForeignKey("workflow_resources.id"), primary_key=True),
    sa.Column("assessment_id", sa.String(36), sa.ForeignKey("assessments.id"), nullable=False),
    sa.Column("evidence_id", sa.String(36), nullable=False),
    sa.Column("result", sa.JSON(), nullable=False),
    sa.ForeignKeyConstraint(
        ["assessment_id", "evidence_id"],
        ["evidence_references.assessment_id", "evidence_references.id"],
    ),
)

"""Frozen relational schema for migration 0002; change through later migrations."""

import sqlalchemy as sa
from sqlalchemy.sql.schema import SchemaItem

metadata = sa.MetaData()


def entity(name: str, *extra: SchemaItem) -> sa.Table:
    return sa.Table(
        name,
        metadata,
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("assessment_id", sa.String(36), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.UniqueConstraint("assessment_id", "id"),
        sa.ForeignKeyConstraint(["assessment_id"], ["assessments.id"], ondelete="RESTRICT"),
        *extra,
    )


def link(column: str, target: str) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["assessment_id", column],
        [f"{target}.assessment_id", f"{target}.id"],
        ondelete="RESTRICT",
    )


assessments = sa.Table(
    "assessments",
    metadata,
    sa.Column("id", sa.String(36), primary_key=True),
    sa.Column("owner_id", sa.String(200), nullable=False, index=True),
    sa.Column("payload", sa.JSON(), nullable=False),
)
scope_versions = entity(
    "scope_versions",
    sa.Column("revision", sa.Integer(), nullable=False),
    sa.UniqueConstraint("assessment_id", "revision"),
    sa.CheckConstraint("revision >= 1"),
)
assets = entity(
    "assets",
    sa.Column("identifier", sa.String(500), nullable=False),
    sa.UniqueConstraint("assessment_id", "identifier"),
)
services = entity(
    "services",
    sa.Column("asset_id", sa.String(36), nullable=False),
    link("asset_id", "assets"),
)
endpoints = entity(
    "endpoints",
    sa.Column("asset_id", sa.String(36), nullable=False),
    link("asset_id", "assets"),
)
tool_runs = entity(
    "tool_runs",
    sa.Column("scope_id", sa.String(36), nullable=False),
    link("scope_id", "scope_versions"),
)
evidence_references = entity(
    "evidence_references",
    sa.Column("run_id", sa.String(36), nullable=False),
    link("run_id", "tool_runs"),
)
observations = entity(
    "observations",
    sa.Column("run_id", sa.String(36), nullable=False),
    sa.Column("asset_id", sa.String(36), nullable=False),
    sa.Column("evidence_id", sa.String(36), nullable=False),
    sa.Column("source_key", sa.String(500), nullable=False),
    link("run_id", "tool_runs"),
    link("asset_id", "assets"),
    link("evidence_id", "evidence_references"),
    sa.UniqueConstraint("assessment_id", "run_id", "source_key"),
)
vulnerability_concepts = entity("vulnerability_concepts")
occurrences = entity(
    "occurrences",
    sa.Column("concept_id", sa.String(36), nullable=False),
    sa.Column("asset_id", sa.String(36), nullable=False),
    sa.Column("observation_id", sa.String(36), nullable=False),
    sa.Column("location", sa.String(2000), nullable=False),
    link("concept_id", "vulnerability_concepts"),
    link("asset_id", "assets"),
    link("observation_id", "observations"),
    sa.UniqueConstraint("assessment_id", "observation_id", "location"),
)
decisions = entity("decisions")
findings = entity(
    "findings",
    sa.Column("concept_id", sa.String(36), nullable=False),
    sa.Column("decision_id", sa.String(36)),
    link("concept_id", "vulnerability_concepts"),
    link("decision_id", "decisions"),
)
approvals = entity(
    "approvals",
    sa.Column("decision_id", sa.String(36), nullable=False),
    link("decision_id", "decisions"),
)
report_snapshots = entity("report_snapshots")

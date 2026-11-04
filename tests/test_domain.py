"""Handcrafted contract records only; these are not scanner captures or accuracy proof."""

import hashlib
import secrets
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from aegistrace import schema_v1 as db
from aegistrace.db import make_engine
from aegistrace.domain import (
    Assessment,
    Asset,
    EvidenceReference,
    Finding,
    Observation,
    Occurrence,
    ScopeVersion,
    ToolRun,
    VulnerabilityConcept,
)
from aegistrace.repository import get_record, insert_record, require_owner
from aegistrace.settings import Settings
from pydantic import ValidationError
from sqlalchemy import Engine, select
from sqlalchemy.exc import IntegrityError


@pytest.fixture
def domain_engine(tmp_path: Path) -> Engine:
    engine = make_engine(
        Settings(
            _env_file=None,
            app_secret=secrets.token_hex(32),
            database_url=f"sqlite:///{tmp_path / 'domain.db'}",
        )
    )
    db.metadata.create_all(engine)
    yield engine
    engine.dispose()


def seed(connection):
    now = datetime.now(UTC)
    assessment = Assessment(name="Contract test only", owner_id="analyst-a", created_at=now)
    scope = ScopeVersion(assessment_id=assessment.id, revision=1, targets=["asset-a", "asset-b"])
    run = ToolRun(
        assessment_id=assessment.id,
        scope_id=scope.id,
        tool="Nmap",
        tool_version="test-only",
        mode="recorded-import",
        captured_at=now,
        state="recorded",
    )
    evidence = EvidenceReference(
        assessment_id=assessment.id,
        run_id=run.id,
        sha256=hashlib.sha256(b"explicit handcrafted test bytes").hexdigest(),
        pointer="/test-only",
        pointer_type="xml-path",
        captured_at=now,
    )
    concept = VulnerabilityConcept(assessment_id=assessment.id, title="Test concept")
    for collection, record in [
        ("assessments", assessment),
        ("scope_versions", scope),
        ("tool_runs", run),
        ("evidence_references", evidence),
        ("vulnerability_concepts", concept),
    ]:
        insert_record(connection, collection, record)
    return assessment, run, evidence, concept


def test_two_assets_keep_two_occurrences_and_original_provenance(domain_engine: Engine) -> None:
    with domain_engine.begin() as connection:
        assessment, run, evidence, concept = seed(connection)
        for identifier in ["asset-a", "asset-b"]:
            asset = Asset(assessment_id=assessment.id, identifier=identifier, kind="host")
            insert_record(connection, "assets", asset)
            observation = Observation(
                assessment_id=assessment.id,
                asset_id=asset.id,
                run_id=run.id,
                evidence_id=evidence.id,
                source_key=identifier,
                title="Test observation",
                observed_at=datetime.now(UTC),
            )
            insert_record(connection, "observations", observation)
            insert_record(
                connection,
                "occurrences",
                Occurrence(
                    assessment_id=assessment.id,
                    concept_id=concept.id,
                    asset_id=asset.id,
                    observation_id=observation.id,
                    location="tcp/443",
                ),
            )
            restored = get_record(connection, "observations", assessment.id, observation.id)
            assert restored["cve"] is None and restored["cvss_score"] is None
            assert restored["run_id"] == str(run.id) and restored["evidence_id"] == str(evidence.id)
            assert restored["observed_at"] == observation.model_dump(mode="json")["observed_at"]
        assert len(connection.execute(select(db.occurrences)).all()) == 2
        with pytest.raises(LookupError):
            require_owner(connection, assessment.id, "analyst-b")


def test_duplicate_source_and_cross_assessment_links_rejected(domain_engine: Engine) -> None:
    with domain_engine.begin() as connection:
        assessment, run, evidence, _ = seed(connection)
        asset = Asset(assessment_id=assessment.id, identifier="asset-a", kind="host")
        insert_record(connection, "assets", asset)
        observation = Observation(
            assessment_id=assessment.id,
            asset_id=asset.id,
            run_id=run.id,
            evidence_id=evidence.id,
            source_key="source-1",
            title="Test",
            observed_at=datetime.now(UTC),
        )
        insert_record(connection, "observations", observation)
        with pytest.raises(IntegrityError), connection.begin_nested():
            insert_record(
                connection, "observations", observation.model_copy(update={"id": uuid4()})
            )
        other = Assessment(name="Other", owner_id="b", created_at=datetime.now(UTC))
        insert_record(connection, "assessments", other)
        with pytest.raises(IntegrityError), connection.begin_nested():
            insert_record(
                connection,
                "tool_runs",
                run.model_copy(update={"id": uuid4(), "assessment_id": other.id}),
            )


def test_confirmation_and_unknown_fields_are_explicit() -> None:
    common = dict(
        assessment_id=uuid4(),
        asset_id=uuid4(),
        run_id=uuid4(),
        evidence_id=uuid4(),
        source_key="test",
        title="Test",
        observed_at=datetime.now(UTC),
    )
    for values in [
        {"validation_state": "confirmed"},
        {"cvss_score": 11},
        {"confidence": 0.9},
        {"cve": "made-up"},
        {"cvss_score": float("nan")},
    ]:
        with pytest.raises(ValidationError):
            Observation(**(common | values))
    with pytest.raises(ValidationError):
        Finding(
            assessment_id=uuid4(),
            concept_id=uuid4(),
            title="Test",
            information_kind="ai-inference",
            validation_state="confirmed",
            decision_id=uuid4(),
        )


@pytest.mark.services
def test_domain_on_actual_postgresql() -> None:
    import os

    if os.environ.get("RUN_SERVICE_TESTS") != "1":
        pytest.skip("requires migrated PostgreSQL")
    engine = make_engine(Settings())
    with engine.begin() as connection:
        assessment, run, _, _ = seed(connection)
        assert require_owner(connection, assessment.id, "analyst-a").id == assessment.id
        with pytest.raises(IntegrityError), connection.begin_nested():
            insert_record(
                connection, "tool_runs", run.model_copy(update={"id": uuid4(), "scope_id": uuid4()})
            )
    engine.dispose()

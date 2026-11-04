"""Handcrafted lifecycle audit proof; no actual scanner or report lifecycle claim."""

import copy
import hashlib
import os
import secrets
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from aegistrace.audit import (
    AuditEvent,
    append_event,
    checkpoint,
    read_events,
    verify_chain,
    verify_checkpoint,
)
from aegistrace.audit_schema import events, heads, install_guards
from aegistrace.db import make_engine
from aegistrace.domain import Assessment
from aegistrace.repository import insert_record
from aegistrace.schema_v1 import metadata
from aegistrace.settings import Settings
from sqlalchemy import select
from sqlalchemy.exc import DBAPIError


@pytest.fixture
def audit_context(tmp_path):
    engine = make_engine(
        Settings(
            _env_file=None,
            app_secret=secrets.token_hex(32),
            database_url=f"sqlite:///{tmp_path / 'audit.db'}",
        )
    )
    metadata.create_all(engine)
    assessment = Assessment(name="Test only", owner_id="owner", created_at=datetime.now(UTC))
    with engine.begin() as connection:
        install_guards(connection)
        insert_record(connection, "assessments", assessment)
    yield engine, assessment
    engine.dispose()


def event(assessment_id, action="assessment.requested"):
    request = uuid4()
    return AuditEvent(
        assessment_id=assessment_id,
        actor_id="test-reviewer",
        correlation_id=request,
        request_id=request,
        action=action,
        action_digest=hashlib.sha256(action.encode()).hexdigest(),
        outcome="completed",
        scope_revision=1,
        plan_revision=1,
    )


def test_lifecycle_checkpoint_change_omission_and_replay(audit_context):
    engine, assessment = audit_context
    secret = secrets.token_hex(32)
    with engine.begin() as connection:
        for action in [
            "assessment.requested",
            "plan.proposed",
            "approval.requested",
            "approval.approved",
            "execution.recorded",
            "finding.reviewed",
            "report.requested",
        ]:
            append_event(connection, event(assessment.id, action))
        anchor = checkpoint(connection, assessment.id, secret)
        rows = read_events(connection, assessment.id)
        assert verify_checkpoint(rows, anchor["signature"], secret, assessment.id)
        changed = copy.deepcopy(rows)
        changed[1]["payload"]["actor_id"] = "tampered"
        assert not verify_checkpoint(changed, anchor["signature"], secret, assessment.id)
        assert not verify_checkpoint(
            rows[:3] + rows[4:], anchor["signature"], secret, assessment.id
        )
        assert not verify_checkpoint(rows[:-1], anchor["signature"], secret, assessment.id)
        assert not verify_checkpoint(rows + [rows[-1]], anchor["signature"], secret, assessment.id)
        assert not verify_checkpoint(rows, anchor["signature"], secret, uuid4())
        replay = AuditEvent.model_validate(rows[0]["payload"])
        with pytest.raises(ValueError, match="replay"):
            append_event(connection, replay)
        for statement in [events.update().values(digest="f" * 64), events.delete()]:
            with pytest.raises(DBAPIError), connection.begin_nested():
                connection.execute(statement)


def test_concurrent_appends_have_total_order_and_resumable_cursor(audit_context):
    engine, assessment = audit_context

    def append(_):
        with engine.begin() as connection:
            append_event(connection, event(assessment.id))

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(append, range(12)))
    with engine.begin() as connection:
        head = connection.execute(select(heads)).mappings().one()
        rows = read_events(connection, assessment.id)
        assert verify_chain(rows, head["sequence"], head["digest"])
        assert read_events(connection, assessment.id, after=5)[0]["sequence"] == 6


@pytest.mark.services
def test_postgresql_application_role_cannot_rewrite_history():
    if os.environ.get("RUN_SERVICE_TESTS") != "1":
        pytest.skip("requires migrated PostgreSQL")
    engine = make_engine(Settings())
    assessment = Assessment(
        name="Postgres audit test only", owner_id="audit-test", created_at=datetime.now(UTC)
    )
    with engine.begin() as connection:
        insert_record(connection, "assessments", assessment)
        append_event(connection, event(assessment.id))
        for statement in [
            events.update()
            .where(events.c.assessment_id == str(assessment.id))
            .values(digest="f" * 64),
            events.delete().where(events.c.assessment_id == str(assessment.id)),
        ]:
            with pytest.raises(DBAPIError), connection.begin_nested():
                connection.execute(statement)
        with pytest.raises(DBAPIError), connection.begin_nested():
            connection.exec_driver_sql("TRUNCATE audit_events")
    # Use an actual restricted role rather than relying solely on an admin connection.
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE ROLE audit_application_test NOLOGIN")
        connection.exec_driver_sql("GRANT USAGE ON SCHEMA public TO audit_application_test")
        connection.exec_driver_sql(
            "GRANT SELECT, UPDATE, DELETE ON audit_events TO audit_application_test"
        )
        connection.exec_driver_sql("SET LOCAL ROLE audit_application_test")
        for statement in [
            events.update()
            .where(events.c.assessment_id == str(assessment.id))
            .values(digest="f" * 64),
            events.delete().where(events.c.assessment_id == str(assessment.id)),
        ]:
            with pytest.raises(DBAPIError), connection.begin_nested():
                connection.execute(statement)
        connection.exec_driver_sql("RESET ROLE")
        connection.exec_driver_sql("DROP OWNED BY audit_application_test")
        connection.exec_driver_sql("DROP ROLE audit_application_test")
    engine.dispose()

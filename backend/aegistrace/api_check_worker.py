"""Private API-check runner: single claim, fenced dispatch and durable outcomes."""

import multiprocessing
import time
from collections.abc import Mapping
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Engine, select

from aegistrace.api_assessment import (
    Credential,
    Operation,
    Transport,
    assess_operations,
    pinned_https,
)
from aegistrace.api_check_schema import api_checks
from aegistrace.api_check_service import check_authority, check_row, lock_assessment, read_secret
from aegistrace.approvals import action_digest
from aegistrace.auth import Identity
from aegistrace.platform_api import record_request
from aegistrace.policy import (
    Destination,
    ExecutionPolicy,
    PolicyError,
    Resolver,
    authorize,
    dns_addresses,
    release_policy,
    reserve_policy,
)
from aegistrace.settings import Settings


def _request_child(pipe: Any, target: Destination, method: str, headers: dict[str, str]) -> None:
    try:
        pipe.send(pinned_https(target, method, headers))
    except BaseException:
        pipe.send(None)
    finally:
        pipe.close()


def supervised_request(
    target: Destination, method: str, headers: Mapping[str, str], deadline: float, cancelled: Any
) -> int:
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(
        target=_request_child, args=(sender, target, method, dict(headers)), daemon=True
    )
    process.start()
    sender.close()
    try:
        while time.time() < deadline and not cancelled():
            if receiver.poll(0.1):
                status = receiver.recv()
                if type(status) is not int:
                    raise PolicyError("transport failed")
                return status
            if not process.is_alive():
                break
        raise PolicyError("request cancelled or timed out")
    finally:
        if process.is_alive():
            process.terminate()
        process.join(timeout=2)
        if process.is_alive():
            process.kill()
            process.join(timeout=2)
        receiver.close()


def execute_check(
    engine: Engine,
    config: Settings,
    assessment_id: UUID,
    check_id: UUID,
    *,
    transport: Transport | None = None,
    resolver: Resolver = dns_addresses,
) -> dict[str, Any]:
    """Run once from a trusted isolated worker, never from an HTTP request handler.

    A nondefault transport is for the disposable in-process acceptance harness.
    Production callers must use the default supervised pinned-HTTPS transport.
    """
    worker_id = str(uuid4())
    with engine.begin() as connection:
        lock_assessment(connection, assessment_id)
        row = check_row(connection, assessment_id, check_id)
        if row["state"] != "queued":
            raise PolicyError("job already claimed or not approved")
        check_authority(connection, config, assessment_id, row)
        plan = dict(row["payload"])
        plan.update(
            started_at=time.time(),
            deadline=min(time.time() + plan["max_runtime_seconds"], plan["valid_until"]),
            worker_id=worker_id,
        )
        connection.execute(
            api_checks.update()
            .where(api_checks.c.id == str(check_id))
            .values(state="running", payload=plan)
        )
    deadline = plan["deadline"]

    def current_policy() -> ExecutionPolicy:
        with engine.begin() as connection:
            current = check_row(connection, assessment_id, check_id)
            if current["payload"].get("worker_id") != worker_id or time.time() >= deadline:
                raise PolicyError("worker expired or replaced")
            return check_authority(connection, config, assessment_id, current)  # type: ignore[no-any-return]

    def cancelled() -> bool:
        try:
            current_policy()
            return False
        except (PolicyError, LookupError):
            return True

    def credentials() -> dict[str, Credential]:
        values = {}
        with engine.connect() as connection:
            for name, secret_id in plan["credential_ids"].items():
                try:
                    values[name] = read_secret(connection, config, assessment_id, UUID(secret_id))
                except PolicyError:
                    continue
        return values

    def dispatch(target: Destination, method: str, headers: Mapping[str, str]) -> int:
        policy = current_policy()
        # Reserve globally, including parallel worker processes, immediately
        # before any request. Never retry a failed external request automatically.
        with engine.begin() as connection:
            lock_assessment(connection, assessment_id)
            current = check_row(connection, assessment_id, check_id)
            check_authority(connection, config, assessment_id, current)
            reserve_policy(connection, policy)
            payload = dict(current["payload"]) | {"reservation": True}
            connection.execute(
                api_checks.update().where(api_checks.c.id == str(check_id)).values(payload=payload)
            )
        try:
            if cancelled():
                raise PolicyError("cancelled before dispatch")
            approved = authorize(
                current_policy(),
                target_url(target),
                "active-web",
                resolver,
                config.control_plane_networks,
            )
            if approved != target:
                raise PolicyError("destination changed")
            if transport is not None:
                return transport(target, method, headers)
            return supervised_request(target, method, headers, deadline, cancelled)
        finally:
            with engine.begin() as connection:
                lock_assessment(connection, assessment_id)
                current = check_row(connection, assessment_id, check_id)
                if current["payload"].get("reservation"):
                    release_policy(connection, UUID(plan["policy_id"]))
                    payload = dict(current["payload"]) | {"reservation": False}
                    connection.execute(
                        api_checks.update()
                        .where(api_checks.c.id == str(check_id))
                        .values(payload=payload)
                    )

    operations = tuple(Operation.model_validate(value) for value in plan["operations"])
    allowed = frozenset((operations[i].method, operations[i].url) for i in plan["selected_indices"])
    result: dict[str, Any]
    try:
        result = assess_operations(
            operations,
            plan["operation_digest"],
            current_policy,
            credentials,
            explicitly_allowed_operations=allowed,
            transport=dispatch,
            resolver=resolver,
            protected_networks=config.control_plane_networks,
            cancelled=cancelled,
        )
        result.update(
            source_normalization_id=plan["source_normalization_id"],
            source_evidence_id=plan["source_evidence_id"],
            check_id=str(check_id),
            worker_id=worker_id,
            completed_at=time.time(),
            execution_mode="disposable-test" if transport is not None else "live-request",
        )
        operation_results = result["operations"]
        if isinstance(operation_results, list):
            for index, outcome in enumerate(operation_results):
                outcome["endpoint_id"] = plan["endpoint_ids"][index]
        result["sha256"] = action_digest(result)
    except Exception:
        result = {
            "check_id": str(check_id),
            "reason": "worker-failed-no-automatic-retry",
            "operation_results_unknown": True,
        }
    was_cancelled = cancelled()
    with engine.begin() as connection:
        lock_assessment(connection, assessment_id)
        current = check_row(connection, assessment_id, check_id)
        if (
            current["state"] not in {"running", "cancel-requested"}
            or current["payload"].get("worker_id") != worker_id
        ):
            raise PolicyError("late output after terminal reconciliation")
        state = (
            "cancelled" if was_cancelled or current["state"] == "cancel-requested" else "completed"
        )
        outcomes = result.get("operations")
        ambiguous = isinstance(outcomes, list) and any(
            op.get("attempted") and op.get("status_code") is None for op in outcomes
        )
        if result.get("operation_results_unknown") or ambiguous:
            state = "unknown"
        connection.execute(
            api_checks.update()
            .where(api_checks.c.id == str(check_id))
            .values(state=state, result=result)
        )
        actor = Identity(
            subject="api-check-worker",
            role="scanner",
            principal_kind="service",
            expires=int(time.time()) + 30,
        )
        record_request(
            connection,
            assessment_id,
            actor,
            "api-check." + state,
            check_id,
            {
                "result_sha256": result.get("sha256"),
                "attempted_count": result.get("attempted_count"),
            },
        )
    return result


def target_url(target: Destination) -> str:
    host = f"[{target.host}]" if ":" in target.host else target.host
    return f"{target.protocol}://{host}:{target.port}{target.path}"


def reconcile_expired(engine: Engine) -> int:
    """A crashed worker's ambiguous job is terminal unknown, never auto-replayed."""
    count = 0
    with engine.begin() as connection:
        rows = (
            connection.execute(
                select(api_checks).where(api_checks.c.state.in_(["running", "cancel-requested"]))
            )
            .mappings()
            .all()
        )
        for row in rows:
            if row["payload"].get("deadline", 0) > time.time():
                continue
            assessment_id = UUID(row["assessment_id"])
            lock_assessment(connection, assessment_id)
            current = check_row(connection, assessment_id, UUID(row["id"]))
            if current["state"] not in {"running", "cancel-requested"}:
                continue
            if current["payload"].get("reservation"):
                release_policy(connection, UUID(current["payload"]["policy_id"]))
            connection.execute(
                api_checks.update()
                .where(api_checks.c.id == row["id"])
                .values(
                    state="unknown",
                    payload=dict(current["payload"]) | {"reservation": False},
                    result={"reason": "worker-deadline-expired", "operation_results_unknown": True},
                )
            )
            count += 1
    return count

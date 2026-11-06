"""Evidence -> bounded candidates -> model proposal -> deterministic filter -> human review."""

import hashlib
import html
import json
import re
from typing import Any, Literal
from uuid import UUID, uuid4

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import Connection, select

from aegistrace.api_contracts import WorkflowResource
from aegistrace.api_schema import resources
from aegistrace.auth import Identity
from aegistrace.capabilities import capability_snapshot
from aegistrace.evidence import EvidenceError
from aegistrace.grounding import SourceClaim
from aegistrace.inference_guards import ReasoningProposal, model_context, store_proposal
from aegistrace.log_safety import safe_log_text
from aegistrace.model_provider import ProviderFailure, build_provider
from aegistrace.platform_api import current_scope, plan_digest, record_request
from aegistrace.repository import get_record, require_access
from aegistrace.result_schema import revisions
from aegistrace.schema_v1 import assessments, observations, services, tool_runs
from aegistrace.settings import Settings


class ReplanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    scope_id: UUID
    scope_revision: int = Field(ge=1)
    conversation_id: UUID
    request_text: str = Field(min_length=1, max_length=1000)
    result_revision_ids: tuple[UUID, ...] = Field(max_length=25)
    allow_external_processing: bool = False
    data_policy_reference: str | None = Field(default=None, max_length=300)


class RejectedAlternative(BaseModel):
    model_config = ConfigDict(extra="forbid")
    candidate_id: str = Field(min_length=1, max_length=100)
    reason: str = Field(min_length=1, max_length=500)
    observation_ids: list[UUID] = Field(max_length=50)


class ModelDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    decision: Literal["select", "request-review", "stop"]
    selected_candidate_id: str | None
    rationale: str = Field(min_length=1, max_length=1500)
    observation_ids: list[UUID] = Field(max_length=50)
    expected_information_gain: str = Field(min_length=1, max_length=500)
    assumptions: list[str] = Field(max_length=10)
    stop_conditions: list[str] = Field(min_length=1, max_length=10)
    rejected_alternatives: list[RejectedAlternative] = Field(max_length=30)


def candidate_steps(
    facts: list[dict[str, Any]],
    completed: dict[str, set[str]],
    failed_tools: list[str],
    registry: list[dict[str, object]],
) -> list[dict[str, Any]]:
    """Only fixed, offline actions are offered; the model cannot add a tool or target."""
    candidates: list[dict[str, Any]] = []
    if facts:
        candidates.append(
            {
                "id": "review-sources",
                "action": "request-review",
                "tool": None,
                "observation_ids": [row["id"] for row in facts],
                "reason": "Review source evidence and uncertainty before making any validation claim.",
            }
        )
    if failed_tools:
        return candidates
    available = {
        str(row["name"])
        for row in registry
        if row.get("mode") != "unsupported" and row.get("guarded_containers")
    }
    for asset_id in sorted({row["asset_id"] for row in facts}):
        related = [row for row in facts if row["asset_id"] == asset_id]
        web = [
            row
            for row in related
            if row.get("service", {}).get("observed_name", "").casefold()
            in {"http", "https", "http-alt", "ssl/http"}
        ]
        if not web:
            continue
        for tool in ("OWASP ZAP", "Nikto"):
            if tool not in available or tool in completed.get(asset_id, set()):
                continue
            candidates.append(
                {
                    "id": f"import-{tool}-{asset_id}",
                    "action": "request-import",
                    "tool": tool,
                    "asset_id": asset_id,
                    "observation_ids": [row["id"] for row in web],
                    "reason": "Observed web service warrants missing recorded web evidence; no live scan is enabled.",
                }
            )
    return candidates


def validate_decision(
    decision: ModelDecision, candidates: list[dict[str, Any]], facts: list[dict[str, Any]]
) -> None:
    by_id = {row["id"]: row for row in candidates}
    known = {row["id"] for row in facts}
    if not set(str(v) for v in decision.observation_ids).issubset(known):
        raise ProviderFailure("model-citation-not-in-context")
    if facts and not decision.observation_ids:
        raise ProviderFailure("model-rationale-needs-citations")
    if any(len(text) > 500 for text in decision.assumptions + decision.stop_conditions):
        raise ProviderFailure("model-text-limit")
    for alternative in decision.rejected_alternatives:
        if alternative.candidate_id not in by_id or not set(
            str(v) for v in alternative.observation_ids
        ).issubset(known):
            raise ProviderFailure("model-alternative-not-in-context")
        if not alternative.observation_ids or not set(
            str(v) for v in alternative.observation_ids
        ).issubset(set(by_id[alternative.candidate_id]["observation_ids"])):
            raise ProviderFailure("model-alternative-citations-mismatch")
    rejected_ids = [v.candidate_id for v in decision.rejected_alternatives]
    if len(rejected_ids) != len(set(rejected_ids)) or set(rejected_ids) != set(by_id) - {
        decision.selected_candidate_id
    }:
        raise ProviderFailure("model-alternatives-incomplete-or-duplicated")
    if decision.decision == "stop":
        if decision.selected_candidate_id is not None:
            raise ProviderFailure("model-stop-has-action")
        return
    selected = by_id.get(decision.selected_candidate_id or "")
    if selected is None:
        raise ProviderFailure("model-action-not-in-candidates")
    cited = {str(v) for v in decision.observation_ids}
    if not cited or not cited.issubset(set(selected["observation_ids"])):
        raise ProviderFailure("model-action-citations-mismatch")
    expected = "request-review" if selected["action"] == "request-review" else "select"
    if decision.decision != expected:
        raise ProviderFailure("model-decision-action-mismatch")


def replan(
    connection: Connection,
    config: Settings,
    assessment_id: UUID,
    body: ReplanRequest,
    actor: Identity,
) -> dict[str, Any]:
    require_access(connection, assessment_id, actor.subject)
    if actor.principal_kind != "human" or actor.role not in {"reviewer", "admin"}:
        raise HTTPException(403, "Human reviewer required for external reasoning")
    connection.execute(
        select(assessments.c.id).where(assessments.c.id == str(assessment_id)).with_for_update()
    ).one()
    current_scope(connection, assessment_id, body.scope_id, body.scope_revision)
    all_plans = [
        dict(row)
        for row in connection.execute(
            select(resources.c.payload).where(
                resources.c.assessment_id == str(assessment_id), resources.c.kind == "plans"
            )
        ).scalars()
    ]
    previous = [
        row
        for row in all_plans
        if row.get("request", {}).get("conversation_id") == str(body.conversation_id)
    ]
    used_calls = sum(
        bool(row.get("request", {}).get("proposal", {}).get("provider", {}).get("provider_invoked"))
        for row in all_plans
    )
    if used_calls >= config.model_max_assessment_calls:
        raise HTTPException(409, "Assessment model call budget exhausted")
    used_steps = sum(bool(row["request"].get("adaptive")) for row in previous)
    if used_steps >= config.model_max_plan_revisions:
        raise HTTPException(
            409, "Adaptive plan budget exhausted; review before starting a new conversation"
        )
    version = max((row["revision"] for row in previous), default=0) + 1
    selected_revisions = []
    for revision_id in body.result_revision_ids:
        source = connection.execute(
            select(revisions.c.payload).where(
                revisions.c.id == str(revision_id), revisions.c.assessment_id == str(assessment_id)
            )
        ).scalar_one_or_none()
        if source is None:
            raise HTTPException(422, "Result revision does not belong to assessment")
        run = get_record(connection, "tool_runs", assessment_id, UUID(source["run_id"]))
        if run["scope_id"] != str(body.scope_id):
            raise HTTPException(409, "Prior evidence belongs to a different scope")
        selected_revisions.append(dict(source))
    observation_ids = list(
        dict.fromkeys(v for row in selected_revisions for v in row["observation_ids"])
    )
    source_rows = (
        [
            dict(row)
            for row in connection.execute(
                select(observations.c.payload)
                .where(
                    observations.c.assessment_id == str(assessment_id),
                    observations.c.id.in_(observation_ids[:201]),
                )
                .order_by(observations.c.id)
            ).scalars()
        ]
        if observation_ids
        else []
    )
    service_ids = [row["service_id"] for row in source_rows if row.get("service_id")]
    service_rows = (
        {
            str(row["id"]): dict(row)
            for row in connection.execute(
                select(services.c.payload).where(
                    services.c.assessment_id == str(assessment_id), services.c.id.in_(service_ids)
                )
            ).scalars()
        }
        if service_ids
        else {}
    )
    secrets = (
        config.app_secret.get_secret_value(),
        config.evidence_key.get_secret_value() if config.evidence_key else "",
        config.groq_api_key.get_secret_value() if config.groq_api_key else "",
    )

    def clean(value: str) -> str:
        return safe_log_text(value, secrets)

    facts = []
    for row in source_rows:
        service = service_rows.get(str(row.get("service_id")), {})
        facts.append(
            {
                "id": row["id"],
                "asset_id": row["asset_id"],
                "evidence_id": row["evidence_id"],
                "title": clean(row["title"]),
                "validation_state": row.get("validation_state", "unknown"),
                "observed_at": row.get("observed_at"),
                "source_cve": row.get("cve"),
                "source_cvss_score": row.get("cvss_score"),
                "source_severity": clean(row.get("source_severity") or "unknown"),
                "service": {
                    "port": service.get("port"),
                    "protocol": service.get("protocol"),
                    "observed_name": clean(service.get("observed_name") or ""),
                },
            }
        )
    completed: dict[str, set[str]] = {}
    prior_scope_results = [
        dict(row)
        for row in connection.execute(
            select(revisions.c.payload)
            .join(tool_runs, revisions.c.run_id == tool_runs.c.id)
            .where(
                revisions.c.assessment_id == str(assessment_id),
                tool_runs.c.scope_id == str(body.scope_id),
            )
            .order_by(revisions.c.id)
            .limit(1001)
        ).scalars()
    ]
    for row in prior_scope_results:
        if row["state"] == "normalized":
            for asset_id in row["asset_ids"]:
                completed.setdefault(asset_id, set()).add(row["tool"])
    failed = sorted({row["tool"] for row in selected_revisions if row["state"] != "normalized"})
    conflicts = []
    for row in facts:
        for other in facts:
            if row["id"] >= other["id"] or row["asset_id"] != other["asset_id"]:
                continue
            same_cve = row["source_cve"] and row["source_cve"] == other["source_cve"]
            if same_cve and any(
                row[field] != other[field] for field in ("source_cvss_score", "source_severity")
            ):
                conflicts.append([row["id"], other["id"]])
            port = re.fullmatch(r"Nmap (tcp|udp)/(\d+): (\w+)", row["title"])
            other_port = re.fullmatch(r"Nmap (tcp|udp)/(\d+): (\w+)", other["title"])
            if (
                port
                and other_port
                and port.group(1, 2) == other_port.group(1, 2)
                and port.group(3) != other_port.group(3)
            ):
                conflicts.append([row["id"], other["id"]])
    registry = capability_snapshot()
    candidates = candidate_steps(
        facts, completed, failed + (["conflicting-observations"] if conflicts else []), registry
    )
    evidence_ids = tuple(UUID(row["evidence_id"]) for row in selected_revisions)
    context = {
        "schema_version": "1.0",
        "request": clean(body.request_text),
        "scope_id": str(body.scope_id),
        "scope_revision": body.scope_revision,
        "observations": facts,
        "candidates": candidates,
        "failed_tools": failed,
        "conflicts": conflicts,
        "capabilities": [
            {
                "name": row["name"],
                "mode": row["mode"],
                "recorded_import_parser_configured": bool(row.get("guarded_containers")),
            }
            for row in registry
        ],
        "existing_same_scope_tools": {key: sorted(value) for key, value in completed.items()},
        "source_authenticity": "Not independently verified by model context",
        "constraints": ["recorded imports only", "human review required", "no scanner invocation"],
    }
    context_digest = hashlib.sha256(json.dumps(context, sort_keys=True).encode()).hexdigest()
    blockers: list[str] = []
    trace: dict[str, Any] = {
        "provider": "groq",
        "model": config.groq_model,
        "model_called": False,
        "provider_invoked": False,
        "prompt_version": "adaptive-v2",
        "schema_version": "1.0",
    }
    proposal: dict[str, Any] | None = None
    decision: ModelDecision | None = None
    if not facts:
        blockers.append("no-observed-evidence; stop-and-request-input")
    elif len(observation_ids) > 200:
        blockers.append("context-limit; select-fewer-result-revisions")
    elif len(prior_scope_results) > 1000:
        blockers.append("scope-history-limit; review-existing-results")
    elif any(
        row["request"].get("context_sha256") == context_digest
        and row["request"].get("proposal", {}).get("decision")
        for row in all_plans
    ):
        blockers.append("unchanged-evidence; reuse-prior-plan-instead-of-repeating-model-call")
    elif (
        not body.allow_external_processing
        or not config.model_data_policy_reference
        or body.data_policy_reference != config.model_data_policy_reference
    ):
        blockers.append("external-data-policy-approval-required")
    else:
        try:
            provider = build_provider(config)
            # Access and reviewed/unexpired redaction are checked; raw derivative text is never sent.
            model_context(connection, config, assessment_id, evidence_ids, actor)
            trace["provider_invoked"] = True
            reply = provider.generate(context, ModelDecision.model_json_schema())
            trace.update(
                model_called=reply.source == "live-provider",
                provider_source=reply.source,
                model=reply.model,
                response_id_sha256=reply.response_id,
                usage=reply.usage,
            )
            decision = ModelDecision.model_validate_json(reply.content)
            validate_decision(decision, candidates, facts)
            if capability_snapshot() != registry:
                raise ProviderFailure("capabilities-changed-during-reasoning")
            # Revalidate the same scope after the external call, before saving a reviewable draft.
            current_scope(connection, assessment_id, body.scope_id, body.scope_revision)
            cited_rows = [
                row
                for row in source_rows
                if row["id"] in {str(v) for v in decision.observation_ids}
            ]
            proposal = store_proposal(
                connection,
                config,
                assessment_id,
                ReasoningProposal(
                    purpose="next-step",
                    narrative=clean(decision.rationale),
                    source_evidence_ids=evidence_ids,
                    claims=tuple(
                        SourceClaim(
                            type="title",
                            value=row["title"],
                            observation_id=row["id"],
                            evidence_id=row["evidence_id"],
                            asset_id=row["asset_id"],
                        )
                        for row in cited_rows
                        if clean(row["title"]) == row["title"]
                    ),
                ),
                actor,
            )
        except ProviderFailure as error:
            blockers.append(str(error))
            decision = None
        except HTTPException:
            blockers.append("scope-changed-during-reasoning")
            decision = None
        except EvidenceError:
            blockers.append("reviewed-unexpired-evidence-required")
            decision = None
        except (ValueError, LookupError):
            blockers.append("model-output-or-evidence-not-valid")
            decision = None
    decision_value = decision.model_dump(mode="json") if decision else None
    steps: list[dict[str, Any]] = []
    if decision_value and decision is not None:
        # All free prose remains untrusted inference, escaped and secret-filtered in persisted plans.
        def sanitize(value: Any) -> Any:
            if isinstance(value, str):
                return html.escape(clean(value))
            if isinstance(value, list):
                return [sanitize(v) for v in value]
            if isinstance(value, dict):
                return {k: sanitize(v) for k, v in value.items()}
            return value

        decision_value = sanitize(decision_value)
        if decision.decision != "select":
            blockers.append("model-requested-review-or-stop")
        else:
            chosen = next(row for row in candidates if row["id"] == decision.selected_candidate_id)
            steps.append(
                chosen
                | {
                    "mode": "recorded-import",
                    "profile": "recorded-import-only",
                    "scope_id": str(body.scope_id),
                    "scope_revision": body.scope_revision,
                    "requires": ["human plan review", "permitted source artifact with provenance"],
                    "rationale": decision_value["rationale"],
                    "expected_information_gain": decision_value["expected_information_gain"],
                }
            )
    request_data = {
        "adaptive": True,
        "conversation_id": str(body.conversation_id),
        "scope_id": str(body.scope_id),
        "scope_revision": body.scope_revision,
        "supersedes_plan_id": max(previous, key=lambda row: row["revision"])["id"]
        if previous
        else None,
        "request_text": clean(body.request_text),
        "data_policy_reference": clean(body.data_policy_reference)
        if body.data_policy_reference
        else None,
        "result_revision_ids": [str(v) for v in body.result_revision_ids],
        "context_sha256": context_digest,
        "context": context,
        "proposal": {
            "information_kind": "ai-inference" if decision else "unknown",
            "decision": decision_value,
            "candidates": candidates,
            "reasoning_proposal_id": proposal["id"] if proposal else None,
            "blockers": blockers,
            "steps": steps,
            "execution_enabled": False,
            "capability_snapshot": registry,
            "provider": trace,
            "assumptions": ["Imported sources and service names are unverified observations."],
        },
    }
    value = WorkflowResource.model_validate(
        dict(
            id=uuid4(),
            assessment_id=assessment_id,
            kind="plans",
            revision=version,
            state="blocked" if blockers else "draft",
            mode="request-only",
            reason=",".join(blockers) or None,
            request=request_data,
        )
    ).model_dump(mode="json")
    value["request"]["review_digest"] = plan_digest(value)
    connection.execute(
        resources.insert().values(
            id=value["id"], assessment_id=str(assessment_id), kind="plans", payload=value
        )
    )
    record_request(
        connection, assessment_id, actor, "plan.adaptive-proposed", UUID(value["id"]), value
    )
    return value

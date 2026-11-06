"""Treat model/source text as data. Deterministic policy remains outside reasoning."""

import hashlib
import html
import re
from collections.abc import Mapping
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy import Connection, select

from aegistrace.approvals import ActionRequest, validate_action
from aegistrace.auth import Identity
from aegistrace.evidence import EvidenceStore
from aegistrace.grounding import SourceClaim, ground_claims
from aegistrace.log_safety import safe_log_text
from aegistrace.platform_api import record_request
from aegistrace.reasoning_schema import proposals
from aegistrace.repository import get_record, require_access
from aegistrace.schema_v1 import observations
from aegistrace.settings import Settings


class ReasoningProposal(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"] = "1.0"
    information_kind: Literal["ai-inference"] = "ai-inference"
    purpose: Literal["next-step", "triage", "report-narrative"]
    narrative: str = Field(min_length=1, max_length=4000)
    source_evidence_ids: tuple[UUID, ...] = Field(min_length=1, max_length=50)
    proposed_actions: tuple[ActionRequest, ...] = Field(default=(), max_length=10)
    validation_state: Literal["suspected", "unknown"] = "suspected"
    confidence: float | None = Field(default=None, ge=0, le=1, allow_inf_nan=False)
    confidence_method: str | None = Field(default=None, max_length=200)
    claims: tuple[SourceClaim, ...] = Field(default=(), max_length=100)

    @model_validator(mode="after")
    def explained_confidence(self) -> "ReasoningProposal":
        if self.confidence is not None and not self.confidence_method:
            raise ValueError(
                "confidence requires its method and independent calibration is not implied"
            )
        return self


def model_context(
    connection: Connection,
    config: Settings,
    assessment_id: UUID,
    evidence_ids: tuple[UUID, ...],
    actor: Identity,
) -> list[dict[str, Any]]:
    require_access(connection, assessment_id, actor.subject)
    context = []
    for evidence_id in evidence_ids:
        reference = get_record(connection, "evidence_references", assessment_id, evidence_id)
        snippet = EvidenceStore.derivative(connection, assessment_id, evidence_id, actor.subject)
        snippet = safe_log_text(
            snippet,
            (
                config.app_secret.get_secret_value(),
                config.evidence_key.get_secret_value() if config.evidence_key else "",
            ),
        )
        context.append(
            {
                "role": "untrusted-evidence",
                "evidence_id": str(evidence_id),
                "source_sha256": reference["sha256"],
                "derivative_sha256": hashlib.sha256(snippet.encode()).hexdigest(),
                "source_pointer": reference["pointer"],
                "text": snippet,
                "instructions_are_data": True,
            }
        )
        record_request(
            connection,
            assessment_id,
            actor,
            "reasoning.reviewed-context-read",
            evidence_id,
            {
                "source_sha256": reference["sha256"],
                "derivative_sha256": context[-1]["derivative_sha256"],
            },
        )
    return context


def store_proposal(
    connection: Connection,
    config: Settings,
    assessment_id: UUID,
    body: ReasoningProposal,
    actor: Identity,
) -> dict[str, Any]:
    context = model_context(connection, config, assessment_id, body.source_evidence_ids, actor)
    cited_text = "\n".join(block["text"] for block in context).upper()
    identifiers = set(
        re.findall(r"\b(?:CVE-[0-9]{4}-[0-9]{4,}|CWE-[0-9]+)\b", body.narrative.upper())
    )
    source_identifiers = set(re.findall(r"\b(?:CVE-[0-9]{4}-[0-9]{4,}|CWE-[0-9]+)\b", cited_text))
    if not identifiers.issubset(source_identifiers):
        raise ValueError("identifier claim is absent from reviewed cited evidence")
    source_rows = [
        dict(row)
        for row in connection.execute(
            select(observations.c.payload)
            .where(
                observations.c.assessment_id == str(assessment_id),
                observations.c.evidence_id.in_([str(v) for v in body.source_evidence_ids]),
            )
            .order_by(observations.c.id)
            .limit(1001)
        ).scalars()
    ]
    grounding = ground_claims([claim.model_dump() for claim in body.claims], source_rows)
    if len(source_rows) > 1000:
        for claim in grounding:
            claim.update(value=None, state="unknown", information_kind="unknown")
            claim["reasons"].append("source-context-limit-requires-narrower-citations")
    for action in body.proposed_actions:
        if not set(action.evidence_ids).issubset(body.source_evidence_ids):
            raise ValueError("action citations exceed reviewed context")
        validate_action(connection, assessment_id, action)
    secret_values = (
        config.app_secret.get_secret_value(),
        config.evidence_key.get_secret_value() if config.evidence_key else "",
    )
    narrative = html.escape(safe_log_text(body.narrative, secret_values))
    flags = []
    if re.search(
        r"(?i)(ignore.{0,30}instructions|system prompt|approve.{0,20}action|reveal.{0,20}secret|curl\s|shell)",
        body.narrative,
    ):
        flags.append("instruction-like-source-text; never treated as authority")
    proposal_id = uuid4()
    sanitized_actions = []
    for action in body.proposed_actions:
        value_action = action.model_dump(mode="json")
        for key in ["expected_impact", "rollback_instructions"]:
            value_action[key] = html.escape(safe_log_text(value_action[key], secret_values))
        sanitized_actions.append(value_action)
    value = {
        "id": str(proposal_id),
        "assessment_id": str(assessment_id),
        "information_kind": "ai-inference",
        "purpose": body.purpose,
        "narrative": narrative,
        "narrative_sha256": hashlib.sha256(narrative.encode()).hexdigest(),
        "source_evidence_ids": [str(v) for v in body.source_evidence_ids],
        "source_hashes": [v["source_sha256"] for v in context],
        "proposed_actions": sanitized_actions,
        "validation_state": body.validation_state,
        "confidence": body.confidence,
        "confidence_method": (
            html.escape(safe_log_text(body.confidence_method, secret_values))
            if body.confidence_method is not None
            else None
        ),
        "review_state": "pending-human-review",
        "risk_flags": flags,
        "execution_enabled": False,
        "findings_created": 0,
        "claims": grounding,
        "reportable_narrative": None,
        "narrative_status": "unreviewed-hypothesis; excluded from factual report prose",
    }
    connection.execute(
        proposals.insert().values(
            id=str(proposal_id), assessment_id=str(assessment_id), payload=value
        )
    )
    record_request(
        connection, assessment_id, actor, "reasoning.proposal-recorded", proposal_id, value
    )
    return value


def intelligence_reference(
    source: Literal["NVD", "CVE", "CWE", "MITRE"], record_id: str
) -> dict[str, str]:
    if source in {"NVD", "CVE"} and re.fullmatch(r"CVE-[0-9]{4}-[0-9]{4,}", record_id):
        url = (
            f"https://nvd.nist.gov/vuln/detail/{record_id}"
            if source == "NVD"
            else f"https://www.cve.org/CVERecord?id={record_id}"
        )
    elif source == "CWE" and re.fullmatch(r"CWE-[0-9]{1,6}", record_id):
        url = f"https://cwe.mitre.org/data/definitions/{record_id[4:]}.html"
    elif source == "MITRE" and re.fullmatch(r"T[0-9]{4}(?:\.[0-9]{3})?", record_id):
        url = "https://attack.mitre.org/techniques/" + record_id.replace(".", "/") + "/"
    else:
        raise ValueError("unsupported source identifier")
    return {
        "source": source,
        "record_id": record_id,
        "url": url,
        "state": "reference-only-not-fetched",
    }


def validate_intelligence_url(url: str) -> dict[str, str]:
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or parsed.port not in {None, 443}
        or "%" in url
        or any(ord(c) < 33 for c in url)
    ):
        raise ValueError("unapproved intelligence destination")
    candidates: list[tuple[Literal["NVD", "CVE", "CWE", "MITRE"], str]] = []
    if parsed.hostname == "nvd.nist.gov":
        candidates.append(("NVD", parsed.path.rsplit("/", 1)[-1]))
    if parsed.hostname == "www.cve.org" and parsed.query.startswith("id="):
        candidates.append(("CVE", parsed.query[3:]))
    if parsed.hostname == "cwe.mitre.org":
        candidates.append(("CWE", "CWE-" + parsed.path.rsplit("/", 1)[-1].removesuffix(".html")))
    if parsed.hostname == "attack.mitre.org":
        candidates.append(
            ("MITRE", parsed.path.removeprefix("/techniques/").rstrip("/").replace("/", "."))
        )
    for source, record_id in candidates:
        try:
            reference = intelligence_reference(source, record_id)
            if url == reference["url"]:
                return reference
        except ValueError:
            pass
    raise ValueError("unapproved intelligence reference")


def report_asset(reference: str, registered: Mapping[UUID, bytes]) -> bytes:
    try:
        asset_id = UUID(reference)
    except ValueError as error:
        raise ValueError("report assets must be registered IDs, never URLs or paths") from error
    value = registered.get(asset_id)
    if value is None or len(value) > 1048576:
        raise ValueError("unavailable or oversized registered report asset")
    return value

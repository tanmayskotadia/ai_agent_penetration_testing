"""Versioned, bounded report-reference catalogue and provenance rules."""

import re
from decimal import Decimal, InvalidOperation
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

CATALOG_REVISION = "aegistrace-standards-2026-11-08.1"

FRAMEWORKS: list[dict[str, Any]] = [
    {
        "key": "nist-sp-800-115",
        "name": "NIST SP 800-115",
        "version": "2008",
        "role": "methodology",
        "source_url": "https://doi.org/10.6028/NIST.SP.800-115",
        "description": "Technical guide for information security testing and assessment. A citation does not mean every procedure was performed.",
        "entries": [],
    },
    {
        "key": "owasp-top-10-2025",
        "name": "OWASP Top 10",
        "version": "2025",
        "role": "risk-category",
        "source_url": "https://top10.owasp.org/2025/",
        "description": "Web application risk-awareness categories; a reviewer mapping is not proof that a vulnerability exists.",
        "entries": [
            {"id": "A01:2025", "title": "Broken Access Control"},
            {"id": "A02:2025", "title": "Security Misconfiguration"},
            {"id": "A03:2025", "title": "Software Supply Chain Failures"},
            {"id": "A04:2025", "title": "Cryptographic Failures"},
            {"id": "A05:2025", "title": "Injection"},
            {"id": "A06:2025", "title": "Insecure Design"},
            {"id": "A07:2025", "title": "Authentication Failures"},
            {"id": "A08:2025", "title": "Software or Data Integrity Failures"},
            {"id": "A09:2025", "title": "Security Logging and Alerting Failures"},
            {"id": "A10:2025", "title": "Mishandling of Exceptional Conditions"},
        ],
    },
    {
        "key": "cve",
        "name": "CVE",
        "version": "CVE Program; record version not pinned",
        "role": "source-identifier",
        "source_url": "https://www.cve.org/",
        "description": "Only identifiers present in the exact selected source observation are included; record validity and freshness are not independently checked.",
        "entries": [],
    },
    {
        "key": "cvss",
        "name": "CVSS",
        "version": "source-reported version; current reference CVSS 4.0",
        "role": "source-score",
        "source_url": "https://www.first.org/cvss/v4-0/specification-document",
        "description": "Scores, version, and vector are reproduced only when all are present in selected source evidence; AegisTrace does not calculate or recalibrate them.",
        "entries": [],
    },
    {
        "key": "cwe",
        "name": "CWE",
        "version": "CWE List 5.0",
        "role": "source-identifier",
        "source_url": "https://cwe.mitre.org/data/",
        "description": "Only identifiers present in selected source observations are included; they remain source-reported and may not be a validated mapping.",
        "entries": [],
    },
    {
        "key": "mitre-attack-enterprise",
        "name": "MITRE ATT&CK Enterprise",
        "version": "20.1 (2026-11-05)",
        "role": "reviewer-mapped-hypothesis",
        "source_url": "https://attack.mitre.org/resources/updates/",
        "description": "A reviewer mapping is a taxonomy hypothesis. A vulnerability category or exposed port is not evidence that an adversary action occurred.",
        "entries": [
            {
                "id": "T1190",
                "title": "Exploit Public-Facing Application",
                "source_url": "https://attack.mitre.org/techniques/T1190/",
            },
            {
                "id": "T1059",
                "title": "Command and Scripting Interpreter",
                "source_url": "https://attack.mitre.org/techniques/T1059/",
            },
            {
                "id": "T1078",
                "title": "Valid Accounts",
                "source_url": "https://attack.mitre.org/techniques/T1078/",
            },
        ],
    },
    {
        "key": "nist-csf-2.0",
        "name": "NIST CSF",
        "version": "2.0 (2024-02-26)",
        "role": "reviewer-mapped-outcome",
        "source_url": "https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20",
        "description": "Outcome mappings support communication and do not establish control effectiveness, organizational conformance, or certification.",
        "entries": [
            {
                "id": "ID.AM-01",
                "title": "Inventories of hardware managed by the organization are maintained",
            },
            {
                "id": "PR.AA-01",
                "title": "Identities and credentials for authorized users, services, and hardware are managed by the organization",
            },
            {
                "id": "PR.PS-01",
                "title": "Configuration management practices are established and applied",
            },
            {
                "id": "DE.CM-01",
                "title": "Networks and network services are monitored to find potentially adverse events",
            },
        ],
    },
]

FRAMEWORK_BY_KEY = {value["key"]: value for value in FRAMEWORKS}
MAPPABLE_FRAMEWORKS = ("owasp-top-10-2025", "mitre-attack-enterprise", "nist-csf-2.0")
_CVSS_BASE_METRICS = {
    "3.0": {"AV", "AC", "PR", "UI", "S", "C", "I", "A"},
    "3.1": {"AV", "AC", "PR", "UI", "S", "C", "I", "A"},
    "4.0": {"AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"},
}


def _source_cvss_supported(score: Any, version: Any, vector: Any) -> bool:
    if not isinstance(version, str) or version not in _CVSS_BASE_METRICS:
        return False
    if not isinstance(score, str | int | float) or isinstance(score, bool):
        return False
    try:
        numeric_score = Decimal(str(score))
    except InvalidOperation:
        return False
    if not numeric_score.is_finite() or numeric_score < 0 or numeric_score > 10:
        return False
    if not isinstance(vector, str) or not vector.startswith(f"CVSS:{version}/"):
        return False
    metrics: set[str] = set()
    for item in vector.split("/")[1:]:
        match = re.fullmatch(r"([A-Z]{1,3}):([A-Z]{1,4})", item)
        if match is None or match.group(1) in metrics:
            return False
        metrics.add(match.group(1))
    return _CVSS_BASE_METRICS[version] <= metrics


class ReportStandardReferenceCreate(BaseModel):
    """Human mapping request. Source-derived identifiers are deliberately not accepted here."""

    model_config = ConfigDict(extra="forbid")
    framework: Literal["owasp-top-10-2025", "mitre-attack-enterprise", "nist-csf-2.0"]
    status: Literal["applicable", "not-applicable", "unknown"]
    identifier: str | None = Field(default=None, min_length=1, max_length=80)
    supporting_observation_ids: list[str] = Field(min_length=1, max_length=100)
    rationale: str = Field(min_length=10, max_length=2000)

    @model_validator(mode="after")
    def state_and_identifier(self) -> "ReportStandardReferenceCreate":
        if len(set(self.supporting_observation_ids)) != len(self.supporting_observation_ids):
            raise ValueError("standard reference observation IDs must be unique")
        if self.status == "applicable" and not self.identifier:
            raise ValueError("an applicable mapping requires a curated identifier")
        if self.status != "applicable" and self.identifier is not None:
            raise ValueError("unknown or not-applicable references must not include an identifier")
        return self


class FrozenStandardReference(BaseModel):
    """Reference representation stored in the immutable JSON/PDF snapshot."""

    model_config = ConfigDict(extra="forbid")
    framework: str
    name: str
    version: str
    status: Literal["applicable", "not-applicable", "unknown"]
    relation: Literal["methodology", "reviewer-mapped", "source-reported"]
    identifier: str | None = None
    title: str | None = None
    source_url: str
    rationale: str
    supporting_observation_ids: list[str] = Field(default_factory=list)
    source_record_ids: list[str] = Field(default_factory=list)
    validation: str


def validate_mapping(
    reference: ReportStandardReferenceCreate, finding_observation_ids: set[str]
) -> None:
    if not set(reference.supporting_observation_ids) <= finding_observation_ids:
        raise ValueError(
            "standard mapping evidence must be among this finding's source observations"
        )
    if reference.status != "applicable":
        return
    framework = FRAMEWORK_BY_KEY[reference.framework]
    if not any(entry["id"] == reference.identifier for entry in framework["entries"]):
        raise ValueError("standard identifier is not in the versioned supported catalogue")


def reviewer_reference(
    reference: dict[str, Any], finding_observation_ids: set[str] | None = None
) -> dict[str, Any]:
    validated = ReportStandardReferenceCreate.model_validate(reference)
    if finding_observation_ids is not None:
        validate_mapping(validated, finding_observation_ids)
    reference = validated.model_dump(mode="json")
    framework = FRAMEWORK_BY_KEY[reference["framework"]]
    entry = next(
        (value for value in framework["entries"] if value["id"] == reference.get("identifier")),
        None,
    )
    return FrozenStandardReference(
        framework=framework["key"],
        name=framework["name"],
        version=framework["version"],
        status=reference["status"],
        relation="reviewer-mapped",
        identifier=entry["id"] if entry else None,
        title=entry["title"] if entry else None,
        source_url=entry.get("source_url", framework["source_url"])
        if entry
        else framework["source_url"],
        rationale=reference["rationale"],
        supporting_observation_ids=list(reference["supporting_observation_ids"]),
        validation="reviewer mapping; taxonomy existence is catalogued, applicability is not independently verified",
    ).model_dump(mode="json")


def source_references(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Extract structured CVE/CWE/CVSS only from the exact source fields, never reviewer text."""
    results: list[dict[str, Any]] = []
    for observation in observations:
        observation_id = str(observation.get("id", "unknown"))
        for key, field in (("cve", "cve"), ("cwe", "cwe")):
            identifier = observation.get(field)
            pattern = r"CVE-[0-9]{4}-[0-9]{4,}" if key == "cve" else r"CWE-[1-9][0-9]*"
            if not isinstance(identifier, str) or not re.fullmatch(pattern, identifier):
                continue
            framework = FRAMEWORK_BY_KEY[key]
            results.append(
                FrozenStandardReference(
                    framework=key,
                    name=framework["name"],
                    version=framework["version"],
                    status="applicable",
                    relation="source-reported",
                    identifier=identifier,
                    title=None,
                    source_url=(
                        f"https://www.cve.org/CVERecord?id={identifier}"
                        if key == "cve"
                        else f"https://cwe.mitre.org/data/definitions/{identifier.removeprefix('CWE-')}.html"
                    ),
                    rationale=f"Identifier copied from source observation {observation_id}; no external record validation was performed.",
                    supporting_observation_ids=[observation_id],
                    source_record_ids=[observation_id],
                    validation="source-reported; not independently validated",
                ).model_dump(mode="json")
            )
        score = observation.get("cvss_score")
        version = observation.get("cvss_version")
        vector = observation.get("cvss_vector")
        if not _source_cvss_supported(score, version, vector):
            continue
        framework = FRAMEWORK_BY_KEY["cvss"]
        results.append(
            FrozenStandardReference(
                framework="cvss",
                name=framework["name"],
                version=f"{version} (source-reported)",
                status="applicable",
                relation="source-reported",
                identifier=f"{score} / {version}",
                title=f"Vector: {vector}",
                source_url=(
                    "https://www.first.org/cvss/v4-0/specification-document"
                    if str(version) == "4.0"
                    else "https://www.first.org/cvss/"
                ),
                rationale=f"Score, version and vector copied unchanged from source observation {observation_id}; no score was calculated.",
                supporting_observation_ids=[observation_id],
                source_record_ids=[observation_id],
                validation="source-reported; not recalculated or independently validated",
            ).model_dump(mode="json")
        )
    return results


def framework_register(references: list[dict[str, Any]]) -> list[dict[str, Any]]:
    register: list[dict[str, Any]] = []
    for framework in FRAMEWORKS:
        matches = [value for value in references if value["framework"] == framework["key"]]
        states = {value["status"] for value in matches}
        if framework["key"] == "nist-sp-800-115":
            status = "methodology-reference"
            rationale = "Cited as a testing methodology; citing it does not mean its procedures or live tests were all performed."
        elif not states:
            status = "unknown"
            rationale = "No supported source identifier or reviewer mapping was recorded in the frozen findings."
        elif states == {"not-applicable"}:
            status = "not-applicable"
            rationale = (
                "A reviewer recorded this framework as not applicable for the linked observations."
            )
        elif "unknown" in states or "not-applicable" in states:
            status = "mixed-or-partial"
            rationale = (
                "Applicability varies by linked finding; see per-finding references and rationale."
            )
        else:
            status = "references-present"
            rationale = "References are limited to linked observations and explicit reviewer mappings; they do not establish compliance."
        register.append(
            {
                "framework": framework["key"],
                "name": framework["name"],
                "version": framework["version"],
                "role": framework["role"],
                "status": status,
                "rationale": rationale,
                "source_url": framework["source_url"],
                "reference_count": len(matches),
            }
        )
    return register


def catalogue_payload() -> dict[str, Any]:
    return {"revision": CATALOG_REVISION, "frameworks": FRAMEWORKS}

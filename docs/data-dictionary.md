# Canonical domain v1 — T07

Executable contracts live in `backend/aegistrace/domain.py`; generated schemas in `schemas/domain/`. Frozen relational definitions `schema_v1.py` are migration 0002's source. Change them only through a new migration/version rather than rewriting deployed history.

| Entity | Meaning and relationships |
|---|---|
| Assessment | Owner, name and timezone-aware creation timestamp; no baked-in target |
| ScopeVersion | Assessment-bound numbered targets/exclusions; runtime input, recorded-import or live-request; not authorization proof |
| Asset | Distinct assessment-bound identifier and host/URL/application kind |
| Service / Endpoint | Asset-bound transport location or HTTP path/method |
| ToolRun | Tool/version, scope, source capture timestamp, execution state and explicit live versus recorded-import mode |
| EvidenceReference | Run, SHA-256, capture timestamp, byte/XML/JSON/whole-file pointer; storage implemented in T08 |
| Observation | Immutable source attribution, asset/run/evidence, source key and timestamp; observed-evidence only |
| VulnerabilityConcept | Assessment-level vulnerability identity; CVE nullable |
| Occurrence | Concept plus affected asset/location and original observation; two affected assets retain two occurrences |
| Decision | Attributed reviewer decision or explicitly identified AI inference with rationale/time |
| Finding | Derived conclusion; confirmed/false-positive state requires an actual reviewer decision |
| Approval | Action digest, scope revision, decision, expiry and lifecycle state; this schema does not enable validation execution |
| ReportSnapshot | Immutable source-ID list/digest with limitations; report rendering is a later milestone |

All cross-entity links use composite assessment/ID foreign keys. Duplicate source keys within one run are rejected rather than silently overwriting evidence. Asset identity and scope revision are unique within an assessment. Repository checks prevent occurrence/source asset mismatch and observation/evidence run mismatch. Ownership is checked before access by later APIs.

Unknown CVE, CWE, severity, CVSS, vector/version and confidence remain null. Source vectors are retained verbatim with an explicit version, not recalculated here. Confidence needs a named method and is not automatically a calibrated probability. Source timestamps are retained even when evidence is old; age is not silently replaced by ingestion time. Observation contracts cannot confirm findings; AI decisions cannot serve as reviewer confirmation. Later report/view consumers must preserve these categories.

## Verification and limits

`uv run pytest tests/test_domain.py -m 'not services'` verifies two assets/occurrences, source provenance/nulls, duplicate import protection, cross-assessment rejection and invalid confirmation/values. `test_domain_on_actual_postgresql` runs in hosted CI against real migrated PostgreSQL. Existing migration tests exercise upgrade/downgrade/upgrade. `uv run python scripts/export_domain_schemas.py --check` detects schema drift.

Tests are handcrafted contract records, not scanner captures, genuine fixtures or measured accuracy. T05 remains pending for that corpus; it does not block testing the general-purpose schema. T07 supplies the R07–R11/R16–R18 persistence contract; adapter normalization and correlation accuracy are later work. Direct database administrators can bypass application validation; restricted database roles and append-only audit controls are separate layers.

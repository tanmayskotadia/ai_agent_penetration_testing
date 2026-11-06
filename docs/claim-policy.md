# Evidence claim policy

The application accepts candidate reasoning proposals and structured claims without treating them as confirmed findings or factual report prose. Source observations and severity/CVSS remain explicitly source-reported. `backend/aegistrace/grounding.py` enforces the source-claim contract at proposal storage and again when freezing reports.

## Validation rules

- A claim must cite an observation, evidence object and asset from the same source record.
- CVE, CWE, source CVSS, source severity and title values are reportable only when the exact value appears in the cited observation. A structured CVSS claim without a version or vector is unknown; separately displayed raw source scores remain source-reported.
- Missing or mismatched references, unsupported claim types, unobserved values, and claims requiring unavailable advisory lookup return `state=unknown`, null value and machine-readable reasons.
- A matching imported source proves only that the source reported the value. It does not confirm that the vulnerability exists or that an advisory is current.
- No CVE/CWE advisory feed is configured, so external identifier validity and freshness are not claimed.

`tests/test_grounding.py` contains synthetic test-only cases for fabricated IDs, wrong-asset evidence, missing CVSS version and unavailable advisory lookup. These are engineering checks, not genuine scanner evidence.

## Structured claim enforcement — issue #53

The existing `POST /api/v1/assessments/{id}/reasoning/proposals` boundary now accepts up to 100 structured `claims`. Each records `type`, bounded `value`, `kind` (`fact`, `inference`, or `unknown`), `observation_id`, `evidence_id`, `asset_id`, and optional `requires_external_validation`. Only assessment-owned normalized observations whose evidence IDs are included in the reviewed proposal context are eligible. Evidence access/redaction checks run before grounding. Boolean numeric coercion, nonfinite numbers and oversized values are rejected.

A source-supported value must exactly match the cited observation, evidence and asset. Supported source fields are title, source severity, CVE, CWE and CVSS score. Identifier syntax is checked; numeric CVSS requires the source version and vector. Confirmation, exploitability, impact and remediation are not inferred from source banners, version matches or arbitrary model prose. Unsupported types/values, missing citations, cross-asset references, inferences offered as facts and unavailable external validation produce `state: unknown`, `value: null`, and stable abstention reasons. Contradictory values for the same asset/CVE preserve both observation IDs and require review. They never mutate source observations or create confirmed findings.

Source-supported means only that the imported observation reported the value. It does not establish source authenticity, identifier existence in an authoritative catalog, advisory freshness, score-vector consistency, exploitability or vulnerability truth. No vetted external advisory service/snapshot is currently configured; claims requiring that verification always abstain. Reference URLs alone do not establish validation. A version-only match therefore remains suspected. Provider integration in #52 must submit its candidate claims through this boundary; posting a proposal does not prove a model was called.

The stored proposal contains the grounding results and an attributable audit reference. Model narrative remains escaped, explicitly `ai-inference` / pending human review, with `reportable_narrative: null`. Unsupported model narrative is never copied into factual report prose. The frozen export includes grounded proposal records only when all proposal evidence belongs to the selected result revisions, and revalidates their claims against that exact frozen observation set. The VAPT content/PDF displays accepted values as source-reported and rejected values as unknown, with source citations and reasons. The original observations remain visible separately, including disagreements. Older reports remain immutable.

Verification uses clearly synthetic cases in `tests/test_grounding.py`, `tests/test_grounding_workflow.py`, and the existing inference guard tests. The integrated test exercises import/normalization → proposal → frozen JSON → authenticated PDF; fake identifiers and unsupported remediation/model prose are absent from both export and PDF. This is software-boundary evidence, not genuine scanner evidence, external advisory validation, actual model reasoning or T30 acceptance. No participant credentials or manual cloud setup are required for #53.

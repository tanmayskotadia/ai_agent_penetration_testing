# Evidence claim policy

The current application has no LLM-generated finding or report prose path. Source observations are rendered as source observations, and source severity/CVSS are labeled as source-reported. `backend/aegistrace/grounding.py` is the validation contract for any future factual claim that uses a source field.

## Validation rules

- A claim must cite an observation, evidence object and asset from the same source record.
- CVE, CWE, source CVSS, source severity and title values are reportable only when the exact value appears in the cited observation. A CVSS score without a version is unknown.
- Missing or mismatched references, unsupported claim types, unobserved values, and claims requiring unavailable advisory lookup return `state=unknown`, null value and machine-readable reasons.
- A matching imported source proves only that the source reported the value. It does not confirm that the vulnerability exists or that an advisory is current.
- No CVE/CWE advisory feed is configured, so external identifier validity and freshness are not claimed.

`tests/test_grounding.py` contains synthetic test-only cases for fabricated IDs, wrong-asset evidence, missing CVSS version and unavailable advisory lookup. These are engineering checks, not genuine scanner evidence.

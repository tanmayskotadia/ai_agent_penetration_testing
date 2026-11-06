# Finding triage and confidence policy

Every scanner observation remains an immutable source record. A human reviewer can append a separate decision with one of five states: `suspected`, `confirmed`, `false-positive`, `contradictory`, or `unknown`. Each decision includes an attributed reviewer, timestamp, rationale, assessment-local observation ID, and an audit event. Later decisions supersede earlier decisions only in the current projection; the append-only history remains available.

`contradictory` requires one or more distinct observation IDs from the same assessment. This preserves the disagreement and its provenance instead of averaging, discarding, or silently selecting a source. Other states cannot attach contradiction references. Reviewer decisions never rewrite source evidence or source confidence.

Confidence is source-reported only when a source value and its method are present. Otherwise it is `unknown`. This release does not produce a calibrated probability or train a confidence model. Statistical calibration is deferred until an independently labelled, representative held-out corpus and a documented validation method exist. Reports preserve reviewer state, rationale, contradiction references, confidence method, and calibration status.

## API

- `GET /api/v1/assessments/{assessment_id}/finding-reviews` returns the latest decision per observation and the bounded append-only history.
- `POST /api/v1/assessments/{assessment_id}/finding-reviews` records a decision. Requires reviewer/admin role, an idempotency key, rationale, and observation IDs owned by the assessment.

The endpoint is a human review workflow. It does not verify exploitability, authenticate the legal provenance of imports, or cause a scan to run.


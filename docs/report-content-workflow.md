# Evidence-backed report content

## Purpose and boundaries

The report-content review step lets an authenticated human reviewer write the report narrative that cannot be inferred safely from a scanner alert alone. It does not change scanner observations, validate exploitability, or convert an import into a live scan. Unreviewed observations remain distinct from reviewer-authored findings. Empty impact and remediation fields stay `unknown` in the report.

Each report finding is an append-only, versioned review record linked to one or more observations in the same assessment. Revisions use optimistic concurrency. A frozen JSON/PDF export includes the report-content revision and selected evidence revisions; later imports or edits do not alter an already frozen export. Create a new export to include later changes.

## UI workflow

1. Sign in with a reviewer or administrator account and open the assessment workspace.
2. Import and normalize permitted evidence through the recorded-input workflow. The evidence must belong to the assessment before it can be selected.
3. In **Evidence-backed report content**, select **New report finding** or choose a prior report finding to revise.
4. Select the supporting observation rows. A source observation can be assigned to only one current report finding. The rows show their title, asset ID, and evidence ID.
5. Enter the finding title, evidence-backed description, and a rationale of at least 10 characters. Technical impact, business impact, remediation, and references are optional; leave them empty when the source and reviewer cannot support a claim.
6. Save the reviewed content. On a stale revision conflict, reload the list and reapply the intended edits. The panel reports that a new export is needed.
7. Freeze a new result export including every result revision that contains the selected observations. Download its JSON and PDF. Verify that the selected observation IDs, source hashes, reviewer narrative, and separate finding/occurrence totals appear in the export.

The UI does not provide an exploitability confirmation control here. Use the separate finding-review workflow for validation state; its decision and the original source text remain attributable records.

## API contract

- `GET /api/v1/assessments/{assessment_id}/report-findings` returns the current global content revision, latest finding records, and append-only history.
- `POST /api/v1/assessments/{assessment_id}/report-findings` creates or revises report content. It requires `expected_revision`, `observation_ids`, `title`, `description`, and `rationale`. Optional narrative fields are `technical_impact`, `business_impact`, `remediation`, and `references`; omitted values remain unknown.
- A stale `expected_revision` returns `409`. An observation that is missing or belongs to another assessment returns `404`. Reusing an observation assigned to a different current report finding returns `409`. Non-human or non-reviewer/admin callers are denied.
- `POST /api/v1/assessments/{assessment_id}/result-exports` freezes a new JSON snapshot. Retrieve its PDF at `/api/v1/assessments/{assessment_id}/result-exports/{export_id}/pdf`.

The export distinguishes reviewer findings, source observations, ranked entries, canonical finding records, and source occurrences. CVSS, severity, confidence, CVE/CWE, timestamps, tool versions, evidence hashes/pointers, scope, processing state, approval decisions, and limitations are shown only when present in the frozen source records; unsupported values remain explicit unknown/not supplied. Source severity and CVSS are not recalculated. Authorization references are participant-supplied and are not independently verified.

## Failure and omission behavior

- An assessment with no selected observations produces an explicit empty report section; it is not described as a clean result.
- Partial/failed processing outcomes and denied actions remain visible in the execution/decision sections.
- If a finding links observations not included in the export selection, that finding is omitted and the limitation explains that its source revisions must be selected.
- Snapshot row limits are recorded as limitations and mark the frozen snapshot incomplete.
- An export is immutable. Verify its SHA-256 before relying on its content; making new source imports or reviewer edits requires creating another export.

All inputs and screenshots used to demonstrate this workflow should be synthetic or explicitly authorized. Do not include credentials, request/response bodies, or unauthorized target data in a report.

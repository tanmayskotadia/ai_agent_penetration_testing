# Evidence-backed report content

## Purpose and boundaries

The report-content review step lets an authenticated human reviewer write the report narrative that cannot be inferred safely from a scanner alert alone. It does not change scanner observations, validate exploitability, or convert an import into a live scan. Unreviewed observations remain distinct from reviewer-authored findings. Empty impact and remediation fields stay `unknown` in the report.

Each report finding is an append-only, versioned review record linked to one or more observations in the same assessment. Revisions use optimistic concurrency. A frozen JSON/PDF export includes the report-content revision and selected evidence revisions; later imports or edits do not alter an already frozen export. Create a new export to include later changes.

The current `content_revision` is `1.2`, which adds grounded priority rationales, impact/remediation bases, a reviewer-suggested remediation owner, and verification steps to the versioned report contract.

## UI workflow

1. Sign in with a reviewer or administrator account and open the assessment workspace.
2. Import and normalize permitted evidence through the recorded-input workflow. The evidence must belong to the assessment before it can be selected.
3. In **Evidence-backed report content**, select **New report finding** or choose a prior report finding to revise.
4. Select the supporting observation rows. A source observation can be assigned to only one current report finding. The rows show their title, asset ID, and evidence ID.
5. Enter the finding title, evidence-backed description, and a rationale of at least 10 characters. If you enter technical impact, add its source-evidence basis. If you enter business impact, add its assumptions/basis. If you enter remediation, include the observed technology/evidence that supports it and concrete verification or retest steps. A suggested remediation owner is optional and must be supplied by the reviewer; the application does not assign or notify people. References are optional; leave impact or remediation fields empty when the source and reviewer cannot support a claim. The API rejects unsupported partial narratives.
6. Save the reviewed content. On a stale revision conflict, reload the list and reapply the intended edits. The panel reports that a new export is needed.
7. Freeze a new result export including every result revision that contains the selected observations. Download its JSON and PDF. Verify that the selected observation IDs, source hashes, reviewer narrative, and separate finding/occurrence totals appear in the export.

The UI does not provide an exploitability confirmation control here. Use the separate finding-review workflow for validation state; its decision and the original source text remain attributable records. Reviewer-supplied impacts and recommendations are attributed to their author and shown as unverified, proposed actions; recommendations are never marked completed or applied by this workflow.

## API contract

- `GET /api/v1/assessments/{assessment_id}/report-findings` returns the current global content revision, latest finding records, and append-only history.
- `POST /api/v1/assessments/{assessment_id}/report-findings` creates or revises report content. It requires `expected_revision`, `observation_ids`, `title`, `description`, and `rationale`. Optional fields include `technical_impact`, `technical_impact_basis`, `business_impact`, `business_impact_basis`, `remediation`, `remediation_basis`, `remediation_owner`, `verification_steps`, and `references`. Supplying technical or business impact requires its corresponding basis; supplying remediation requires its observed basis and at least one verification/retest step. Omitted values remain unknown.
- A stale `expected_revision` returns `409`. An observation that is missing or belongs to another assessment returns `404`. Reusing an observation assigned to a different current report finding returns `409`. Non-human or non-reviewer/admin callers are denied.
- `POST /api/v1/assessments/{assessment_id}/result-exports` freezes a new JSON snapshot. Retrieve its PDF at `/api/v1/assessments/{assessment_id}/result-exports/{export_id}/pdf`.

The executive summary is deterministically assembled from frozen counts, severity labels, reviewer validation states, selected processing outcomes, and the selected-revision risk ranking. For the top three review entries, it shows the supported factor values/references and explicitly lists missing context as the priority rationale. It identifies its observations as source records, labels local priority as an uncalibrated triage aid, lists partial/failed runs, and states the coverage/authorization boundary. It does not use model-generated prose.

The export distinguishes reviewer findings, source observations, ranked entries, canonical finding records, and source occurrences. CVSS, severity, confidence, CVE/CWE, timestamps, tool versions, evidence hashes/pointers, scope, processing state, approval decisions, and limitations are shown only when present in the frozen source records; unsupported values remain explicit unknown/not supplied. Source severity and CVSS are not recalculated. Authorization references are participant-supplied and are not independently verified. Business assumptions, remediation basis, suggested owner, and verification steps are attributed to the reviewer; the system does not independently certify the recommendation, assign/notify an owner, or execute it.

## Failure and omission behavior

- An assessment with no selected observations produces an explicit empty report section; it is not described as a clean result.
- Partial/failed processing outcomes and denied actions remain visible in the execution/decision sections.
- If a finding links observations not included in the export selection, that finding is omitted and the limitation explains that its source revisions must be selected.
- Snapshot row limits are recorded as limitations and mark the frozen snapshot incomplete.
- An export is immutable. Verify its SHA-256 before relying on its content; making new source imports or reviewer edits requires creating another export.

All inputs and screenshots used to demonstrate this workflow should be synthetic or explicitly authorized. Do not include credentials, request/response bodies, or unauthorized target data in a report.

## Tracing a finding to its source

Use the PDF contents to open the detailed findings. In a finding, select its linked **Evidence ID** to jump to the entry in the frozen evidence manifest. The entry shows the source hash and capture metadata. An ID without a link has no corresponding entry in that export's manifest.

In **Report**, **Download matching JSON** downloads the same frozen export as the PDF. **Download frozen PDF again** retries that export without creating another snapshot.

To inspect the source in AegisTrace, sign in, select the assessment listed in the PDF, and open **Findings & review**. In **Finding validation and uncertainty**, paste the source observation ID or evidence ID into **Observation or evidence ID from report**. Use the evidence inspector on the matching row. The filter searches the assessment's current observation inventory. If an older observation is absent, use the frozen manifest to identify its original reference. Source access still depends on your role and assessment permissions.

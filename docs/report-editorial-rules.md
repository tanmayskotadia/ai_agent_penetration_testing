# Grounded report editorial rules

These rules govern executive summaries, impact statements, and remediation text in the current VAPT report. The report builder assembles its summary deterministically from frozen records. It does not ask a language model to invent business context or prescribe fixes.

## Source alignment

This implementation maps to the participant-supplied PS-1 report requirements recorded in [`docs/compliance-matrix.csv`](compliance-matrix.csv): REPORT-01 (executive summary, PDF 7.1 p5), REPORT-15 (business and technical impact, PDF 7.5 p6), REPORT-16 (actionable remediation, references and retest guidance, PDF 7.5 p6), REPORT-18 (limitations, PDF 7.6 p6), and QUAL-12 (technical accuracy and visual review, PDF p10). It supports the report-content portion of those requirements; it does not claim an authorized live assessment or satisfy the end-to-end demonstration gate by itself.

## Evidence categories

- **Observed evidence:** scanner/import text and normalized source fields, linked to observation, evidence, asset, tool, and capture metadata.
- **Reviewer decision:** validation state and narrative supplied by an authenticated human reviewer. It is attributable, but not independently verified by the application.
- **Inference or assumption:** must be named as such and include its basis. Never render it as a source fact.
- **Unknown:** use `unknown` or `not supplied`; do not replace a missing value with a plausible guess.

## Executive summary

The generated summary uses only the selected frozen revisions. It reports counts, source-severity distribution, reviewer validation states, a bounded list of priority-review observations with their documented factor rationale and missing context, and partial/failed source-processing states. It explains that:

- source observations are not confirmed vulnerabilities;
- source severity/CVSS values are reproduced, not recalculated;
- the local priority index is an uncalibrated review aid, not CVSS or an exploitability probability;
- displayed priority rationale contains only source-reported or provenance-backed inputs; unknown factors remain explicit;
- only selected revisions are represented, and authorization/authenticity/complete coverage are not independently established;
- recommendations are supplied by a reviewer, not independently validated or executed.

An empty report says no source observations were selected and explicitly avoids a clean-assessment conclusion. A partial or failed run appears in the summary and the detailed execution section; it must not be hidden by favorable findings elsewhere.

## Technical and business impact

- Technical impact must describe the observable effect and its affected asset/endpoint as supported by selected source observations or reviewer validation.
- Business impact requires an explicit basis or assumption. Describe the business function and dependency only when the reviewer supplied that context. The application records who supplied the statement; it does not validate the business relationship.
- Separate potential impact from confirmed effect. A suspected finding can have a potential impact statement, but the report must preserve its suspected/unconfirmed status.
- Do not infer data exposure, compromise, customer impact, regulatory scope, exploitability, or asset criticality from a severity label alone.
- References are reviewer supplied; existence, freshness, and applicability are not independently checked unless a separately documented validation service actually ran.

## Remediation and verification

When remediation is supplied, the reviewer must include:

1. The exact observed technology/configuration or source evidence that makes the action relevant.
2. A corrective action framed as a proposal; the application never executes it or records it as completed.
3. At least one safe verification or retest step. State what evidence would demonstrate the change, and preserve the existing scope/approval boundary for any active test.
4. Optionally, a reviewer-supplied suggested owner. This is a report field only; it does not assign work, send notifications, or imply acceptance by that person.
5. Applicable source or baseline references where available. Unknown baselines remain unknown.

If the observation does not identify enough technology or configuration detail to support a specific action, leave remediation unknown or request analyst review. Prefer a bounded, non-destructive inspection and validation step over an exploit or state-changing command. No remediation text may claim a CVE, exploit path, patch, or successful fix unless its source and status are recorded.

## Review checklist

For each reviewer-authored finding, confirm that its selected observations and assets are correct; technical/business impact has the stated basis; remediation corresponds to the observed system and uncertainty; verification steps are safe and measurable; references are relevant; and no proposed action is presented as executed. Have a security reviewer check the technical statements and a nontechnical reader check that the executive summary communicates risk and uncertainty without jargon.

Synthetic examples and tests are marked `TEST ONLY`. They validate formatting and policy behavior, not scanner accuracy or real-world remediation correctness.

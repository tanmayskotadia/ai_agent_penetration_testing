# Evidence-driven replanning

The analyst workspace can ask the configured reasoning provider to recommend a bounded next evidence step. A recommendation is AI inference, not a finding, vulnerability confirmation, scan, authorization, or action approval. Replanning does not create scan jobs.

## Operator workflow

1. Open an assessment in **Analyst view** and use **Replan from evidence**.
2. Confirm the displayed scope revision and select only normalized result revisions in that exact scope. Quarantined and older-scope results are excluded.
3. Inspect each selected original's provenance status. A provenance review is a human assertion; it does not change the original or independently verify its source. Generate and inspect the matching redacted derivative; mark it reviewed only if it is safe. The server requires a current reviewed derivative as an access/review gate, but does not send its text to the model.
4. Enter a narrowly scoped question. Before submitting, review the hosted provider's current data terms and decide whether the bounded assessment context and your request may be sent. Confirm the service has an approved private data-processing policy and enter its exact reference. Check the consent box only after deciding the actual inputs are acceptable. Raw originals, derivative text and credentials are not sent. Avoid placing sensitive details in your request.
5. Inspect the saved decision, rationale, cited observation links, available and rejected candidates, assumptions, expected information gain, stop conditions, and sanitized provider trace. `TEST ONLY` responses are synthetic and must never be represented as a live model result.
6. Follow **Open saved plan and its separate human review** to review or reject the plan. That review still does not authorize scanner execution. Any later action requires the distinct action approval process.

If the scope changes, reload and select evidence again. If there is no eligible evidence, stop and import an authorized recorded artifact. Provider configuration, policy mismatch, redaction review, validation, budget, or rate-limit blockers are shown without treating a failed response as a recommendation. A retry after provider failure is a separate, explicit action. Repeating an unchanged evidence/action request reuses the saved plan instead of making another provider call.

## Hosted acceptance still requires a human operator

Code-level and synthetic browser checks do not prove that the hosted provider is configured or that sending a particular bounded context is acceptable. Before a real provider-backed rehearsal, the operator must review the service's privacy/data-processing terms and private configuration, inspect the selected sources and their redacted derivatives, decide whether the normalized assessment context is permitted for external processing, and provide the approved policy reference plus request-scoped consent in the UI. Never paste an API key into the UI or chat. The derivative is required for review/access control but its text is not passed to the provider.

For the rehearsal, use a current-scope, reviewed HTTP observation as the positive case. Compare it with an SSH-only observation, conflicting evidence, and an already-covered candidate. Capture the assessment, selected scope/result revision IDs, saved plan ID/revision, cited observation IDs, sanitized provider trace, hosted deploy revision, and the observed repeat-request behavior. Confirm that no scan job or action approval was created. Label the record as a reviewer-run acceptance exercise, not as proof of vulnerability or organizer authorization. Do not close the corresponding acceptance issue until this hosted run is recorded.

## Implementation contract

The workspace calls `POST /api/v1/assessments/{assessment_id}/reasoning/replan`. The result-revisions response includes the owning `scope_id` and `scope_revision` so clients can enforce exact current-scope selection. The stored adaptive plan is linked to plan review and the audit timeline. It contains the sanitized decision/provider metadata and remains subject to the backend's consent, policy, scope, evidence and retry gates.

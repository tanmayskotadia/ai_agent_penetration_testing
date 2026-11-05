# Assessment intake and draft plans

`POST /api/v1/assessments/{assessment_id}/plans/intake` accepts a bounded user request, optional conversation ID, exact current scope ID/revision, and bounded constraints. The response is an immutable `WorkflowResource` plan revision and can be reloaded with `GET /api/v1/assessments/{assessment_id}/plans`.

## Planner behavior

- `deterministic-intake-v1` uses bounded text matching and a fixed tool/format map. It does not call an LLM, perform DNS, fetch a URL, or generate shell commands.
- Without an explicit scope, the request is saved as `blocked`, includes a scope clarification, and has no proposed actions.
- A target mentioned in the request must match an exact scope target. A target in exclusions or outside the set blocks the plan. Subdomains are not implicitly included.
- Requests for active validation stay blocked and explain the separate action-bound human approval and verified isolated-runtime requirement.
- A valid draft only proposes participant-supplied Nmap XML, ZAP Alerts JSON, Nikto JSON, or OpenAPI JSON imports. It never executes a scanner. Unavailable/unsupported evidence remains a prerequisite, not a claimed result.
- Conversation text and a participant-supplied authorization reference are not proof of permission. Missing authorization context is disclosed; scope creation is not a live execution grant.
- Every revision is persisted, linked to the scope revision and audit event, and points to the prior plan ID when revising the same conversation. Stale scope revisions return `409`.
- The UI supplies existing result-revision IDs. The API validates assessment ownership and compares their scope IDs/revisions. A normalized import already present in the exact current scope is not proposed again; prior results from different scopes are disclosed and ignored. Failed prior imports require review before a fresh capture is suggested.
- Each proposed input states that parser code is present while native execution, scanner edition, license and authenticity remain unverified.
- Downstream jobs and approvals reject blocked plans and plans without a bound scope.

## Manual inputs for an actual assessment

The participant must enter the exact approved target set, exclusions, and request, then supply genuine artifacts and source metadata through the recorded import interface. The application can validate that these values match the stored scope; it cannot independently authenticate authorization or scanner provenance. Live scanning remains disabled in this deployment.

## Verification

`tests/test_planning_intake.py` uses synthetic, test-only strings to exercise scope omission, exact target matching, exclusions, active-request abstention, and import-only plan steps. `test_plan_intake_persists_revisions_scope_checks_and_owner_access` verifies persisted revisions, owner isolation, blocked-plan rejection, and stale-scope failure using a disposable SQLite database. These tests are not scanner captures, authorization proof, or prototype acceptance evidence.

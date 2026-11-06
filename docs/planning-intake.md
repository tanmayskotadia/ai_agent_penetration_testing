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

## Analyst decision contract (T37 / issue #51)

Each intake proposal captures the configured capability registry without promoting its status. A candidate import parser can remain `planned` until genuine verification; an absent or revoked/unsupported parser produces a clarification and blocks approval. Unsupported explicit tool requests are not silently ignored. Proposed steps include scope ID/revision, targets/exclusions, the offline profile, limits, prerequisites, expected evidence and alternatives. `information_kind` identifies this as a deterministic proposal, distinct from source evidence and AI inference. Actual model reasoning belongs to #52.

1. Create a draft with `POST /api/v1/assessments/{assessment_id}/plans/intake` and inspect its `request.proposal` and `request.review_digest`.
2. A human `reviewer` or `admin` submits `POST /api/v1/assessments/{assessment_id}/plans/{plan_id}/reviews` with `plan_revision`, `plan_digest` (the returned review digest), `decision` (`approve` or `reject`), and a 10–2000 character rationale. Standard authenticated mutation headers are required.
3. Reload durable decisions through `GET /api/v1/assessments/{assessment_id}/plan-reviews`. The decision records reviewer, timestamp and audit event, and always returns `authorizes_execution: false`.

The digest binds the plan ID, revision and complete stored request, including scope, constraints and capability snapshot. Changed digests, stale scopes, superseded conversation revisions and duplicate decisions return `409`; analyst/service identities cannot approve. A rejected revision cannot request downstream jobs/approvals. Create a new plan revision for reconsideration. Blocked proposals cannot be approved. Review does not mutate the original plan or grant active-validation permission; that remains the separate action approval mechanism. UI controls consuming this API are tracked in #54.

### Issue-level acceptance evidence

`tests/test_planning_intake.py` checks scope/intent clarification, exclusions, exact target matching, reused/stale sources, revoked/absent capabilities and step rationale/limits. `tests/test_api_contracts.py` checks durable revision history, ownership, digest tampering, role authorization, approval/rejection, supersession and unchanged denial. The integrated minimum-prototype test exercises intake with downstream imports/review/report using explicitly synthetic inputs. This proves the intake/review software contract, not model reasoning, genuine scan execution or T30 completion. No cloud keys or manual participant action is needed for #51's software acceptance.

## Assessment inputs

The participant must enter the exact approved target set, exclusions, and request, then supply genuine artifacts and source metadata through the recorded import interface. The application can validate that these values match the stored scope; it cannot independently authenticate authorization or scanner provenance. Live scanning remains disabled in this deployment.

## Verification

`tests/test_planning_intake.py` uses synthetic, test-only strings to exercise scope omission, exact target matching, exclusions, active-request abstention, and import-only plan steps. `test_plan_intake_persists_revisions_scope_checks_and_owner_access` verifies persisted revisions, owner isolation, blocked-plan rejection, and stale-scope failure using a disposable SQLite database. These tests are not scanner captures, authorization proof, or prototype acceptance evidence.

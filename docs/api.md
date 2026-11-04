# Authenticated API v1 — T10

`schemas/openapi.json` is generated from the executable FastAPI app; `frontend/src/generated/api.ts` exposes matching schema types. `scripts/export_api_contracts.py --check` detects drift. The frontend provides authenticated assessment review, recorded Nmap XML upload/normalization/replay and persisted-cursor SSE without putting tokens into URLs or local storage. Live scanner controls remain disabled.

## Identity and resource authorization

Every private route requires a short-lived operator-issued bearer identity. The server derives assessment ownership from its verified subject, never a client-supplied owner header. Owner checks apply to reads, writes, SSE, evidence and checkpoint download, including cached idempotent replays. Wrong-owner resources return 404. An auditor cannot mutate; reviewed redactions require a reviewer identity. This M02 foundation does not implement public sign-in, organization membership, refresh tokens or immediate revocation; T15/T53 supply those before shared multi-user deployment. There is no public token-minting endpoint. Public system readiness exposes capability status, not private evidence.

## Endpoints and truthful states

All routes below start `/api/v1`. POST/PUT payload contracts use schema version `1.0` unless the body is raw original bytes.

| Route | Behavior |
|---|---|
| POST/GET `/assessments` | Create/list owning user's runtime assessment; list capped at 100 |
| GET `/assessments/{id}` | Read owning user's assessment |
| POST `/assessments/{id}/scopes` | Create next immutable scope revision with runtime targets/exclusions and authorization reference; this is not live authorization verification |
| GET `/assessments/{id}/scopes` | List the owning user's immutable scope revisions in order |
| GET `/assessments/{id}/scopes/{scope}` | Read a versioned scope |
| POST `/assessments/{id}/assets` | Record an asset identity without contacting it |
| POST `/assessments/{id}/runs` | Record supplied tool version/capture time as `recorded-import`; cannot create a live run |
| POST `/assessments/{id}/runs/{run}/evidence` | Register original digest/capture/pointer metadata |
| GET `/assessments/{id}/evidence/{evidence}` | Read canonical source reference |
| PUT `/assessments/{id}/evidence/{evidence}/original` | Store bounded hash-matching encrypted original with explicit `expires_at` query parameter |
| POST `/assessments/{id}/evidence/{evidence}/download-ticket` | Issue short-lived authenticated download ticket; replay may return the original now-expired ticket, so request a new key for a fresh ticket |
| GET `/assessments/{id}/evidence/{evidence}/original` | Exact-byte attachment with bearer and `X-Download-Ticket` |
| POST evidence `redaction` / `redaction-review` | Generate candidate redaction / explicitly review derivative |
| POST `/assessments/{id}/plans` | Persist draft revision-1 plan steps for current scope; no model or execution implied |
| POST `/assessments/{id}/jobs` | Persist request with `blocked`, `execution-not-enabled`; never sends a scanner task |
| POST `/assessments/{id}/imports` | Persist supported-tool/format/evidence request as `pending-ingestion`; T11 supplies the ingestion boundary |
| POST `/assessments/{id}/imports/{import}/normalize-nmap` | Normalize user-supplied Nmap XML as `recorded-import`; no scan is invoked |
| POST `/assessments/{id}/imports/{import}/normalize-zap` | Normalize bounded ZAP Alerts JSON as source-linked, suspected observations; no ZAP API or scanner call |
| POST `/assessments/{id}/imports/{import}/normalize-nikto` | Normalize version-gated Nikto 2.6.x JSON observations; no Nikto process is started |
| POST `/assessments/{id}/imports/{import}/normalize-openapi` | Catalog OpenAPI 3.0/3.1 JSON operations offline; never fetches servers or uses credentials |
| GET `/assessments/{id}/coverage` | Show recorded runs, endpoint catalog/alert counts, capability matrix and explicit prototype acceptance checks; does not claim tested coverage |
| GET `/assessments/{id}/action-approvals/profiles` | Read the scan-impact profile catalog; this is not an execution grant or live-scan switch |
| POST `/assessments/{id}/replays` and `/replays/{manifest}/ingest` | Create a signed recorded-input manifest and replay the private capture without a network call |
| POST `/assessments/{id}/approvals` | Persist request as `pending-review`; cannot grant approval or authorize an action |
| POST `/assessments/{id}/reports` | Persist request as `blocked`, `report-renderer-not-enabled`; no invented PDF or findings |
| GET `/assessments/{id}/result-revisions` | Read source-linked immutable result revision summaries |
| POST `/assessments/{id}/result-exports` | Reviewer freezes chosen revisions into an immutable, hashed export |
| GET `/assessments/{id}/result-exports/{export_id}/pdf` | Download a PDF evidence summary from the frozen export; does not assert full coverage or complete VAPT conclusions |
| GET `/assessments/{id}/resources/{kind}/{resource}` | Read workflow request and explicit state |
| GET `/assessments/{id}/findings` or `/findings/{finding}` | Read canonical derived findings; empty remains empty until populated by real workflows |
| GET `/assessments/{id}/events` | Finite batch of at most 100 persisted audit SSE events |
| GET `/assessments/{id}/scan-jobs` | Latest 50 owner-bound durable job snapshots with truthful worker state and heartbeat freshness |
| GET `/assessments/{id}/scan-jobs/{jobId}/events` | Finite batch of at most 100 append-only per-job SSE progress events; resume with `Last-Event-ID` |
| GET `/assessments/{id}/audit/checkpoint` | Private signed checkpoint attachment for independent retention |

Scope creation serializes on the assessment row and requires the next revision. New workflow requests check the current scope; job/approval requests also require a matching plan revision. A new scope invalidates use of a previous plan. Plans are immutable drafts; adaptive revision workflows belong to M07. Bounds on source steps prevent oversized narratives. Imports must reference evidence belonging to the same assessment. Recorded inputs never appear as live results. Contract test artifacts are not source-data authenticity proof.

## Atomic mutations, errors and retries

Every mutation requires `X-Request-ID` (UUID) and `Idempotency-Key` (8–128 printable ASCII characters). Optional `X-Correlation-ID` is a UUID; responses echo request attribution. Body bytes are capped before JSON deserialization (256 KiB normally, 2 MiB for originals), including chunked requests.

Mutation receipts are scoped to verified actor, method/path and a digest of the idempotency key. The canonical request digest, domain change, audit writes and cached successful response share one SQL transaction. Identical retries return the same resource/status with `Idempotent-Replay: true`; changed input returns typed 409. Concurrent retries serialize using the database receipt row; no receipt commits without the matching business change. Failed mutations roll back their receipt. There is no idempotency expiry in this version: retain receipts for the life of the corresponding assessment. A future cleanup policy must not create duplicate side effects.

Errors have `code`, `message`, `request_id`; schema validation errors do not echo raw input values or tokens. Documented codes include unauthenticated, forbidden, not-found, conflict, body-too-large, invalid-request and unavailable. The frontend must present blocked/pending/failed states honestly rather than treating HTTP 202 as execution success.

SSE is authenticated and finite to tolerate free-host restarts. Reconnect with `Last-Event-ID` equal to the last fully received event. Events are persisted before transmission; replay is at least once and clients deduplicate by sequence. The frontend uses authenticated fetch (native EventSource cannot attach this bearer header). Empty batches include a retry hint; no in-memory event list is canonical state.

## Verification

`tests/test_api_contracts.py` covers runtime scope/plan inputs, duplicate/conflicting/concurrent requests, no duplicate jobs/reports, stale revisions, wrong owner, missing/forged credentials, invalid schema/headers, oversized bodies, read-only roles, SSE reconnect and checkpoint attachment. Hosted CI reruns idempotency/concurrency and events on real PostgreSQL. Evidence API regression tests run through the same receipt mechanism; fresh migration tests cover rollback/forward. R01/R02/R10/R12/R22/R28 are supported at the contract/persistence layer; actual assessment reasoning, execution and report content belong to their later milestones.

Durable scan-job snapshots use the same assessment access check as other private routes. Job progress is a finite persisted event batch per job, separate from canonical audit SSE. It reports worker-supplied attempt, duration, version and bounded exit status; it never estimates a percentage. Stale heartbeat presentation is derived as `unknown` while the last persisted state remains available until reconciliation. Diagnostics are selected from fixed safe messages; raw stderr and arbitrary exception text are excluded.

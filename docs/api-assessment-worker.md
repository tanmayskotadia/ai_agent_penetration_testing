# API assessment worker — T27 / issue #44

This change provides an isolated-runner library and improves the offline definition importer. It does not enable target requests from the public API or finish issue #44.

## Definition contract

The OpenAPI 3.x parser now applies operation-level servers before path-level servers before document servers. Every declared server is included in scope checking, even when overridden. Server variables and path references are rejected rather than silently interpreted. Security alternatives retain OpenAPI OR semantics between alternatives and AND semantics within each alternative; an empty alternative permits anonymous access. Query-bearing servers remain rejected. Import normalization preserves the effective URL and original security alternatives with each operation.

## Worker contract

`aegistrace.api_assessment.assess_operations` accepts an immutable, content-hashed operation plan, an exact set of approved method/URL pairs, a callback that reloads current execution policy, a worker-owned credential provider, cancellation and a trusted transport. Even GET requires explicit approval, because a GET handler can change state. No body, query substitution, automatic login, OAuth token refresh, cookie replay, path-variable substitution or arbitrary authentication scheme execution is supported. Missing support is not inferred as success.

The default transport makes one HTTPS request to the authorized pinned IP with certificate/hostname verification, no environment proxy, no redirects and no response-body collection. It verifies the connected peer before TLS. It uses socket timeouts; the enclosing runner must also enforce a total job deadline, process isolation and kernel egress rules. One batch is sequential and spaces requests according to current policy. Global concurrent batches and policy rate reservations must be enforced by the existing durable job dispatcher; this library's spacing is not a distributed rate limiter.

Bearer/header API-key credentials are supplied only by the trusted worker provider, with an explicit HTTPS origin and expiry. They are hidden in model repr and never copied into result records. Header names and values are validated; routing/framing/proxy/cookie headers are rejected. Credentials are reloaded per operation. Each AND alternative must have every credential and nonconflicting headers. If no alternative is usable, the operation is blocked before dispatch. The provider must be scoped to the assessment and reviewed schemes; it must not expose arbitrary environment-variable lookup to a caller.

Results record method/URL, attempted state, status code, success/failure/exclusion and authentication limitations. HTTP 2xx means request success; it does not prove which identity was authenticated or establish vulnerability status. 401/403 are rejected, redirects are failed without following them, and missing/expired credentials leave the operation unattempted. Hidden/unlisted routes never count as covered. Credential and transport exception text is discarded.

## Verification

`tests/test_api_assessment.py` uses a disposable test-only FastAPI application to exercise public, protected and forbidden routes and a wrong-token request. Separate adversarial checks cover missing/expired/wrong-origin credentials, unapproved destructive methods, external destinations, cancellation, scope exclusions, modified plan digests, redirects, provider error redaction and OpenAPI server/security semantics. The disposable transport is in-process and does not establish the deployed pinned-TLS/kernel boundary.

## Remaining integration before #44 closes

1. Connect execution to authenticated persisted assessment jobs and reloaded approval/policy state, including global reservations, cancellation and a total deadline. No arbitrary HTTP execution route should be enabled in the application process.
2. Run it in the isolated worker/collector environment tracked by #28; verify the default pinned HTTPS transport against a private test service and negative DNS/TLS/egress cases.
3. Resolve dedicated assessment credentials using a secure provider; persist only safe references. Verify deployed rotation/revocation and origin binding.
4. Persist source-linked operation results and derive endpoint/method attempted, succeeded, failed, excluded and untested counts from them. Connect those records to #46 and report snapshots.
5. Complete integrated API/evidence/approval acceptance and then update the prototype gate from verified records, not fixed success values.

These steps remain implementation work. No participant local setup or real credentials are required to develop or run the disposable tests. Once the private runner exists, the participant will enter dedicated test credentials into the selected secret store, supply only secret references plus expiry/origin, and approve the exact target/method set. No organizer questions are required to build this software. Applicable authority is still required before real target requests are enabled.

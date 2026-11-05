# Web scan impact and API coverage (T27–T29)

## Impact profile catalogue

`GET /api/v1/assessments/{id}/action-approvals/profiles` returns the versioned read-only impact rules. `enforcement_state` is `review-bound`: both generic approvals and API checks bind the profile digest and reject changed rules at dispatch. `execution_enabled` remains false for native scanner execution; `api_check_execution_available` identifies the concrete active-web API-check path. The catalogue never grants permission. See [rules of engagement](rules-of-engagement.md) for parameters, side effects, limits and consent.

`passive-web` means analysis of already captured/proxied HTTP messages without target requests. Crawling, spidering, fetching and active-mode escalation are denied. Active-web API checks require exact selected operations, reviewed scope/policy, an impact statement and reset instructions. Actual rate/concurrency, cancellation, TLS pins and a supervised deadline are enforced by the private worker. Native ZAP/Nikto execution and offensive validation remain unavailable. Acceptance traffic uses only a disposable test-owned server.

## API definitions and authenticated sessions

OpenAPI 3.0/3.1 JSON files are parsed offline through the same encrypted artifact boundary. The parser records operation method/path, security requirement names and JSON pointers, but never follows `$ref`, downloads servers, logs in, accepts credentials, or copies examples/descriptions into normalized output. Scope and exclusions are checked against each declared server/operation before catalog endpoints are written. The returned state is `definition-only-untested`; definitions do not prove endpoints are reachable or were scanned.

The separate API-check workflow now stores encrypted assessment-bound bearer/header API-key credentials, with origin, expiry and revocation. It saves per-operation outcomes and exposes them in coverage and terminal JSON exports. No credential is included in those outputs. HTTP success does not establish authenticated identity. Cookie replay and automatic OAuth refresh remain unsupported. See [API assessment worker](api-assessment-worker.md).

## Coverage view semantics

`GET /api/v1/assessments/{id}/coverage` aggregates source runs, assets, catalogued endpoints, API-definition operations, imported ZAP/Nikto alert endpoints and source observations beside the seven-tool capability registry. It deliberately reports `coverage-not-established`. Alert locations are positive observations, not the denominator or proof that all API operations were attempted. OpenAPI operations represent a declared surface, not exercised coverage. Genuine scanner coverage needs a versioned runner artifact with attempted/succeeded/blocked/failed operations and source pointers.

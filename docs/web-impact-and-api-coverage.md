# Web scan impact and API coverage (T27–T29)

## Impact profile catalogue

`GET /api/v1/assessments/{id}/action-approvals/profiles` returns the versioned read-only profile catalogue. Every profile declares whether it can generate network traffic, whether a fresh human approval is required, and its implementation limitations. `execution_enabled` is always false and `enforcement_state` is `catalogue-only`: this endpoint is documentation for review, not a permission grant or runtime rate limiter. The approval service independently binds a single-use review to the current scope, policy, plan, evidence, impact profile and reset instructions. It still does not start a scanner.

`passive-web` means analysis of already captured/proxied HTTP messages with no fetch/crawl from this product. A future integration must not silently issue requests under this profile. `active-web` may send test payloads and change target state; it must remain unavailable until an authorized lab, bounded request/rate/redirect policy, out-of-scope redirect denial, timeout, cancellation and reset behavior are verified. Offensive validation stays disabled. No external target was contacted for this implementation.

## API definitions and authenticated sessions

OpenAPI 3.0/3.1 JSON files are parsed offline through the same encrypted artifact boundary. The parser records operation method/path, security requirement names and JSON pointers, but never follows `$ref`, downloads servers, logs in, accepts credentials, or copies examples/descriptions into normalized output. Scope and exclusions are checked against each declared server/operation before catalog endpoints are written. The returned state is `definition-only-untested`; definitions do not prove endpoints are reachable or were scanned.

Authentication credentials are intentionally absent from the current import form and API. A later authenticated runner must use an isolated, short-lived session broker; bind the session and expiry to a named assessment/scope; redact cookies and authorization headers from raw result views; report per-operation auth outcome and coverage; and revoke/clear credentials on cancellation or completion. Until then authenticated endpoint coverage is `unknown`, not passed.

## Coverage view semantics

`GET /api/v1/assessments/{id}/coverage` aggregates source runs, assets, catalogued endpoints, API-definition operations, imported ZAP/Nikto alert endpoints and source observations beside the seven-tool capability registry. It deliberately reports `coverage-not-established`. Alert locations are positive observations, not the denominator or proof that all API operations were attempted. OpenAPI operations represent a declared surface, not exercised coverage. Genuine scanner coverage needs a versioned runner artifact with attempted/succeeded/blocked/failed operations and source pointers.

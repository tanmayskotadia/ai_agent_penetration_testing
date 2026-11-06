# OWASP ZAP recorded Alerts import (T25)

## Delivered behavior

The authenticated import route accepts user-supplied ZAP 2.x Alerts JSON in either the Alerts API shape (`{"alerts": [...]}`) or the ZAP Traditional JSON Report shape (`{"site": [...]}`). Traditional reports may include `@programName`, which is accepted as report metadata. The ZAP version remains a concrete ZAP 2.x release string supplied with the import. The importer does not launch ZAP, call its API, follow links, send target requests, or start either passive or active scanning. This route imports the output of work already done in ZAP; the fact that an imported alert exists does not show whether its original source traffic was proxied, replayed, crawled, passively analyzed, or actively tested.

The bounded parser runs in the isolated parser child with a 10-second wall-clock budget for ZAP imports, rejects duplicate JSON keys and unsupported shapes, and retains ZAP `id`, `pluginId`, `alertRef`, source risk/confidence labels, source pointers, HTTP method, origin, path and safe parameter names. Query keys and the ZAP parameter label are retained without values. Normalized URLs omit query strings and fragments. Request and response headers/bodies are not copied into normalized records; the original evidence remains encrypted, source-hash linked, and available only through the evidence access controls. Every endpoint is matched against the current declared scope and exclusions; any out-of-scope entry quarantines the import. The resulting observations remain `suspected`, with no CVE, confirmed finding, calibrated probability or exploitability claim.

All committed ZAP test samples are handcrafted software tests, not genuine scanner evidence. These tests prove parser and encrypted-import behavior only.

## Current #38 scope and acceptance

The 6 November 2026 roadmap reset narrows this issue to the supported recorded-import path. The live ZAP API/Automation Framework runner, authentication/session configuration, passive traffic generation, active scans, cancellation and isolated scanner networking are deferred; they are not prerequisites for closing this narrowed software task. The importer and analyst UI are already available on the hosted application.

Before marking the user-evidence gate complete, the participant must provide one genuine ZAP 2.x Alerts JSON file from a target they were permitted to test, together with its reported ZAP version, capture timestamp, exact in-scope URL(s), exclusions and source/authorization reference. No local setup or new live scan is needed for the import demonstration. Do not label the handcrafted fixtures in this repository as genuine.

1. Sign in to the deployed application and select the intended assessment. Confirm its scope and exclusions before importing.
2. In **Import evidence and API definitions**, select **OWASP ZAP Alerts JSON**, choose the participant-provided file, enter the exact URLs represented, the source/authorization reference, the version reported by the file, and the reported capture time.
3. Store and normalize the import. Confirm it is labeled `recorded-import`, the source hash/run/evidence references are present, every endpoint is in scope, query/parameter values are absent from normalized output, and observations remain `suspected`.
4. In **Source provenance review**, inspect the displayed SHA-256, run and evidence identifiers against the source you received. Record `genuine-permitted-capture` only if the provenance is personally established; otherwise leave it unverified or reject it. This is an attributable human assertion, not independent scanner or authorization proof.
5. Save the normalization and source-review IDs plus the sanitized assessment reference for the issue's acceptance record. The original remains encrypted; do not paste it or secrets into GitHub.

If a genuine permitted Alerts JSON file is not available, the code and synthetic integration tests can still be reviewed, but the genuine-source demonstration remains open. Do not provision a scanner or run a live test just to satisfy this import-only scope.

## Live runner status

No ZAP API or Automation Framework runner is delivered in this repository. Native ZAP execution remains unavailable and the capability registry correctly remains `planned`. The versioned profile catalogue describes approval rules but does not submit ZAP work. In particular, a passive-only permission must never call an import option that sends requests or an active-scan job. ZAP Automation Framework plans can configure contexts, include/exclude paths, authentication and ordered jobs; the import job explicitly supports `sendRequests: false` by default, while setting it true sends requests and follows redirects. Do not infer runtime permission from an uploaded definition or plan. This paragraph describes deferred native execution and is not a blocker for the current recorded-import scope.

If a later issue authorizes native execution, a private runner will need a pinned ZAP/add-on version, internal-only API listener, API-key secret and enforceable egress allowlist. That future runner must check action-bound approvals, scope and exclusions, enforce request/time budgets, block redirect escapes, observe cancellation, and record actual ZAP/add-on versions and run timestamps. No such runtime is currently present, so the capability remains `planned` and we do not represent this as a working live integration.

Format/control references: [ZAP API](https://www.zaproxy.org/docs/api/), [Automation Framework](https://www.zaproxy.org/docs/desktop/addons/automation-framework/), [Automation environment, contexts, exclusions and authentication](https://www.zaproxy.org/docs/desktop/addons/automation-framework/environment/), [Automation import job and `sendRequests`](https://www.zaproxy.org/docs/desktop/addons/import-export/automation/), and [authentication guidance](https://www.zaproxy.org/docs/desktop/addons/automation-framework/authentication/). API access or a locally valid plan does not grant target authorization.


If an import times out, it remains quarantined and creates no observations. Upload it as a new import after the service is available; the existing normalization record is immutable.

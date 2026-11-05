# Seven-tool capability contract — T12

The API, frontend and report snapshot helper use `aegistrace.capabilities.capability_snapshot()`. The default registry is conservative and has no scanner installed/edition/API claim. `config/integration-matrix.json` is its generated review artifact, not an independently edited status table. No user-facing endpoint can toggle a tool to live/import-only. Provider status and findings never imply an adapter is verified.

| Tool | Current mode | Edition/version/license | Native integration |
|---|---|---|---|
| Nmap | planned | unverified | No normalizer/live adapter; bounded XML container guard only |
| Nessus | planned | unverified | Candidate bounded offline `.nessus` XML parser and source-linked host/plugin observations; no genuine version-matched capture, Tenable API entitlement, or live runner verified |
| Greenbone / OpenVAS | planned | unverified | Candidate bounded offline XML report parser; QoD stays source metadata; no genuine capture, GMP client, manager/feed/configuration readiness, or live runner verified |
| Nikto | planned | unverified | Candidate offline 2.6.x JSON import normalizer; no verified adapter or live runner; genuine versioned capture and permitted lab demonstration pending |
| OWASP ZAP | planned | unverified | Candidate offline Alerts JSON normalizer; no verified adapter or live runner; genuine versioned capture and permitted lab demonstration pending |
| Burp Suite | planned | unverified | Candidate bounded offline issue XML parser; base64 request/response bodies stay in private encrypted original; no genuine capture, edition/export/API entitlement, or live runner verified |
| Metasploit | planned | unverified | No module execution or validation adapter enabled |

**Verified working integration count: 0.** Nmap, Nessus, Greenbone, ZAP, Nikto, Burp and OpenAPI now have offline candidate parsing/normalization paths in the application. Handcrafted parser tests and user-declared metadata do not verify source authenticity, licensing, installed edition, or scanner integration; capability mode therefore remains `planned`. The PDF's minimum three genuine permitted integrations/imports with network and web coverage remains an M05 gate. M06's import implementations still require genuine format/version fixtures and review before an issue can close. Neither parser tests nor format recognition satisfy those gates.

## Typed adapter boundary

`workers/aegistrace_workers/adapters/base.py` defines healthcheck, capabilities, plan validation, submit, status, cancel, collect and normalize. Plans reference assessment/scope/revision and asset UUIDs, a bounded profile and action digest rather than a shell command. ExecutionGrant is a transport contract only: deterministic runtime policy must verify identity, expiry, scope/action binding, revocation and single use outside the LLM before dispatch. A Pydantic instance or adapter `accepted` boolean is not permission to execute.

Collected artifacts retain tool/version, run, capture time, format, hash and explicit live/recorded-import mode. Normalize produces observations with source pointers, never silently confirmed findings. Unknown run/cancel outcomes remain unknown; callers reconcile status rather than blindly resubmitting external side effects. Worker queue cancellation, real scanner timeouts and actual scope enforcement are later implementation, not claimed by the protocol.

## Verification-gated mode changes

The operator-only registration function requires a complete capability declaration plus matching proof, ToolRun, EvidenceReference, fixture metadata and original hash. It rejects missing license/edition/version verification, source/run/assessment mismatch, handcrafted/unreviewed source, mismatched adapter/API versions, unsupported import format and future timestamps. Live additionally needs a completed live run, actual live-capture provenance and explicit authorization/runtime-gate verification references. Import-only stays labelled recorded and cannot become live because its source tool can scan.

Capture authenticity, license entitlement and genuine contract-suite results still require trusted operator review: matching metadata and a digest cannot authenticate a person or prove execution. Proof records must reference real CI/run/capture evidence before production registration. Never install synthetic test attestations into the actual registry. Registration is in-process and fails back to planned on restart; durable verified registry loading and signed release artifacts should be added with real adapters rather than assuming remembered status remains valid.

The JSON registry includes supported formats, guarded container names, installed edition/version, API version, license reference/status, adapter implementation, last verified run/time, demonstration label and limitations. Null means unknown, not a successful probe. The report facade snapshots this exact source; later report generation must preserve it alongside its frozen input revisions.

## Verification

`tests/test_capabilities.py` checks all seven default names, API/status/report equality, copy isolation, missing license/API-version/source/hash/run/authority failures and consistent status/mode. Positive policy branches use explicitly labelled simulated proof metadata in an isolated test registry; they are not genuine captures or demonstration evidence and never modify the default registry. A structural live/import protocol harness returns unknown/no artifacts and performs no scanner/network action. `scripts/export_capabilities.py --check` validates the generated matrix/adapter schemas; the frontend uses generated Capability types.

R05/R06/R23/R29 are represented by truthful per-tool modes and explicit incomplete integration gates. R10/R27 receive typed status/failure contracts; actual seven-check assessment demonstration remains later work. No commercial license, working scanner or report is invented by this milestone.
# Coverage/status consumers (T29)

The workspace and reviewer exports now use the shared evidence-derived coverage snapshot described in [coverage transparency](coverage-transparency.md). All seven scanner capability records remain explicit. Candidate imported sources, normalization failures and completed/unknown job states are separate from verified live/import-only status. A trusted operator can revoke availability/entitlement without erasing the last verification history; a new working claim still requires reviewed proof. Current credential state and historical API results are shown separately, and disposable test requests never count as live coverage. Frozen JSON/PDF exports retain their capture-time statuses and digest rather than reading a later registry.


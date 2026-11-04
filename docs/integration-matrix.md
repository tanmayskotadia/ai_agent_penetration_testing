# Seven-tool capability contract — T12

The API, frontend and report snapshot helper use `aegistrace.capabilities.capability_snapshot()`. The default registry is conservative and has no scanner installed/edition/API claim. `config/integration-matrix.json` is its generated review artifact, not an independently edited status table. No user-facing endpoint can toggle a tool to live/import-only. Provider status and findings never imply an adapter is verified.

| Tool | Current mode | Edition/version/license | Native integration |
|---|---|---|---|
| Nmap | planned | unverified | No normalizer/live adapter; bounded XML container guard only |
| Nessus | planned | unverified | No entitled product API/export adapter verified |
| Greenbone / OpenVAS | planned | unverified | No installed manager/feed/API adapter verified |
| Nikto | planned | unverified | Candidate offline 2.6.x JSON import normalizer; no verified adapter or live runner; genuine versioned capture and permitted lab demonstration pending |
| OWASP ZAP | planned | unverified | Candidate offline Alerts JSON normalizer; no verified adapter or live runner; genuine versioned capture and permitted lab demonstration pending |
| Burp Suite | planned | unverified | Edition/export/API entitlement unverified |
| Metasploit | planned | unverified | No module execution or validation adapter enabled |

**Verified working integration count: 0.** Nmap and ZAP now have candidate offline import paths, but handcrafted contracts and user-uploaded files do not verify source authenticity or establish scanner integration. The PDF's minimum three native integrations/imports with network and web coverage remains an M05 gate. The full seven-tool target remains M06 work. Neither mock classes nor container recognition satisfies those gates.

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

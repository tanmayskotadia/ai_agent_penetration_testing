# M05 implementation status

This status separates implemented recorded-input behavior from acceptance evidence. The app performs no target requests from these paths. All imported originals remain private encrypted evidence; user-declared tool versions and rights are not independently authenticated.

| Issue | Implemented in workspace | Remaining acceptance evidence / manual input |
|---|---|---|
| T25 #38 — ZAP | Bounded offline Alerts JSON parser; scope/exclusion checks; endpoint and source-linked suspected observations; scanner IDs and safe parameter names retained while query values and request/response contents stay in encrypted evidence; no ZAP API or scanner execution | Engineering verification covers parser and encrypted-import behavior only. Live runner/API plan integration is not implemented. Genuine version-matched output and a private isolated ZAP runner with approved scope, exact contexts/exclusions, auth method, and one-time action approval are needed to demonstrate live/passive/active behavior; the organizer-authorized demo and manual source review remain pending |
| T26 #39 — Nikto | Bounded offline Nikto 2.6.x JSON report parser; preserves test IDs/references/pointers; does not infer severity/CVE or confirmation; older schema versions are quarantined | Genuine Nikto 2.6.x capture and source review; authorized demo before claiming verified scanner behavior |
| T27 #44 — API definitions/auth | OpenAPI server/security semantics; AES-GCM assessment credentials; persisted digest-bound human-reviewed operation jobs; private supervised HTTPS execution; revocation, cancellation and crash reconciliation; source-linked endpoint results, coverage and JSON exports | Integrated disposable application and real local HTTPS acceptance are implemented. Participant input is not required for software tests. Production isolated-runner deployment remains #28; actual deployment must receive runtime scope and restricted credentials. See api-assessment-worker.md. |
| T28 #45 — Impact policies | Versioned review-bound rules, profile-specific option rejection, passive/crawl separation, profile digest checks at both approval systems and dispatch, explicit impact/reset inputs and reviewed runtime limits; CI verifies generated profile export | Disposable policy and HTTPS workflow acceptance covers engineering controls. No participant input is needed for tests. Native scanner/production runner deployment and offensive validation remain separate capabilities. |
| T29 #46 — Coverage/status | Shared coverage v2 snapshots derive source states, seven-tool status, per-method worker outcomes, credential health and gaps; live/test outcomes are separate; reviewer exports freeze the same snapshot and PDF fields; truncation and invalid results remain explicit | Software acceptance includes disposable workflow, capability/credential revocation, UI rendering and frozen report consistency. Genuine capture authenticity, native integration verification and broader prototype acceptance remain separate. See coverage-transparency.md. |
| T30 #72 — Mandatory prototype gate | Deterministic gate exposes each unmet evidence criterion, and reviewers can download a PDF summary from frozen source revisions; fabricated samples do not count as acceptance evidence. The coverage API now exposes source-linked correlation candidates and transparent source-score ordering | Still open: verified three-tool network+web imports, authorized end-to-end demonstration, authenticated API coverage, full endpoint attempts, reviewer acceptance of real cross-tool candidate groups/ranking, and review of a real-data report. The PDF summary is not a complete VAPT report |

## Checks run

- Ruff lint: passed.
- mypy backend: passed (64 source files).
- Frontend TypeScript and production build: passed.
- OpenAPI and capability registry generation checks: passed.
- Git whitespace check: passed.
- The focused result-export test could not start its Starlette TestClient on this Windows environment: asyncio stalled while creating its self-pipe socket, before the test body. Hosted CI should execute it.

## Handoff inputs

The user can supply genuine Nmap XML, ZAP Alerts JSON, Nikto 2.6.x JSON and an OpenAPI JSON definition through the product's recorded-input form; no local scanner installation is needed to exercise those offline imports. To claim live scan behavior, someone must provide an organizer-authorized lab scope and valid session credentials through a secure, isolated runner design. The current deployment has no authenticated scanner runner. A reviewer can now freeze and download a source-linked PDF evidence summary; this does not satisfy a complete VAPT report or assessment-coverage acceptance gate. M05 remains open pending genuine source files, validated behavior on those files, the authorized lab demonstration and the other gate evidence.


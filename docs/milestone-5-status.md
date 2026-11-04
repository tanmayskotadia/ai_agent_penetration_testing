# M05 implementation status

This status separates implemented recorded-input behavior from acceptance evidence. The app performs no target requests from these paths. All imported originals remain private encrypted evidence; user-declared tool versions and rights are not independently authenticated.

| Issue | Implemented in workspace | Remaining acceptance evidence / manual input |
|---|---|---|
| T25 #38 — ZAP | Bounded offline Alerts JSON parser; scope/exclusion checks; endpoint and source-linked suspected observations; passive/active impact labels remain separate; no ZAP API or scanner execution | Genuine version-matched ZAP Alerts JSON with redaction review; an authorized demo is still required to claim a verified integration or active-mode behavior |
| T26 #39 — Nikto | Bounded offline Nikto 2.6.x JSON report parser; preserves test IDs/references/pointers; does not infer severity/CVE or confirmation; older schema versions are quarantined | Genuine Nikto 2.6.x capture and source review; authorized demo before claiming verified scanner behavior |
| T27 #44 — API definitions/auth | Offline OpenAPI 3.0/3.1 JSON catalog; stores method/path/auth-scheme names and source pointers; scope checks before catalog writes; no URL fetching or credential storage | A real API definition can be uploaded in the product; authenticated session handling and per-operation auth outcomes remain unimplemented and therefore unknown |
| T28 #45 — Impact policies | Read-only impact catalog distinguishes no-request passive review, request-generating active web checks, bounded discovery and disabled offensive validation. Existing human approvals remain single-use and action-bound; no scan runner is enabled | No authorized lab is available for live profile verification. Catalogue rate suggestions are descriptive, not enforcement controls |
| T29 #46 — Coverage/status | Assessment coverage API and UI show source runs, endpoint catalog, alert endpoints, observations, tool capability modes, and an explicit `coverage-not-established` status. Review-only deterministic cross-tool candidate correlation preserves source observations; ordering uses source-reported CVSS only | Genuine captures and an instrumented runner are needed to report attempted/succeeded/blocked operations. Alert locations do not establish denominator coverage. Candidate grouping requires reviewer validation and is not confirmed deduplication |
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

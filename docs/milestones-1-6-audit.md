# Milestones 1–6 acceptance audit — 5 November 2026

## Verified repository state

Audit covers all 36 task issues and six milestone trackers. Existing closed implementation tasks remain closed. No additional open task currently satisfies its whole acceptance gate. M04's six implementation tasks are complete, but tracker #5 still requires a genuine authorized integrated assessment.

Latest implementation baseline: 7a89768dfa46d5c862bd1796f10e96eb95f21699. Hosted [Foundation CI](https://github.com/tanmayskotadia/ai_agent_penetration_testing/actions/runs/41924503636) passed both foundation and egress jobs: Python checks, real PostgreSQL migration/API tests, Redis/Celery, frontend build, container startup and actual kernel egress tests. This supersedes earlier comments saying hosted CI was unavailable. Synthetic integration tests establish software behavior, not source authenticity or authority.

| Milestone | Closed / attached | Progress | Remaining |
|---|---:|---:|---|
| M01 | 4/7 | 57% | #17 lab, #19 corpus, #2 tracker |
| M02 | 7/7 | 100% | Complete at its engineering scope |
| M03 | 5/7 | 71% | #28 deployed runner isolation, #4 tracker |
| M04 | 6/7 | 86% | #5 genuine integrated acceptance |
| M05 | 0/7 | 0% | #38 #39 #44 #45 #46 #72 and #6 tracker |
| M06 | 0/7 | 0% | #40 #41 #33 #42 #47 #50 and #7 tracker |

GitHub's milestone aggregate counters were stale despite attached closed issues. Removing and immediately restoring one existing closed issue's milestone association forced recalculation for M01–M04. Issue state and milestone membership were preserved. There is no independently editable progress percentage; GitHub derives it from closed/total attached issues, including trackers. If stale counters recur, record the issue's current milestone, temporarily clear that field, restore the same milestone, then verify counts. Do not reopen completed issues to adjust percentages.

## Open work and ownership

| Issue | Delivered | Engineering still owned by implementation agent | Participant/external input |
|---|---|---|---|
| #17 | Strict offline authorization manifest, denial tests | Provision approved hosted targets, verify health/reset/network boundary after scope exists | Genuine applicable authority, exact permitted targets/actions/exclusions/rates/validity; no credential values in Git |
| #19 | Provenance/split validation | Ingest rights-cleared files; test parsers and evaluation splits | Genuine captures; a separate reviewer supplies labels and reviewer identity |
| #28 | Kernel egress test harness | Real scanner runtime, private authenticated collector, deployed routing and denied-flow acceptance | A suitable isolated hosted runner and permitted target scope |
| #5 | All six M04 engineering tasks closed with CI records | Integrated scanner/job/evidence acceptance on approved runner | Same lab/runner/source prerequisites; no new local setup |
| #38 | Offline ZAP Alerts JSON parser | Versioned live/passive/active adapter, exact contexts/exclusions, auth and approval integration, bounded execution | Genuine version-matched exports; live entitlement/session and scope only for live claims |
| #39 | Offline Nikto JSON parser | Installed-version negotiation, reviewed bounded runner, raw-message and cancellation acceptance | Genuine supported Nikto 2.6.x exports; approved target for execution |
| #44 | OpenAPI catalog; encrypted credentials; reviewed durable jobs; supervised pinned HTTPS; source-linked method results, coverage and JSON exports; integrated disposable application and actual local HTTPS tests | Engineering implementation delivered; close only after exact-commit hosted acceptance passes. Production isolated runner deployment remains #28 | None for software acceptance; actual use later requires runtime API scope and restricted account entered privately |
| #45 | Impact catalog and existing single-use approval controls | Bind concrete profile parameters to execution approval; deny unknown options, enforce actual rates/timeouts and verify no drift | Approved traffic/action limits for runtime acceptance |
| #46 | Coverage snapshot, source labels, seven-tool status UI, explicit unknown coverage | Derive attempted/succeeded/blocked method coverage from actual runner events; verify status/report/UI integration | Real input records and independent review of resulting coverage |
| #72 | Prototype gate, source-linked summaries and correlation candidates | Complete request/planning integration, minimum three verified imports, authenticated endpoint coverage, approved transition, professional VAPT PDF and integrated review | Genuine network/web exports, permitted demo scope and reviewer |
| #40 | Offline Nessus XML normalizer | Genuine-file compatibility regression; explicit edition/API entitlement evidence and verified fallback | Genuine .nessus exports with product/edition/version details |
| #41 | Offline Greenbone XML normalizer with QoD metadata | GMP version negotiation, feed/task/config health and bounded approved control when available | Genuine XML; permitted manager/version/feed details if live GMP is required |
| #33 | Offline Burp issue XML, encrypted original | Bounded safe request/response evidence handling and analyst attachment/handoff review; edition-aware support verification | Genuine edition-matched XML and redaction/source review |
| #42 | Offensive execution remains disabled | Narrow reviewed validation templates, approval-bound parameters, isolated execution, stop/timeout and cleanup proof | Authorized lab and explicitly approved validation actions; no arbitrary console access |
| #47 | Candidate compatibility docs and synthetic parser checks | Genuine per-version contract regressions, reviewed supported/unsupported matrix and status promotion | Rights-cleared files and actual edition/license/feed/API evidence |
| #50 | Shared offline observations and candidate correlation | Genuine integrated network/web/infrastructure workflow, partial availability handling, validated transitions and results | Coherent real capture set and reviewer decisions |

Trackers #2, #4, #5, #6 and #7 remain open until their linked task and integrated acceptance gates are satisfied. Providing files alone does not finish the remaining engineering above. Missing engineering is not assigned to the participant.

## Manual procedure: no local installation required

1. **Authority:** use only an existing applicable written authorization or already-published applicable lab permission. Retain the original privately. Record issuer/reference, targets, exclusions, permitted actions, rate/concurrency limits and validity. A self-authored manifest is not independent proof of authority. In the hackathon profile, organizer-lab rules still apply. If no applicable authorization exists and organizer questions are unavailable, keep live execution pending; offline software work may continue.
2. **Files:** obtain original permitted exports from the authorized environment's operator or an existing rights-cleared capture set. Needed formats are Nmap XML, ZAP Alerts JSON, Nikto 2.6.x JSON, Nessus .nessus XML, Greenbone report XML and Burp issue XML. Also retain the OpenAPI JSON definition for API catalog testing. The participant does not need to install scanners locally.
3. **Metadata:** for each artifact record tool/product edition, exact version, capture time/timezone, target scope/authorization reference, collection method, redistribution rights, source hash and redaction review. Do not rename invented/test samples as genuine captures.
4. **Private handling:** keep originals, credentials and authorization documents out of public issues. Provide artifacts through a private handoff or the authenticated upload workflow once a deployed, verified application is available. Source versions are runtime inputs. Current repository code does not establish that a production deployment is ready.
5. **Independent review:** have a reviewer inspect source records and label duplicate occurrences, distinct assets, contradictions, clean cases, and suspected/confirmed/false-positive status. Record rationale, source pointers and reviewer identity. Keep held-out evaluation labels separate from development samples. An implementer's own labels do not satisfy independent review.
6. **Credentials later:** when the runner and secure store are ready, provision a dedicated restricted lab account and store the value through that store. Supply only its secret reference in application requests; never paste passwords/API keys into chat or public issues.
7. **Acceptance:** the implementation agent validates hashes and formats, runs regression tests, verifies scope/approval enforcement, records exact run IDs and CI evidence, and updates capability status only when justified. A reviewer checks the genuine result/report and transitions before an issue closes.

## Runtime and account boundary

GitHub MCP and the approved CLI are sufficient for repository issue/commit/CI work. Supabase and Render can support application data and hosting, but connected accounts alone do not prove an isolated scanner runtime, secret-injection design, or lab authority. No additional MCP is required for this audit. A concrete runner hosting decision and its network capabilities must be evaluated before enabling live scanners. Existing projects must remain separate from the requested dataops project.

## Correction shipped with this audit

A frozen evidence-summary PDF previously set the professional-report prototype gate to passed. The gate now reports summary availability separately and remains unaccepted until full professional VAPT report generation/review exists. This removes a false acceptance signal; it does not claim the full report is implemented.


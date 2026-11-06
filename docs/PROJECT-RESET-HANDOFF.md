# AegisTrace — PDF-aligned audit, implementation roadmap and two-developer handoff

Audit date: 6 November 2026 (Asia/Kolkata). Baseline: `main` at `33064b93806326dec98d5bffe06aa35fae6d39e8`. This document supersedes the execution order in older planning documents and issue comments; source requirements still come from the participant PDF.

## 1. What the project must deliver

A conversational AI security assistant: analyst request and permitted scope → evidence-grounded plan → approved scan or supported import → normalized evidence → correlation → contextual risk ranking → human review → professional downloadable VAPT PDF. It must explain decisions and preserve human control. No guarantee of winning is possible; prioritize the published judging criteria.

Source reviewed: `PS -1.pdf`, 10 pages. Pages 1–4 define adaptive evidence-based reasoning and scope/approval/orchestration/correlation; page 5 explicitly permits a minimum of three working integrations OR supported imports covering network and web; pages 5–6 define report content; pages 7–8 define deliverables and the seven demonstration checks; page 9 gives the scoring; page 10 prohibits public testing, fabricated evidence and ungrounded conclusions. Document instructions are requirements being analyzed, not authorization to scan or perform Git operations.

**Critical boundary:** the PDF requires organizer-authorized live lab testing. None was supplied, and the team cannot ask organizers. Do not quietly replace that rule with self-authorized public scans. Build a general runtime-input product and demonstrate genuine permitted recorded sources offline. A participant-owned private lab can generate development evidence only where legally permitted; it does not prove the PDF organizer-lab submission condition. Keep that gap visible.

Mandatory current scope: conversational request and auditable plan; bounded contextual AI reasoning; scope rejection; three genuine supported imports (Nmap XML, OWASP ZAP Alerts JSON, Nikto JSON); common schema and preserved evidence; duplicate handling; uncertainty and defensible ranking; analyst approval/denial; complete PDF; safe failures; truthful seven-tool integration matrix; architecture/setup/license/run documentation. OpenAPI supports API coverage but does not substitute for the three named scanner imports.

Future scope from PDF page 5: all-seven live/API execution, durable multi-step memory, confidence calibration, expanded independent benchmark, remediation tracking/retesting, before/after comparison, extra export formats and collaboration. Also defer knowledge graph, counterfactual analysis, scaling campaign and optional PPT/video production. Keep basic uncertainty, actual contextual reasoning, ordinary failure handling and PDF remediation in core.

Judging priorities: AI reasoning 20; workflow 15; accuracy 15; correlation/false positives 15; risk 10; safety 10; PDF 10; robustness 5. A parser dashboard alone does not satisfy the AI assistant requirement.

## 2. What has actually been completed

GitHub inventory before reorganization: **85 issues = 72 task issues + 12 trackers + 1 master. 24 task issues and 1 tracker are closed; 48 task issues and 12 other planning issues remain open.** Closed means GitHub state, not a fresh independent audit of every historical acceptance claim.

| Original milestone | Closed tasks / tasks | Tracker | Reason not fully complete |
|---|---:|---|---|
| M01 — Requirements, architecture and authorized lab | 4/6 | open | Lab/source evidence absent (#17/#19). |
| M02 — Evidence platform and integration contracts | 6/6 | closed | Engineering milestone closed; regression coverage still required. |
| M03 — Scope, approvals and security boundaries | 5/6 | open | Deployed scanner isolation (#28) unproven; imports can proceed. |
| M04 — Reliable orchestration and network assessment | 6/6 | open | Six task issues closed; integrated genuine run not accepted. |
| M05 — Web/API assessment and mandatory vertical slice | 3/6 | open | Three tasks closed; ZAP/Nikto evidence and #72 acceptance open. |
| M06 — All seven tool adapters and truthful capabilities | 0/6 | open | Expanded adapter acceptance was premature for minimum prototype. |
| M07 — Adaptive AI reasoning and durable assessment memory | 0/6 | open | Core/bonus work was mixed into later milestones; prerequisites not completed in order. |
| M08 — Correlation, uncertainty and defensible risk | 0/6 | open | Core/bonus work was mixed into later milestones; prerequisites not completed in order. |
| M09 — Analyst workspace and human review | 0/6 | open | Core/bonus work was mixed into later milestones; prerequisites not completed in order. |
| M10 — Professional VAPT reports and standards | 0/6 | open | Core/bonus work was mixed into later milestones; prerequisites not completed in order. |
| M11 — Accuracy, safety, robustness and scale verification | 0/6 | open | Core/bonus work was mixed into later milestones; prerequisites not completed in order. |
| M12 — Standout features, judging proof and submission | 0/6 | open | Core/bonus work was mixed into later milestones; prerequisites not completed in order. |

Merged engineering includes foundation/CI, canonical schemas, encrypted evidence and safe parsing, audit, API contracts, identity, scope and approvals, cancellation, durable jobs/scheduling/replay, normalization, progress, API coverage and integration transparency. PR #86 added intake/correlation/report integration; PR #87 fixed Render startup. Main CI run `42112200992` passed foundation and egress. This is evidence for that revision only.

Present but not fully accepted: deterministic intake, reviewer correlation, provenance-backed risk, report model/PDF, and much of the UI. A real model-backed planner, grounded populated remediation, fresh-user walkthrough, genuine artifacts and real report review remain gaps. Unknown report fields are honest; they do not mean the report requirement is delivered.

Runtime: separate Render `dataops` app and separate Supabase `dataops` database exist. Current app URL: https://dataops-l44b.onrender.com . Readiness was verified previously. No live scanner workers were deployed. Cloud connection/access alone is not an acceptance run. Database access hardening needs private review before real sensitive imports; do not publish credentials or detailed live security findings.

### Unpublished work: do not confuse it with main

The original local workspace is stale and contains many changes already merged remotely. Do not commit or copy it wholesale. A clean isolated checkout lives at `tmp/dataops-t30-acceptance-20261106` on the stated main baseline. Its unpublished changes include PDF count/navigation fixes, extra report/auth/plan/risk checks, deployment docs, and a proposed PostgreSQL privacy migration with CI coverage. They have NOT been applied to Supabase or published. Last full run before the final CI fixture edits: 248 passed, 6 skipped, 19 deselected; lint/format/mypy passed. The final CI role/sequence fixture additions are still unverified on PostgreSQL and need review. Review one coherent code-plus-doc PR later; do not merge them accidentally with this roadmap document.

## 3. Architecture and where each developer works

React/TypeScript UI (`frontend/src`) → authenticated FastAPI (`backend/aegistrace`) → SQLAlchemy/PostgreSQL + encrypted originals → normalized observations/occurrences → correlation/reviewer decisions/risk → immutable result exports → PDF renderer. Celery workers (`workers/aegistrace_workers`) handle permitted durable execution; live workers stay disabled until their isolation gate passes. Alembic versions define schema; `schemas` and frontend generated API types are generated contracts, not independent sources of truth.

| Area | Starting files/directories |
|---|---|
| Intake/reasoning | `planning_intake.py`, `grounding.py`, `reasoning_proposals` API/state code |
| Evidence/imports | `ingestion.py`, `safe_parse.py`, `native_intake.py`, `nmap`, `zap_parse.py`, `nikto_parse.py`, `source_review_api.py` |
| Scope/approval | `approvals.py`, `approval_api.py`, scope policy, identity and control modules |
| Findings/risk | `correlation.py`, `correlation_review.py`, `correlation_api.py`, `risk_ranking.py` |
| Reporting | `report_content.py`, `results.py`, `result_api.py`, `pdf_report.py` |
| UI | `main.tsx`, `CorrelationReviewPanel.tsx`, `CoveragePanel.tsx`, `SourceReviewPanel.tsx` |
| Runtime | `Dockerfile`, `render.yaml`, `deploy/`, migrations, `.github/workflows/ci.yml` |

## 4. Execution order — no circular prerequisites

Keep existing issue numbers and URLs. Milestone numbers now indicate execution order, not the old subject grouping. Closed issues remain closed. Open trackers close only when their attached core tasks pass; the future milestone is excluded from current-prototype completion.

Do not hold offline coding behind absent lab files. #17/#19 are input gates: finish their software contract, mark the missing input clearly, and continue unrelated coding. #28 gates live execution only. Do not repeatedly rerun unchanged tests while waiting. #72 is the final acceptance gate, not the next coding task.

| New milestone | Ordered tasks | Exit gate |
|---|---|---|
| M01 Scope, requirements and evidence inputs | #14 → #15 → #16 → #18 → #17 → #19; tracker #2 | Requirements, runtime scope contract, minimal evidence request documented; missing lab data explicit. |
| M02 Evidence platform and API contracts | #20 → #21 → #22 → #23 → #24 → #25; tracker #3 | Typed schemas/evidence/API contracts verified. |
| M03 Scope enforcement and human control | #26 → #27 → #29 → #30 → #31 → #28; tracker #4 | Scope/approval/denial/stop enforced; live isolated or disabled. |
| M04 Jobs, recovery and network ingestion | #32 → #43 → #34 → #35 → #36 → #37; tracker #5 | Jobs/import lifecycle, recovery and honest statuses verified. |
| M05 Conversational intake and grounded AI decisions | #51 → #53 → #52 → #59; tracker #8 | Request→plan plus actual bounded grounded contextual AI decisions verified. |
| M06 Network and web imports with truthful coverage | #45 → #38 → #39 → #44 → #46; tracker #7 | Three genuine supported imports or explicit pending-source gate; coverage honest. |
| M07 Correlation, uncertainty and risk | #48 → #56 → #57; tracker #9 | Duplicates preserve assets/evidence; uncertainty/rank explainable. |
| M08 Analyst assessment and review workspace | #54 → #58 → #62 → #66 → #74; tracker #10 | Fresh user completes scope/plan/import/review without hidden setup. |
| M09 Complete professional VAPT PDF | #63 → #68 → #69 → #67 → #75; tracker #11 | Complete sourced content; PDF opens, paginates and traces evidence. |
| M10 Mandatory prototype acceptance | #49 → #76 → #78 → #72; tracker #6 | All seven PDF judging checks pass together; #72 evidence attached. |
| M11 Release, demonstration and submission readiness | #79 → #80 → #83 → #85; tracker #12 | Secure release/setup/run documentation and truthful demo readiness. |
| M12 Future implementations — optional PDF extensions | #33 → #40 → #41 → #42 → #47 → #50 → #55 → #60 → #61 → #64 → #65 → #70 → #71 → #73 → #77 → #81 → #82 → #84; tracker #13 | Not required for current release; no dependency from core. |

First coding sequence from the current baseline: #51 → #53 → #52 → #59, while the integration owner resolves #17/#19 and verifies #38/#39. Then #48 → #56 → #57; UI #54 → #58/#62/#66 → #74; reporting #63 → #68/#69 → #67 → #75; acceptance #49/#76 → #78 → #72. Only start a task when its contract dependencies are stable. If a dependency already exists on main, inspect and use it rather than reopening it.

### Every task: state, dependency, reason and exact next action

### M01 — Scope, requirements and evidence inputs

**[#14 [T01] Build the source-linked requirements and judging coverage register](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/14) — CLOSED**

Prerequisites: none. Already closed with implementation history. Preserve closure; verify regressions in final acceptance rather than rebuilding it.

Next action: preserve merged implementation and include it in regression/acceptance testing. No new implementation is assigned.

**[#15 [T02] Approve technical architecture, trust boundaries and architecture decisions](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/15) — CLOSED**

Prerequisites: #14. Already closed with implementation history. Preserve closure; verify regressions in final acceptance rather than rebuilding it.

Next action: preserve merged implementation and include it in regression/acceptance testing. No new implementation is assigned.

**[#16 [T03] Scaffold reproducible development, dependency locks and CI foundations](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/16) — CLOSED**

Prerequisites: #15. Already closed with implementation history. Preserve closure; verify regressions in final acceptance rather than rebuilding it.

Next action: preserve merged implementation and include it in regression/acceptance testing. No new implementation is assigned.

**[#18 [T06] Document tool editions, licenses, resources and model-data assumptions](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/18) — CLOSED**

Prerequisites: #14. Already closed with implementation history. Preserve closure; verify regressions in final acceptance rather than rebuilding it.

Next action: preserve merged implementation and include it in regression/acceptance testing. No new implementation is assigned.

**[#17 [T04] Create the organizer-authorized lab and enforce its provisioning contract](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/17) — OPEN**

Prerequisites: #15, #18. Authority/lab input unavailable. Build runtime scope intake; do not contact organizers or scan public targets. Offline work proceeds. Official organizer-lab acceptance remains unproven.

Current scope: user-supplied runtime target/scope/permission contract and import-only demonstration configuration. Do not provision or test public targets. Preserve the PDF organizer-lab restriction as an unresolved event acceptance constraint.

**[#19 [T05] Build genuine scanner fixtures and an independently labelled benchmark corpus](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/19) — OPEN**

Prerequisites: #17. No genuine three-tool corpus supplied. Separate a minimal provenance-reviewed demo set from the future independent calibration benchmark; friend can independently label permitted samples later.

Current scope: minimal genuine permitted Nmap/ZAP/Nikto source set, hashes, versions, timestamps, provenance and reviewer labels sufficient for the demo. Large held-out calibration corpus is future work.

### M02 — Evidence platform and API contracts

**[#20 [T07] Implement the canonical asset, observation, finding and occurrence schema](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/20) — CLOSED**

Prerequisites: #15. Already closed with implementation history. Preserve closure; verify regressions in final acceptance rather than rebuilding it.

Next action: preserve merged implementation and include it in regression/acceptance testing. No new implementation is assigned.

**[#21 [T08] Build private, integrity-checked evidence storage and redaction](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/21) — CLOSED**

Prerequisites: #20. Already closed with implementation history. Preserve closure; verify regressions in final acceptance rather than rebuilding it.

Next action: preserve merged implementation and include it in regression/acceptance testing. No new implementation is assigned.

**[#22 [T09] Implement attributable audit events and tamper-evident decision history](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/22) — CLOSED**

Prerequisites: #20. Already closed with implementation history. Preserve closure; verify regressions in final acceptance rather than rebuilding it.

Next action: preserve merged implementation and include it in regression/acceptance testing. No new implementation is assigned.

**[#23 [T11] Harden result ingestion against malformed and hostile files](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/23) — CLOSED**

Prerequisites: #21. Already closed with implementation history. Preserve closure; verify regressions in final acceptance rather than rebuilding it.

Next action: preserve merged implementation and include it in regression/acceptance testing. No new implementation is assigned.

**[#24 [T10] Publish authenticated API contracts, idempotency rules and event schemas](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/24) — CLOSED**

Prerequisites: #20, #22. Already closed with implementation history. Preserve closure; verify regressions in final acceptance rather than rebuilding it.

Next action: preserve merged implementation and include it in regression/acceptance testing. No new implementation is assigned.

**[#25 [T12] Define the adapter capability contract and truthful status registry](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/25) — CLOSED**

Prerequisites: #18, #24. Already closed with implementation history. Preserve closure; verify regressions in final acceptance rather than rebuilding it.

Next action: preserve merged implementation and include it in regression/acceptance testing. No new implementation is assigned.

### M03 — Scope enforcement and human control

**[#26 [T13] Enforce versioned target scope and destination validation at dispatch](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/26) — CLOSED**

Prerequisites: #24. Already closed with implementation history. Preserve closure; verify regressions in final acceptance rather than rebuilding it.

Next action: preserve merged implementation and include it in regression/acceptance testing. No new implementation is assigned.

**[#27 [T15] Implement analyst identity, role authorization and secret handling](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/27) — CLOSED**

Prerequisites: #24. Already closed with implementation history. Preserve closure; verify regressions in final acceptance rather than rebuilding it.

Next action: preserve merged implementation and include it in regression/acceptance testing. No new implementation is assigned.

**[#29 [T16] Build explicit, single-use human approval for active validation](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/29) — CLOSED**

Prerequisites: #26, #27. Already closed with implementation history. Preserve closure; verify regressions in final acceptance rather than rebuilding it.

Next action: preserve merged implementation and include it in regression/acceptance testing. No new implementation is assigned.

**[#30 [T17] Implement emergency stop, revocation and safe validation boundaries](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/30) — CLOSED**

Prerequisites: #29. Already closed with implementation history. Preserve closure; verify regressions in final acceptance rather than rebuilding it.

Next action: preserve merged implementation and include it in regression/acceptance testing. No new implementation is assigned.

**[#31 [T18] Defend the planner and report pipeline from prompt injection and unsafe commands](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/31) — CLOSED**

Prerequisites: #23, #29. Already closed with implementation history. Preserve closure; verify regressions in final acceptance rather than rebuilding it.

Next action: preserve merged implementation and include it in regression/acceptance testing. No new implementation is assigned.

**[#28 [T14] Separate scanner networking from control plane and model egress](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/28) — OPEN**

Prerequisites: #26, #30. Isolated egress harness exists; deployed live scanner isolation is unverified. Only blocks enabling live scanners, not recorded imports.

Current scope: keep live execution disabled until deployed isolation is evidenced; prove recorded imports do not contact represented targets. Deployed scanner network remains a conditional live-mode gate.

### M04 — Jobs, recovery and network ingestion

**[#32 [T19] Build durable scan jobs, transactional dispatch and crash reconciliation](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/32) — CLOSED**

Prerequisites: #22, #26, #29. Already closed with implementation history. Preserve closure; verify regressions in final acceptance rather than rebuilding it.

Next action: preserve merged implementation and include it in regression/acceptance testing. No new implementation is assigned.

**[#43 [T21] Schedule bounded work with rate limits, deduplication and prioritization](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/43) — CLOSED**

Prerequisites: #32. Already closed with implementation history. Preserve closure; verify regressions in final acceptance rather than rebuilding it.

Next action: preserve merged implementation and include it in regression/acceptance testing. No new implementation is assigned.

**[#34 [T20] Implement genuine Nmap discovery, service parsing and evidence links](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/34) — CLOSED**

Prerequisites: #23, #25, #32. Already closed with implementation history. Preserve closure; verify regressions in final acceptance rather than rebuilding it.

Next action: preserve merged implementation and include it in regression/acceptance testing. No new implementation is assigned.

**[#35 [T22] Support recorded-output replay without misrepresenting live execution](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/35) — CLOSED**

Prerequisites: #34. Already closed with implementation history. Preserve closure; verify regressions in final acceptance rather than rebuilding it.

Next action: preserve merged implementation and include it in regression/acceptance testing. No new implementation is assigned.

**[#36 [T23] Version results, support partial completion and reconcile late outputs](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/36) — CLOSED**

Prerequisites: #35. Already closed with implementation history. Preserve closure; verify regressions in final acceptance rather than rebuilding it.

Next action: preserve merged implementation and include it in regression/acceptance testing. No new implementation is assigned.

**[#37 [T24] Instrument tool execution with trustworthy progress and actionable diagnostics](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/37) — CLOSED**

Prerequisites: #32, #36. Already closed with implementation history. Preserve closure; verify regressions in final acceptance rather than rebuilding it.

Next action: preserve merged implementation and include it in regression/acceptance testing. No new implementation is assigned.

### M05 — Conversational intake and grounded AI decisions

**[#51 [T37] Build conversational assessment intake and auditable structured plans](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/51) — OPEN**

Prerequisites: #24, #25, #26. Deterministic request-only intake is merged. This does not prove model-driven contextual reasoning; complete auditable conversational request/plan contract first.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#53 [T40] Ground AI claims, validate identifiers and enforce abstention](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/53) — OPEN**

Prerequisites: #21, #31, #51. Grounding helpers exist. Need actual planner/report integration, source citations, abstention and adversarial checks.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#52 [T38] Implement evidence-driven adaptive replanning and explainable next steps](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/52) — OPEN**

Prerequisites: #34, #51, #53. Real contextual model reasoning remains incomplete. Implement bounded evidence-grounded tool selection/next-step proposals; advanced durable multi-step memory is optional.

Current scope: bounded contextual reasoning over actual normalized evidence, tool capability availability, rationale and source references; explicit unknown/abstention and human approval. Durable autonomous multi-step memory is deferred.

**[#59 [T41] Make the planner budget-aware, failure-aware and efficient](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/59) — OPEN**

Prerequisites: #37, #52. Open acceptance work; run after the explicit prerequisites below. Existing code must be reviewed before adding duplicate implementation.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

### M06 — Network and web imports with truthful coverage

**[#45 [T28] Define reviewed scan-impact profiles and approval policy for web/network actions](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/45) — CLOSED**

Prerequisites: #29, #43. Already closed with implementation history. Preserve closure; verify regressions in final acceptance rather than rebuilding it.

Next action: preserve merged implementation and include it in regression/acceptance testing. No new implementation is assigned.

**[#38 [T25] Integrate OWASP ZAP with separate passive and approved active modes](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/38) — OPEN**

Prerequisites: #23, #25, #45. ZAP Alerts JSON import exists; original live/passive/active runner acceptance was broader than the minimum import prototype. Finish and demonstrate genuine import path now; live execution deferred.

Current scope: supported native recorded import, provenance, scope matching, normalization, safe parsing, failures, evidence trace and honest import-only coverage. Native live/API execution is deferred; no fabricated scan proof.

**[#39 [T26] Integrate Nikto and distinguish server observations from proven vulnerabilities](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/39) — OPEN**

Prerequisites: #23, #25, #45. Nikto JSON import exists; genuine source compatibility unverified. Native runner proof deferred; finish source-linked import acceptance now.

Current scope: supported native recorded import, provenance, scope matching, normalization, safe parsing, failures, evidence trace and honest import-only coverage. Native live/API execution is deferred; no fabricated scan proof.

**[#44 [T27] Handle authorized API definitions, authenticated sessions and endpoint coverage](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/44) — CLOSED**

Prerequisites: #24, #29, #45. Already closed with implementation history. Preserve closure; verify regressions in final acceptance rather than rebuilding it.

Next action: preserve merged implementation and include it in regression/acceptance testing. No new implementation is assigned.

**[#46 [T29] Build coverage and integration transparency views for all seven tools](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/46) — CLOSED**

Prerequisites: #34, #38, #39. Already closed with implementation history. Preserve closure; verify regressions in final acceptance rather than rebuilding it.

Next action: preserve merged implementation and include it in regression/acceptance testing. No new implementation is assigned.

### M07 — Correlation, uncertainty and risk

**[#48 [T43] Implement explainable cross-tool deduplication with preserved occurrences](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/48) — OPEN**

Prerequisites: #20, #34, #38, #39. Candidate correlation and reviewer merge/split code exists. Still verify exact asset/endpoint/parameter semantics and preserved occurrences end to end; independent calibration belongs to future work.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#56 [T44] Implement false-positive triage, contradictions and calibrated confidence](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/56) — OPEN**

Prerequisites: #48. Basic reviewer uncertainty/contradiction handling is core. Statistical confidence calibration is optional and excluded from current acceptance.

Current scope: suspected/confirmed/false-positive reviewer states, contradiction evidence, explicit unknown confidence, and preserved source references. Calibration/model training is deferred.

**[#57 [T45] Build transparent severity and contextual risk ranking with missing-data handling](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/57) — OPEN**

Prerequisites: #48, #56. Deterministic provenance-backed risk code exists. Additional reproducibility/monotonic/disputed-input checks are only local and unpublished.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

### M08 — Analyst assessment and review workspace

**[#54 [T49] Build conversational onboarding, scoped assessment setup and plan review UI](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/54) — OPEN**

Prerequisites: #27, #51. Scope/plan/import/review UI exists; fresh-user, stale revision and error walkthrough remain unproven.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#58 [T50] Build real-time assessment timeline, decisions and safe recovery controls](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/58) — OPEN**

Prerequisites: #37, #54. Open acceptance work; run after the explicit prerequisites below. Existing code must be reviewed before adding duplicate implementation.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#62 [T51] Build finding triage, confidence review and remediation workflow](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/62) — OPEN**

Prerequisites: #48, #56, #54. Open acceptance work; run after the explicit prerequisites below. Existing code must be reviewed before adding duplicate implementation.

Current scope: finding triage and confidence/contradiction review with analyst decisions and preserved evidence. Remediation task tracking and retesting are deferred; remediation recommendations in reports remain core.

**[#66 [T52] Build evidence inspector and action-bound approval review screens](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/66) — OPEN**

Prerequisites: #21, #29, #54. Open acceptance work; run after the explicit prerequisites below. Existing code must be reviewed before adding duplicate implementation.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#74 [T54] Verify usability, accessibility and executive/technical presentation modes](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/74) — OPEN**

Prerequisites: #58, #62, #66. Open acceptance work; run after the explicit prerequisites below. Existing code must be reviewed before adding duplicate implementation.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

### M09 — Complete professional VAPT PDF

**[#63 [T55] Build a versioned report snapshot and complete VAPT content contract](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/63) — OPEN**

Prerequisites: #36, #46, #48, #57. Versioned content model and frozen exports exist. Required descriptions, findings, impact and remediation must be populated from evidence/reviewer input, not only unknown placeholders.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#68 [T57] Write grounded executive summaries, impact and actionable remediation](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/68) — OPEN**

Prerequisites: #53, #63. Grounded executive, technical impact and actionable remediation are a substantive core gap. Unknown is honest for missing evidence but not a replacement for implementing report content.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#69 [T58] Map findings and methodology to all seven applicable reference frameworks](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/69) — OPEN**

Prerequisites: #18, #63. Open acceptance work; run after the explicit prerequisites below. Existing code must be reviewed before adding duplicate implementation.

Map only supported findings/methodology to applicable NIST SP 800-115, OWASP Top 10, CVE, CVSS, CWE, MITRE ATT&CK and NIST CSF 2.0 references. Explain not applicable/unknown; do not require all seven labels on every finding or claim certification.

**[#67 [T56] Generate a polished downloadable PDF with navigable evidence references](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/67) — OPEN**

Prerequisites: #63, #68, #69. PDF renderer is merged. Source-count fixes and internal evidence links are local/unpublished; source viewer trace and real report visual acceptance remain.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#75 [T60] Automate report completeness, consistency, confidentiality and visual QA](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/75) — OPEN**

Prerequisites: #67. Open acceptance work; run after the explicit prerequisites below. Existing code must be reviewed before adding duplicate implementation.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

### M10 — Mandatory prototype acceptance

**[#49 [T62] Run a negative safety and adversarial-input verification campaign](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/49) — OPEN**

Prerequisites: #31, #38, #39, #66. Open acceptance work; run after the explicit prerequisites below. Existing code must be reviewed before adding duplicate implementation.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#76 [T63] Verify crash recovery, timeouts, partial reports and graceful degradation](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/76) — OPEN**

Prerequisites: #36, #37, #46. Open acceptance work; run after the explicit prerequisites below. Existing code must be reviewed before adding duplicate implementation.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#78 [T61] Build full lifecycle acceptance tests aligned to all seven judging checks](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/78) — OPEN**

Prerequisites: #52, #57, #74, #75, #49, #76. Open acceptance work; run after the explicit prerequisites below. Existing code must be reviewed before adding duplicate implementation.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#72 [T30] Deliver the mandatory end-to-end prototype as a real acceptance gate](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/72) — OPEN**

Prerequisites: #19, #38, #39, #46, #51, #52, #48, #57, #54, #63, #67, #78. Prematurely attempted before intake/AI, correlation, UI and report gates. Now placed last in acceptance; only close after the entire seven-check journey and genuine sources.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

### M11 — Release, demonstration and submission readiness

**[#79 [T65] Add operational observability, health checks and evidence-safe diagnostics](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/79) — OPEN**

Prerequisites: #37, #76. Open acceptance work; run after the explicit prerequisites below. Existing code must be reviewed before adding duplicate implementation.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#80 [T66] Package secure deployment, backup/restore and release reproducibility](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/80) — OPEN**

Prerequisites: #21, #27, #79. Cloud integration/release owner lane only. Render is live, but database/privacy configuration and backup/restore proof still require verification.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#83 [T70] Create a truthful seven-check live demo and failure-recovery rehearsal](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/83) — OPEN**

Prerequisites: #72, #80. Open acceptance work; run after the explicit prerequisites below. Existing code must be reviewed before adding duplicate implementation.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#85 [T72] Run the final compliance review and request explicit commit approval](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/85) — OPEN**

Prerequisites: #83. Open acceptance work; run after the explicit prerequisites below. Existing code must be reviewed before adding duplicate implementation.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

### M12 — Future implementations — optional PDF extensions

**[#33 [T33] Implement Burp Suite export ingestion and analyst-assisted validation handoff](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/33) — OPEN**

Prerequisites: #25, #23. Deliberately deferred: optional extension or extra integration beyond the three-source minimum. Resume only after #72 and core release acceptance.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#40 [T31] Implement Nessus native import and edition-aware optional API execution](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/40) — OPEN**

Prerequisites: #25, #23. Deliberately deferred: optional extension or extra integration beyond the three-source minimum. Resume only after #72 and core release acceptance.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#41 [T32] Implement OpenVAS/Greenbone native import and verified GMP control](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/41) — OPEN**

Prerequisites: #25, #23. Deliberately deferred: optional extension or extra integration beyond the three-source minimum. Resume only after #72 and core release acceptance.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#42 [T34] Implement a separately isolated, human-approved Metasploit validation adapter](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/42) — OPEN**

Prerequisites: #28, #29, #30. Deliberately deferred: optional extension or extra integration beyond the three-source minimum. Resume only after #72 and core release acceptance.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#47 [T35] Verify all adapter formats, licensing disclosures and compatibility matrices](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/47) — OPEN**

Prerequisites: #33, #40, #41. Deliberately deferred: optional extension or extra integration beyond the three-source minimum. Resume only after #72 and core release acceptance.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#50 [T36] Exercise cross-tool network/web workflows with partial commercial availability](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/50) — OPEN**

Prerequisites: #47, #72. Deliberately deferred: optional extension or extra integration beyond the three-source minimum. Resume only after #72 and core release acceptance.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#55 [T39] Persist assessment memory, checkpoints and resumable review states](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/55) — OPEN**

Prerequisites: #52. Deliberately deferred: optional extension or extra integration beyond the three-source minimum. Resume only after #72 and core release acceptance.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#60 [T46] Enrich findings with vetted vulnerability intelligence and reference provenance](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/60) — OPEN**

Prerequisites: #57. Deliberately deferred: optional extension or extra integration beyond the three-source minimum. Resume only after #72 and core release acceptance.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#61 [T47] Build the evidence graph and contextual risk-path explanation](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/61) — OPEN**

Prerequisites: #48, #57. Deliberately deferred: optional extension or extra integration beyond the three-source minimum. Resume only after #72 and core release acceptance.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#64 [T42] Evaluate model/provider choices and record decision quality reproducibly](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/64) — OPEN**

Prerequisites: #52. Deliberately deferred: optional extension or extra integration beyond the three-source minimum. Resume only after #72 and core release acceptance.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#65 [T48] Evaluate correlation, ranking and uncertainty on held-out ground truth](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/65) — OPEN**

Prerequisites: #19, #48, #57. Deliberately deferred: optional extension or extra integration beyond the three-source minimum. Resume only after #72 and core release acceptance.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#70 [T59] Add structured JSON/CSV/SARIF exports and portable evidence manifests](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/70) — OPEN**

Prerequisites: #63. Deliberately deferred: optional extension or extra integration beyond the three-source minimum. Resume only after #72 and core release acceptance.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#71 [T68] Add counterfactual remediation analysis and decision replay explorer](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/71) — OPEN**

Prerequisites: #57, #67. Deliberately deferred: optional extension or extra integration beyond the three-source minimum. Resume only after #72 and core release acceptance.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#73 [T53] Add role-aware collaboration, review ownership and conflict handling](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/73) — OPEN**

Prerequisites: #27, #62. Deliberately deferred: optional extension or extra integration beyond the three-source minimum. Resume only after #72 and core release acceptance.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#77 [T64] Measure scaling, cost, latency and redundant-action reduction](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/77) — OPEN**

Prerequisites: #43, #59. Deliberately deferred: optional extension or extra integration beyond the three-source minimum. Resume only after #72 and core release acceptance.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#81 [T67] Add remediation retesting and evidence-backed before/after comparison](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/81) — OPEN**

Prerequisites: #67. Deliberately deferred: optional extension or extra integration beyond the three-source minimum. Resume only after #72 and core release acceptance.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#82 [T69] Publish a controlled baseline comparison and judging evidence dossier](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/82) — OPEN**

Prerequisites: #72, #65. Deliberately deferred: optional extension or extra integration beyond the three-source minimum. Resume only after #72 and core release acceptance.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

**[#84 [T71] Prepare and verify PPT, demonstration video and repository submission links](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/84) — OPEN**

Prerequisites: #83. PPT/video are not stated as mandatory deliverables in this PDF. Keep optional until a separately verified submission instruction requires them.

Implement the issue-specific PDF-relevant behavior. Inspect existing main first; retain source-linked acceptance criteria and replace broad bonus claims with the current prototype scope.

## 5. Two-developer allocation without account labels

No issues are assigned or labelled as friend/user. Choose work later. The following **22 coding-only candidates** can be taken from this document; each still obeys its prerequisites. These tasks use repository code, synthetic tests and pull requests. They do not require Render/Supabase access, deploying services, pasting production keys, obtaining scanner licenses, or configuring external providers.

[#51](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/51), [#53](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/53), [#52](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/52), [#59](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/59), [#48](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/48), [#56](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/56), [#57](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/57), [#54](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/54), [#58](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/58), [#62](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/62), [#66](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/66), [#74](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/74), [#63](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/63), [#68](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/68), [#69](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/69), [#67](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/67), [#75](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/75), [#49](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/49), [#76](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/76), [#78](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/78), [#83](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/83), [#85](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/85)

For #52/#53 implement provider interfaces, guarded prompt/output contracts and recorded test-provider cases; the integration owner injects a real provider credential and performs the real provider acceptance. Never close real-AI acceptance based only on a stub. For #83 deliver reproducible demo script/checklists; the integration owner runs the actual hosted demonstration. For #85 deliver the review and resolved code findings; submission/account actions stay with the integration owner.

Integration/account lane: #17/#19 evidence authority and files, #28 live runner networking if chosen, #38/#39 genuine scanner imports/runtime compatibility, #44 real API credentials if used, #79/#80 hosted diagnostics/release/backups, provider secret configuration and actual #72 demo. Existing closed implementation tasks are not a new workload allocation. Future integrations #33/#40/#41/#42 stay deferred.

Avoid shared-file collisions: complete intake contracts before its UI; complete correlation/risk JSON shape before report/UI consumers; freeze report content before PDF layout. Use one issue branch (`codex/t37-intake`, etc.), one owner per active issue, and one reviewed PR at a time per shared module. Claim ownership in an issue comment after the team selects tasks, not by changing this roadmap into permanent person-specific labels.

## 6. Setup and what to send privately

Send your friend **this document**, repository URL/access invitation, and the original `PS -1.pdf` privately. The PDF need not be committed unless redistribution is permitted. Fresh clone is the source of code; do not send the stale workspace, `.git`, virtual environments or node_modules. No cloud credentials are needed for the coding lane.

Commit-safe: application source, tests, synthetic fixtures clearly marked test-only, schema migrations after review, lockfiles, generated schemas/types, example environment with placeholders, architecture/setup docs and non-secret scripts. Keep docs with implementation PRs; this single planning document is a deliberate exception requested for the reset/handoff.

Never commit/send through public issues: `.env`, API keys, tokens, database passwords/URIs, EVIDENCE_KEY, APP_SECRET, BOOTSTRAP_TOKEN, cookies, production dumps, original private scanner evidence or private authorization letters. Share permitted genuine artifacts privately with their hashes/version/capture/provenance metadata. Each developer generates their own disposable test secrets. Production secrets stay with the integration owner in the cloud secret configuration.

Coding setup (local setup is optional for the user; the friend may use a development machine or cloud coding environment):

```powershell
git clone https://github.com/tanmayskotadia/ai_agent_penetration_testing.git
cd ai_agent_penetration_testing
git switch main
git pull --ff-only
# Install Python 3.12, uv, Node 24 and Git if the coding environment lacks them.
uv sync --frozen
cd frontend
npm ci --no-audit --no-fund
cd ..
git switch -c codex/issue-N-short-name
```

Use `.env.example` with disposable development values only. Read README before starting a server. `uv run pytest -m "not services"` uses disposable test data; service-marked tests need disposable PostgreSQL/Redis and belong in CI or an approved development environment. Do not use production Supabase as a test database. CI provides PostgreSQL/Redis/container checks; repository access is sufficient to open a PR and inspect them.

Required checks appropriate to the change: `uv run ruff check backend workers reports tests migrations scripts infra`; matching `ruff format --check`; `uv run mypy`; focused pytest cases; contract export `--check` scripts where schemas change; `npm run build` for frontend changes. Full end-to-end checks run after related integration changes, not in a loop after docs edits.

### Paste into the other Codex session

> Read docs/PROJECT-RESET-HANDOFF.md and issue #N on current main. Implement only the selected issue and its unresolved coding prerequisites. Inspect existing implementation first. Preserve PDF boundaries, supported import modes, evidence/source links and unknowns. Do not access Render/Supabase or production secrets, enable scanners, fabricate evidence, or modify another active issue’s files without coordination. Write meaningful regression tests for changed behavior, run the focused checks and required CI, update docs alongside code, push a scoped issue branch and PR under your own authorized GitHub identity. Report exactly what requires integration-owner input. Close only after issue-specific acceptance is proven; blocked cloud/source input is not an instruction to keep retrying. Do not use this repository’s historical tanmayskotadia author email for another human’s commits.

## 7. Work boundaries that prevent long loops

1. Start by stating 3–6 concrete acceptance checks and the input/output contract. If an issue is larger, use a checked subtask list inside the same issue rather than inventing another milestone.
2. Inspect main and existing tests once. Separate missing code, missing external input, and missing verification. Never rewrite a delivered component merely because its tracker is open.
3. Work in bounded sessions. If there is no new evidence after two attempts at the same failure, stop retrying and record root cause, exact next action and dependency. Do not claim a time guarantee; a session limit is a decision point, not permission to ship incomplete code.
4. Run focused tests during development; run broader checks after substantive integrated changes. A successful unchanged run is not new progress. Do not broaden scope to earn more test counts.
5. If blocked, add the precise blocker and named issue/input, then take the next dependency-ready task. No automatic repeated authentication requests, organizer questions, or synthetic-as-genuine substitution.
6. Ready for review means code + docs + tests + known limitations. Done means required hosted CI and acceptance evidence verified and merged. If external proof remains, keep the issue open with a narrow checklist. Do not close a tracker while its required tasks are open.

## 8. T30 final acceptance checklist

- One assessment has a permitted target/scope revision and conversational request; invalid/excluded targets are rejected.
- AI proposes a contextual, evidence-cited plan/next step; shows rationale and abstains when unsupported. Deterministic intake alone is not AI proof.
- Genuine Nmap/ZAP/Nikto inputs are imported with versions/timestamps/hashes/source review; live versus import status is accurate.
- Normalized findings retain source/asset/time/raw reference/confidence/status; duplicate review preserves distinct assets/occurrences.
- Ranking is explainable, severity/CVSS preserved, unsupported context unknown; reviewer decision/denial remains enforced.
- PDF contains executive scope, methodology/rules/assets/tool summary, distribution/priorities, complete detailed findings, impact/remediation/references and limitations/failures/approvals/timestamps. Trace a finding to its original source and inspect every page.
- Demonstrate a safe failed/unavailable import and honest partial coverage. Attach sanitized run IDs, hashes, CI revision and screen recording/checklist where permitted.
- Preserve unresolved official lab condition; do not claim that offline development evidence satisfies an absent organizer-authorized live target.

## 9. Milestone progress and historical records

GitHub calculates progress as closed attached issues divided by all attached issues; trackers count too. No editable percentage exists. Reorganization refreshes membership and names; inspect returned open/closed counts. M02 stays closed if all its tasks remain accepted. Future work is a separate open milestone and does not block core release. Do not reopen completed work to force a visual percentage. This roadmap preserves task IDs and history; updated issue scope/dependencies supersede older mixed core/bonus checklists.

This reset is planning and handoff only. It does not implement, deploy or close unverified acceptance work. Use issue status and exact main/PR state to track progress after this dated snapshot.

# Judging scorecard and live-demo acceptance

**Source:** supplied PDF section 11, page 9 (weights); section 10, page 8 (demo checks).
**Current status:** product not demonstrated; no achieved score is claimed. Completing T01 establishes the register, not the judged behavior.

## Published 100-point rubric

| ID | Criterion | Points | What must be proved | Principal implementation/evaluation issues | Evidence readiness |
|---|---|---:|---|---|---|
| J01 | End-to-End Coverage | 15 | Coherent reconnaissance-to-report workflow. | [T30](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/72), [T61](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/78) | Not demonstrated |
| J02 | AI Reasoning & Decisions | 20 | Adaptive planning, contextual next steps and rationale. | [T38](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/52), [T42](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/64), [T69](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/82) | Not demonstrated |
| J03 | Technical Accuracy | 15 | Correct interpretation, evidence and validation status. | [T35](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/47), [T40](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/53), [T48](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/65) | Not demonstrated |
| J04 | Correlation & False Positives | 15 | Deduplication, confidence and traceability. | [T43](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/48), [T44](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/56), [T48](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/65) | Not demonstrated |
| J05 | Risk Prioritization | 10 | Defensible severity, impact and exposure ranking. | [T45](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/57), [T48](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/65) | Not demonstrated |
| J06 | Safety & Scope Control | 10 | Lab-only scope, approval and audit trail. | [T16](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/29), [T62](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/49) | Not demonstrated |
| J07 | Report Quality | 10 | Professional clarity, evidence and remediation. | [T56](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/67), [T60](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/75) | Not demonstrated |
| J08 | Efficiency & Robustness | 5 | Avoidance of unnecessary actions and error recovery. | [T63](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/76), [T64](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/77) | Not demonstrated |
| | **Total** | **100** | Published allocation; not an achieved or predicted score | | |

## Evidence needed to assess each criterion

- **J01:** one coherent authorized conversation-to-report journey, including genuine network/web multi-tool results and source trace.
- **J02:** evidence-dependent branches, rationale and alternatives; a changed result changes the next useful permitted action; demonstrate stop/avoid-repeat behavior.
- **J03:** original tool artifacts, correct parsing, source-grounded identifiers and explicit suspected/confirmed state. Review inaccurate and unsupported cases.
- **J04:** true duplicate consolidation with source retention, distinct affected occurrences, contradiction/false-positive review and independent labelled accuracy data.
- **J05:** supported severity/CVSS, exposure, exploitability, asset impact and confidence; reproducible contextual priorities with missing information visible.
- **J06:** actual organizer lab manifest, forbidden-target non-dispatch, approval denial/expiry enforcement and attributable decision/action outcomes.
- **J07:** complete readable PDF, accurate executive/technical narrative, actionable remediation, limitations and original-evidence trace; visual page review.
- **J08:** avoided redundant actions, bounded work and safe failure recovery; publish measured time/cost/workload when claiming efficiency.

No numerical achieved score is assigned by the register. Any later self-assessment must name the reviewed evidence, reviewer, method and limitations; it is not a promised judge result.

## Seven source-backed live-demo checks

| Check | Source requirement | Required proof | Planned verification | Readiness |
|---|---|---|---|---|
| D01 | DEMO-01: D01: Enter an authorized target and conversation, and demonstrate scope validation. | Authorized intake plus excluded-target rejection with no dispatch. | [T61](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/78), [T70](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/83) | Not demonstrated |
| D02 | DEMO-02: D02: Show generated plan with clear tool choices and reasoning. | Evidence-linked plan and adaptive next-step decision. | [T61](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/78), [T70](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/83) | Not demonstrated |
| D03 | DEMO-03: D03: Execute/import multiple tools with genuine execution status and traceable outputs. | Original-source run/import records and truthful mode labels. | [T61](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/78), [T70](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/83) | Not demonstrated |
| D04 | DEMO-04: D04: Demonstrate normalization, correlation, duplicate/false-positive handling and uncertainty. | True duplicate, distinct occurrences and uncertain/reviewed finding. | [T48](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/65), [T61](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/78), [T70](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/83) | Not demonstrated |
| D05 | DEMO-05: D05: Show severity/risk prioritization and explicit approval before active validation. | Risk factor explanation and approval enforcement trace. | [T61](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/78), [T62](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/49), [T70](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/83) | Not demonstrated |
| D06 | DEMO-06: D06: Download/inspect final report and trace a finding to its original evidence. | Downloaded PDF, finding ID, raw source pointer and integrity record. | [T60](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/75), [T61](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/78), [T70](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/83) | Not demonstrated |
| D07 | DEMO-07: D07: Show safe failures and honestly identify unsupported integrations. | Real partial/failed run, documented coverage impact and no invented success. | [T61](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/78), [T63](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/76), [T70](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/83) | Not demonstrated |

## Minimum working-prototype gate

The minimum gate is [T30](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/72). It needs all of the following together:

- Conversational request, validated scope and auditable justified plan.
- At least three working integrations or supported native imports, with both network and web coverage.
- Common finding schema, original evidence links, true duplicate handling and risk ranking.
- Analyst approval gate and a complete professional downloadable PDF.
- Truthful seven-tool status, licensing/unsupported disclosures and organizer-authorized demonstration.

Bonus features are evaluated separately and cannot waive any minimum capability. Milestone numbering groups work; pull required reasoning, correlation, UI and report dependencies forward for this vertical slice.

## Review protocol

1. Follow each matrix requirement to its implementation issue and planned verification issue.
2. Inspect actual tool/import manifests, source evidence, audit records and report snapshot rather than accepting narrative claims.
3. Confirm actual evidence is linked before marking the corresponding product requirement verified.
4. Reproduce the seven-check journey, including rejected scope, uncertainty and safe failures.
5. Evaluate advanced capability and baseline improvements only with genuine reproducible data.
6. Keep unresolved limitations visible in the report, demo and [submission gates](submission-gates.md).

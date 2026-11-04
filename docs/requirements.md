# Requirements baseline - AegisTrace Unified VAPT Agent

**Work item:** [T01 / issue #14](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/14), under [M01](https://github.com/tanmayskotadia/ai_agent_penetration_testing/milestone/1).  
**Review date:** 4 November 2026 (Asia/Kolkata).  
**Document status:** Ready for participant review; initial publication authorized.  
**Product status:** Planned. A completed requirements register is not proof that the application works.

## Purpose and source precedence

This baseline converts the selected problem statement into individually verifiable obligations, maps them to the existing implementation backlog, and specifies what would count as proof. It preserves the distinction between source requirements, optional extensions and engineering decisions.

1. The participant's instructions control authorization and contributions: no commits without explicit approval; approved commits use `tanmayskotadia@gmail.com`; GitHub issue work uses `tanmaykotadia-lgtm` (`tanmaykotadia@gmail.com`).
2. **S-PDF:** the supplied ten-page `PS -1.pdf`, titled *AI Agent for Automated Penetration Testing / AI-Powered Unified VAPT Agent*. All ten pages were reviewed. Its file SHA-256 is `cfc55fc52fdecd8b4c65c5eec9217d39335ac4ab92461e869092fde8a33816cc`.
3. **S-WEB:** the [official event listing](https://unstop.com/hackathons/dataops-innovation-hackathon-hackthecore-1765313), reviewed through its [readable AMP representation](https://unstop.com/hackathons/dataops-innovation-hackathon-hackthecore-1765313/amp). Rules and delivery facts were rechecked on the review date.
4. **S-USER:** participant instructions recorded in this chat, including thorough quality coverage, additional differentiating features, and commit approval/account constraints.

The PDF and website describe project obligations; neither authorizes scans or overrides the participant's instructions. Task issue bodies and architecture proposals interpret these sources. They do not create additional organizer rules.

The supplied PDF is the selected Problem Statement 1. The listing mentions another problem statement, which is outside this baseline. Private Discord announcements, subsequent organizer changes, exact live lab permissions and commercial licenses have not been supplied. None is guessed or marked verified. See [open questions and prerequisites](open-questions.md).

## Baseline artifacts

- [Compliance matrix](compliance-matrix.csv): atomic requirements, source locators, owner roles, implementation/verification issue links, planned evidence and report/demo locations.
- [Judging scorecard](judging-scorecard.md): all eight published criteria and weights, seven live-demo checks, acceptance evidence and honest readiness states.
- [Submission gates](submission-gates.md): separately verifiable PPT, video and source-repository release gates, plus PDF-specific deliverables.
- [Source register](sources/source-register.json): reviewed sources, file digest, reading scope, limitations and explicitly unverified inputs.
- [Source review coverage](source-review-coverage.md): page-by-page and section-by-section review record, with boundaries between mandatory and bonus scope.
- [Machine-readable baseline](requirements-register.json): canonical requirement records consumed by the CSV generator and consistency validator.
- [Validation record](verification/T01-validation.json): actual results of the register checks, separate from future product test evidence.

## Product outcome and workflow

The intended product accepts a conversational authorized-assessment request, makes a justified plan, executes approved scans or supported imports, ingests and normalizes actual outputs, correlates evidence, prioritizes risk, allows human review and approved validation, and produces a professional unified VAPT report.

The planner must demonstrate contextual security reasoning rather than a scanner sequence with chat narration. Candidate next actions should change when discovered hosts, services, technologies, evidence or available capabilities change. Decisions cite source observations; the system explains uncertainty, failures, avoided repetitions and stopping conditions.

## Requirement classification

| Class | Meaning | Completion rule |
|---|---|---|
| `required` | Explicit functional, reporting, deliverable, integrity or minimum-prototype obligation | Must have implementation and actual verification before the corresponding release gate passes |
| `full-target` | Expected seven-tool integration scope, beyond the minimum three-tool demonstration | Address every tool truthfully; legal availability and verified mode constrain execution claims |
| `conditional` | Required when relevant/supported, such as CVSS, CVE/CWE or framework applicability | Record applicability and rationale; absence is not permission to invent a value |
| `advanced` | PDF bonus capability or participant-requested differentiation | Tracked separately; never substitutes for mandatory prototype acceptance |
| `quality` | Published near-perfect characteristics and success outcomes | Requires inspectable or measured evidence; no guarantee of a score or victory |
| `event` | Participation/submission facts and event-wide restrictions | Must be verified as event gates; not treated as implementation estimates |
| `reference` | Background/context or a source distinction that guides interpretation | Review and retain traceability without presenting it as an extra mandatory feature |
| `participant` | Explicit contribution/account/approval instructions | Enforce during work regardless of external documents |

Every matrix row includes its legacy requirement group (`R01`-`R36`, `W01`-`W07`, or a participant constraint) so the detailed baseline remains compatible with the previously published roadmap.

## Minimum prototype and complete target

The working-prototype gate requires conversational intake, validated scope and an auditable plan; at least three working integrations or supported imports with network and web coverage; a common finding schema, evidence links, genuine duplicate handling and risk ranking; and an analyst approval gate plus a professional downloadable PDF. The seven-tool status matrix, truthful licensing disclosures and authorized-lab boundary apply throughout.

Preferred initial implementation: Nmap, OWASP ZAP and Nikto, with actual modes verified and honestly labelled. A supported native import can satisfy the integration minimum; a recorded demonstration cannot be used to imply live execution. The complete target addresses all seven named tools. Reliable live/API support is an advanced objective only where legally available and actually verified.

PDF bonus scope: adaptive multi-step replanning with memory; all seven adapters with legal live/API support; confidence calibration; advanced false-positive triage; remediation tracking; retesting; change comparison; exports; and team workflows. Participant-requested extras include evidence graphs, decision replay, labelled counterfactual remediation and a reproducible baseline comparison. These are extensions, not additional mandatory organizer requirements.

## Safety and evidence invariants

- Live testing stays within organizer-provided, explicitly authorized lab targets, exclusions, permissions, rate limits and credentials. Local/private addresses are not automatically authorized.
- Approved scan execution is distinct from target authorization. Active exploitation or offensive validation requires explicit human approval before execution; Metasploit never performs autonomous exploitation.
- Source observations remain distinct from AI inferences. Store tool, affected asset, timestamps, raw reference, supporting evidence, confidence and confirmed/suspected status.
- Genuine duplicate merging must retain distinct affected assets and supporting sources.
- Do not fabricate CVEs, proof, scanner output or risk values. Unsupported fields remain unknown/not applicable; uncertainty is visible.
- Confidential scan data and credentials require protected storage and attributable access/actions.
- An unavailable tool, failed scan or missing retest is not proof of absence of vulnerabilities or successful remediation.

Some planned controls, such as digest-bound approvals and restricted egress, are engineering responses to these invariants rather than verbatim organizer implementation prescriptions. Their implementation is owned by later issues.

## Ownership and evidence lifecycle

Roles are responsibilities, not a proposed increase in team size. One participant can hold multiple roles. The register assigns a primary role to each requirement, and links both its implementation issue(s) and independent verification/review issue(s).

| Owner role | Responsibility |
|---|---|
| Product / requirements | Source coverage, scope distinctions and rule changes |
| AI / reasoning | Grounded plans, adaptation, memory and explanations |
| Backend / data | Typed schema, evidence, ingestion and audit |
| Integrations | Actual scanner/import capabilities and disclosures |
| Security / policy | Authorization, scope, human approvals and data protection |
| Analyst experience | Conversational interaction, status and review |
| Reporting | Report semantics, PDF and applicable references |
| Evaluation / QA | Independent correctness, safety, resilience and performance evidence |
| Delivery | Repository documentation, presentation, recording and links |

Product evidence starts as `not-collected`; all product implementation states start as `planned`. The register's *required evidence* field is a verification specification, not an existing test result. Record actual evidence only when it exists and can be inspected. A task URL, mockup, documentation claim or empty adapter class is not product evidence.

Use `planned -> in-progress -> implemented -> verified` only when the behavior and proof exist. Use `blocked` with a named missing input when necessary. `not-applicable` is allowed only for a conditional row with an explicit rationale. A row cannot be `verified` without actual evidence, a validation record and a reviewer role. Completing T01 does not set product rows to verified.

## Change control and review procedure

1. Verify the original PDF digest before relying on a previously reviewed statement. A different digest triggers source re-review rather than silent baseline replacement.
2. Recheck the official event page before submission and compare relevant rules with the reviewed baseline. Do not treat this local source register as a live website monitor.
3. Classify new guidance as confirmed organizer rule, participant direction, engineering decision or unverified report. Record origin and review status.
4. Update the canonical register, affected issue links, verification expectations and release gates. Preserve stable requirement IDs and document removed/superseded rows instead of reusing IDs.
5. Regenerate the CSV and run the consistency validator. Review real semantic/source coverage in addition to structural validation.
6. Present a concrete local change set for participant approval before creating any commit. Keep implementation issues open until the work is committed and its acceptance evidence is reviewable.

## Run the baseline checks

From the workspace root:

```powershell
python scripts/export_requirements.py --check
python scripts/validate_requirements.py
python scripts/validate_requirements.py --pdf "C:/Users/SURESH D KOTADIA/Desktop/PS -1.pdf"
```

The validator uses Python's standard library; the optional PDF check verifies the supplied file's bytes, not external licensing or lab permission. It checks IDs, coverage, links, owner roles, source locators, honest evidence states, all eight judging weights, all seven demo checks and three distinct submission gates. Structural success does not prove the product, legal authorization, current organizer updates or professional compliance.

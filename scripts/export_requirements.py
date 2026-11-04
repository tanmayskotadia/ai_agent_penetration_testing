"""Export the canonical T01 register to a reviewable CSV (standard library)."""
from pathlib import Path
import argparse
import csv
import io
import json

ROOT=Path(__file__).resolve().parents[1]
FIELDS=['Requirement ID','Legacy groups','Class','Source','Source section/page','Source anchor','Obligation','Owner role','Implementation issues','Verification issues','Required evidence','Actual evidence','Evidence status','Implementation status','Judging criteria','Demo checks','Report/demo/delivery location','Applicability rationale']

def render(register):
    stream=io.StringIO(newline='')
    writer=csv.DictWriter(stream,fieldnames=FIELDS,lineterminator='\n')
    writer.writeheader()
    tasks=register['tasks']
    for r in register['requirements']:
        def links(ids): return '; '.join(f'{i}: {tasks[i]["url"]}' for i in ids)
        row=dict(zip(FIELDS,[r['id'],', '.join(r['legacy_groups']),r['classification'],r['source_id'],r['source_locator'],r['source_anchor'],r['requirement'],r['owner_role'],links(r['implementation_tasks']),links(r['verification_tasks']),r['required_evidence'],'; '.join(r['actual_evidence']),r['evidence_status'],r['implementation_status'],', '.join(r['judging_criteria']),', '.join(r['demo_checks']),r['report_or_delivery_location'],r['applicability_rationale'] or '']))
        for k,v in row.items():
            if str(v).startswith(('=','+','-','@','\t','\r')): row[k]="'"+str(v)
        writer.writerow(row)
    return stream.getvalue()

def render_scorecard(register):
    def task_link(task): return f'[{task}]({register["tasks"][task]["url"]})'
    lines=['# Judging scorecard and live-demo acceptance','',
      '**Source:** supplied PDF section 11, page 9 (weights); section 10, page 8 (demo checks).',
      '**Current status:** product not demonstrated; no achieved score is claimed. Completing T01 establishes the register, not the judged behavior.','',
      '## Published 100-point rubric','',
      '| ID | Criterion | Points | What must be proved | Principal implementation/evaluation issues | Evidence readiness |',
      '|---|---|---:|---|---|---|']
    for c in register['judging_criteria']:
        lines.append(f'| {c["id"]} | {c["name"]} | {c["points"]} | {c["description"]} | {", ".join(task_link(t) for t in c["tasks"])} | Not demonstrated |')
    lines += ['| | **Total** | **100** | Published allocation; not an achieved or predicted score | | |','',
      '## Evidence needed to assess each criterion','',
      '- **J01:** one coherent authorized conversation-to-report journey, including genuine network/web multi-tool results and source trace.',
      '- **J02:** evidence-dependent branches, rationale and alternatives; a changed result changes the next useful permitted action; demonstrate stop/avoid-repeat behavior.',
      '- **J03:** original tool artifacts, correct parsing, source-grounded identifiers and explicit suspected/confirmed state. Review inaccurate and unsupported cases.',
      '- **J04:** true duplicate consolidation with source retention, distinct affected occurrences, contradiction/false-positive review and independent labelled accuracy data.',
      '- **J05:** supported severity/CVSS, exposure, exploitability, asset impact and confidence; reproducible contextual priorities with missing information visible.',
      '- **J06:** actual organizer lab manifest, forbidden-target non-dispatch, approval denial/expiry enforcement and attributable decision/action outcomes.',
      '- **J07:** complete readable PDF, accurate executive/technical narrative, actionable remediation, limitations and original-evidence trace; visual page review.',
      '- **J08:** avoided redundant actions, bounded work and safe failure recovery; publish measured time/cost/workload when claiming efficiency.',
      '', 'No numerical achieved score is assigned by the register. Any later self-assessment must name the reviewed evidence, reviewer, method and limitations; it is not a promised judge result.','',
      '## Seven source-backed live-demo checks','',
      '| Check | Source requirement | Required proof | Planned verification | Readiness |',
      '|---|---|---|---|---|']
    requirements={r['id']:r for r in register['requirements']}
    for d in register['demo_checks']:
        r=requirements[d['requirement_id']]
        lines.append(f'| {d["id"]} | {r["id"]}: {r["requirement"]} | {r["required_evidence"]} | {", ".join(task_link(t) for t in r["verification_tasks"])} | Not demonstrated |')
    lines += ['','## Minimum working-prototype gate','',
      'The minimum gate is '+task_link('T30')+'. It needs all of the following together:',
      '', '- Conversational request, validated scope and auditable justified plan.',
      '- At least three working integrations or supported native imports, with both network and web coverage.',
      '- Common finding schema, original evidence links, true duplicate handling and risk ranking.',
      '- Analyst approval gate and a complete professional downloadable PDF.',
      '- Truthful seven-tool status, licensing/unsupported disclosures and organizer-authorized demonstration.',
      '', 'Bonus features are evaluated separately and cannot waive any minimum capability. Milestone numbering groups work; pull required reasoning, correlation, UI and report dependencies forward for this vertical slice.',
      '', '## Review protocol','',
      '1. Follow each matrix requirement to its implementation issue and planned verification issue.',
      '2. Inspect actual tool/import manifests, source evidence, audit records and report snapshot rather than accepting narrative claims.',
      '3. Confirm actual evidence is linked before marking the corresponding product requirement verified.',
      '4. Reproduce the seven-check journey, including rejected scope, uncertainty and safe failures.',
      '5. Evaluate advanced capability and baseline improvements only with genuine reproducible data.',
      '6. Keep unresolved limitations visible in the report, demo and [submission gates](submission-gates.md).','']
    return '\n'.join(lines)

def render_submission_gates(register):
    tasks=register['tasks']
    lines=['# Submission and deliverable release gates','',
      '**Sources:** official Unstop submission guidelines; supplied PDF sections 9-10, pages 7-8.',
      '**Current release readiness:** not ready. No final PPT/video/source-content/access proof has been collected. The existence of a repository or a planned issue is insufficient.','',
      '## Three independently required event artifacts','',
      '| Gate | Artifact and source row | What must be checked | Owner / verification | Status |',
      '|---|---|---|---|---|',
      f'| SUB-PPT | Google Drive PPT; WEB-01 | Final presentation exists; correct share URL; anyone-with-link viewing enabled as required; claims match actual capabilities | [T71]({tasks["T71"]["url"]}) / [T72]({tasks["T72"]["url"]}) | Not prepared |',
      f'| SUB-VIDEO | Google Drive demo video; WEB-02 | Actual functionality/implementation shown; correct link; required viewing access verified; live/import/replay distinguished | [T71]({tasks["T71"]["url"]}) / [T72]({tasks["T72"]["url"]}) | Not prepared |',
      f'| SUB-REPO | GitHub source and README; WEB-03 | Actual code/relevant files, features/setup/execution README, dependencies/licenses, fresh setup and link checked | [T71]({tasks["T71"]["url"]}) / [T66]({tasks["T66"]["url"]}) | Source-content gate not verified |',
      '', 'All three must pass; a missing artifact blocks submission readiness. The actual event listing says missing any of them prevents further evaluation. This register does not upload files, change sharing, submit to Unstop or approve commits.',
      '', '## Additional PDF-required deliverables','',
      '| Deliverable | Source / register | Required evidence |',
      '|---|---|---|',
      '| Working prototype | 9.1; DEL-01 | Functional organizer-authorized sample-lab demonstration and minimum acceptance record |',
      '| Architecture overview | 9.2; DEL-02, ARCH-01 through ARCH-06 | Models, orchestration, adapters, data flow, state/memory and security boundaries |',
      '| Sample evidence-backed VAPT PDF | 9.3; DEL-03 | Required content, readable pages, actual evidence trace and limitations |',
      '| Repository documentation | 9.4; DEL-04, REPO-01 through REPO-04 | Setup, dependencies, licensing assumptions and execution verified from clean environment |',
      '| Human-approval demonstration and audit | 9.5; DEL-05 | Explicit human control before active validation; recorded decisions and outcomes |',
      '| Integration status matrix | 9.6; DEL-06, MODE-04 through MODE-08 | Seven truthful statuses plus known limitations, assumptions and unsupported scenarios |',
      '', '## Honest readiness transitions','',
      'Use not-prepared -> prepared -> access/content-reviewed -> verified. Store actual artifact URL, review method, reviewer role/date and evidence before changing a gate to verified. A repository URL alone does not prove source/setup completeness. A local slide outline does not prove a viewable PPT link. A recording script does not prove a video artifact.',
      '', 'Verify viewing access in an unauthenticated/private session at delivery time, without publishing private evidence or credentials. Preserve clear live/import/recorded labels and disclose unsupported licensed tools.',
      '', '## Event facts kept separate from engineering estimates','',
      '- Published team limit: 1-4 members.',
      '- Registration: 1 November 2026 at 23:59 IST.',
      '- Published event start: 2 November 2026 at 14:00 IST; end: 7 November 2026 at 23:59 IST.',
      '- Virtual coordination: Discord; applicable private updates remain unverified until reviewed.',
      '', 'Recheck the [official event page](https://unstop.com/hackathons/dataops-innovation-hackathon-hackthecore-1765313/amp) for changes before delivery. These facts do not impose invented per-task due dates and are not waived by a quality-first engineering preference.',
      '', '## Final contribution gate','',
      'The participant must approve a concrete change set before any commit. Approved commits use `tanmayskotadia@gmail.com`; issue operations use `tanmaykotadia-lgtm`. This register does not authorize payment, public deployment, external scans or automatic event submission.','']
    return '\n'.join(lines)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true',help='Fail if committed/reviewed CSV differs from canonical data; do not rewrite.')
    args=parser.parse_args()
    register=json.loads((ROOT/'docs/requirements-register.json').read_text(encoding='utf-8'))
    outputs=[(ROOT/'docs/compliance-matrix.csv',render(register),'utf-8-sig'),(ROOT/'docs/judging-scorecard.md',render_scorecard(register),'utf-8'),(ROOT/'docs/submission-gates.md',render_submission_gates(register),'utf-8')]
    for target,expected,encoding in outputs:
        if args.check:
            if not target.exists() or target.read_text(encoding=encoding)!=expected:
                raise SystemExit(f'FAIL: {target.relative_to(ROOT)} is missing or stale; run python scripts/export_requirements.py')
        else:target.write_text(expected,encoding=encoding,newline='')
    print(f'{"PASS: checked" if args.check else "Exported"} CSV, judging scorecard and submission gates for {len(register["requirements"])} requirements.')

if __name__=='__main__': main()

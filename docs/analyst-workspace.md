# Guided analyst workspace

The authenticated analyst workspace is organized into four stages that can be revisited without discarding the currently mounted forms:

1. **Scope & plan** — review exact scope, recorded-evidence plan, and evidence-driven recommendation.
2. **Evidence** — import an existing permitted report, read its normalized/quarantined result, review source provenance, and inspect the audit timeline.
3. **Findings & review** — inspect action-bound approvals, record analyst context, review duplicate suggestions, and write evidence-linked findings.
4. **Report** — choose executive or analyst presentation, inspect coverage and unknowns, and freeze a point-in-time PDF.

The assessment selector and recorded-evidence mode remain visible. Analysts can create another assessment from the workspace. Stage tabs show simple progress text, and each stage presents a suggested next safe action. Tool status and detailed processing JSON are expandable. Changing stages preserves form state; changing assessments reloads assessment-specific data. The audit timeline can be opened from any stage.

## Automated UI walkthrough

From `frontend/`:

```powershell
npm run build
npm run check:workspace
npm run check:replan
```

`check:workspace` uses synthetic API fixtures and verifies sign-in, stage navigation, preserved assessment/request/scope state, audit visibility, desktop and narrow layouts, report-stage navigation, and that navigation submits no scan or approval action. It does not claim a fresh human reviewer completed the end-to-end workflow.

## Safe screenshots

The screenshots below use a mocked, synthetic assessment and contain no credentials, private hostnames, or scanner results. They demonstrate layout only; they are not evidence that an assessment, import, finding review, or report export has succeeded.

![Synthetic desktop workspace walkthrough](images/issue-107/workspace-desktop.png)

![Synthetic narrow-screen workspace walkthrough](images/issue-107/workspace-mobile.png)

## Manual acceptance still required

A fresh reviewer should use a permitted assessment and complete the path without developer instructions: select an assessment, set scope, inspect a plan, import a permitted recorded report, review its source, trace a finding to evidence, and export a PDF. They should repeat stage navigation using only the keyboard and inspect the page at a narrow mobile width. Record their role (analyst or nontechnical reader), pass/fail for each step, confusing labels or blockers, and any follow-up fixes. Do not include credentials, private targets, original scanner output, or personal data in screenshots or notes.

Do not mark the UI issue accepted based only on synthetic screenshots or automated browser tests. Existing server-side authorization, provenance, approval, redaction, stale-state and audit controls remain authoritative; the UI must not imply otherwise.

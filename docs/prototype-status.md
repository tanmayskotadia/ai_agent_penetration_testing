# T30 prototype status

**Status: implementation in progress; acceptance not demonstrated.** This file records workspace evidence and must not be read as a claim that the hackathon's minimum prototype gate has passed.

## Codex-owned implementation present in the workspace

- Scope-bound, deterministic conversational intake persists request-only plans and blocks excluded targets and active validation requests.
- Offline, source-linked intake supports Nmap XML, ZAP Alerts JSON, Nikto JSON, and OpenAPI definitions. Originals are encrypted and hashed; imports do not contact target systems.
- Source review is digest-bound and append-only. Synthetic or replay inputs can be labelled test-only and cannot be counted as genuine evidence.
- Nikto explicitly reported CVE/CWE references are mapped only when unambiguous. They remain source-reported references; multiple references are preserved without selecting a correlation key. Severity and confirmation are not inferred.
- Cross-tool observations remain candidates until reviewer action. Reviewer context and decisions are preserved in immutable result exports and a PDF renderer.
- A disabled-by-default ZAP/Nikto worker candidate uses pinned binaries, action-bound approval, bounded jobs, encrypted artifacts, and a per-job proxy. It is not safe to enable without a separately deployed scanner network that denies direct egress. It does not configure authenticated target sessions or independently verify licenses/add-ons.
- The API-check path records protected operation attempts and keeps credential values out of result summaries. Successful HTTP status does not independently prove the authenticated identity.

## Verification performed in the workspace

- The complete non-service suite passed: **241 passed, 6 skipped, 18 deselected**. The skipped cases require external services; deselected cases are service-marked. This includes the single-assessment T30 test-only vertical slice. Fixtures are synthetic/test-only.
- Ruff lint passed and formatting passed after the readiness/access fixes. Strict mypy passed for 81 backend source files in this verification run.
- Generated API/domain/capability/profile checks passed; frontend TypeScript and production build passed.
- The single-assessment T30 test-only journey at `tests/e2e/minimum-prototype/test_minimum_prototype.py` passed as part of the full suite on this Windows host when run with the loopback access required by Starlette `TestClient`. Hosted CI must still execute it on the published implementation revision.
- The journey includes a corrupted Nmap replay and asserts that it is quarantined, remains unverified, and cannot be mistaken for clean coverage.
- A parser smoke check confirmed the T30 synthetic Nmap, ZAP, Nikto, and OpenAPI documents normalize under their supported parser contracts. This is not a scanner integration test or a genuine-data check.

## Evidence and deployment still required

- No genuine permitted Nmap, ZAP, or Nikto capture has been supplied and reviewed. The three-source acceptance count therefore remains unproven.
- No participant-owned authorized end-to-end lab demonstration, actual scanner run IDs, source hashes, or visual review of a real-data PDF are available.
- The disabled web-scanner candidate has no deployed, independently verified private worker network/firewall evidence. No public deployment has been verified from this workspace.
- A real authenticated API operation run needs participant-controlled restricted credentials entered in the deployed app, action-bound approval, and worker evidence. Do not share the credential values in chat or GitHub.
- The test-only end-to-end journey needs a passing hosted CI run on the implementation revision.

## GitHub dependency status at last check

T30 is [issue #72](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/72), still open. Its declared prerequisites #34 is closed; #38 (ZAP), #39 (Nikto), #48 (cross-tool deduplication), #51 (conversational intake), #54 (onboarding UI), #57 (risk ranking), #63 (report contract), and #67 (PDF) are open. Do not close these issues based solely on local code or synthetic tests; each has its own acceptance evidence and contribution constraints.

The T30 implementation is under review in the authorized GitHub pull request. The participant can deploy the import-first UI/API on Render with Supabase using [`free-cloud-deployment.md`](free-cloud-deployment.md); the Render Blueprint does not start scanners or workers. Deployment, real participant-owned captures, and demonstration evidence remain manual acceptance steps. See [`demo/minimum-acceptance.md`](../demo/minimum-acceptance.md) for the participant-side steps and closure evidence checklist.

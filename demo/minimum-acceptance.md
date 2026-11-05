# T30 minimum-prototype acceptance runbook

This runbook separates a software walkthrough using synthetic data from the genuine-evidence acceptance needed to close T30. Synthetic fixtures prove code paths only. They must never be described as scanner captures, permission, scan coverage, or a competition demonstration.

## Software-only walkthrough (test data)

The automated vertical-slice test at `tests/e2e/minimum-prototype/test_minimum_prototype.py` creates one assessment and exercises:

1. Conversational intake bound to an explicit scope and revision.
2. Refusal of an excluded target and refusal to schedule active validation from conversational text.
3. Encrypted recorded imports and normalization of Nmap XML, ZAP Alerts JSON, Nikto JSON, and an OpenAPI JSON definition.
4. Digest-bound reviewer decisions that leave every synthetic scanner source labelled `test-only-reviewed`; the OpenAPI definition remains `not-verified`.
5. A cross-tool ZAP/Nikto candidate based on their shared endpoint and explicitly reported CVE, followed by an append-only reviewer merge.
6. A malformed Nmap replay that is quarantined, remains unverified, and does not appear as a successful empty scan.
7. Reviewer-supplied asset context, frozen result revisions, and a PDF export.
8. A false acceptance gate: the synthetic inputs do not count as genuine integrations and cannot make the three-import criterion pass.

The test makes no network requests to targets and creates no scanner output. The complete non-service suite passed on this Windows host (**241 passed, 6 skipped, 18 deselected**), including this journey, when run with the loopback access required by Starlette `TestClient`. Hosted CI must still execute it on the published implementation revision. On this Windows host, the test runner needs permission to create the local loopback self-pipe used by `TestClient`.

## Participant-owned genuine-evidence run

Complete these steps only with a target and test actions the participant is authorized to perform. Do not ask organizers for a target or assume the event page grants permission.

1. Deploy the API, web UI, database, broker, and required workers in the participant's cloud workspace. Configure secrets in the provider's secret manager. Do not put secrets in this repository, issues, screenshots, or chat. A deployment is not proof of scanner isolation or authorized egress.
2. Use a participant-owned, disposable lab application and record the exact targets, exclusions, allowed methods/profiles, rate and time limits, authorization basis, and validity window. If a private scanner worker with enforced default-deny egress is not deployed and verified, do not enable native ZAP/Nikto execution.
3. In AegisTrace, create an assessment and exact scope. Enter the assessment request, inspect the persisted plan and confirm that it proposes recorded imports only. Verify that an excluded target is blocked and that active validation from the request does not create a job.
4. Upload original Nmap XML, ZAP Alerts JSON, Nikto 2.6.x JSON, and an OpenAPI 3.0/3.1 JSON definition using the **Import evidence and API definitions** form. Enter the source-reported version, capture time, represented targets, exclusions, and a reference to the participant's authorization record. Do not edit/redact originals before upload; sanitized exports can be provided separately if needed. The importer hashes and encrypts originals and never contacts the target.
5. In **Source provenance review**, inspect each original outside the model and in the application, match its SHA-256 to the normalized revision, and record `genuine permitted capture` only if the source really is genuine and the capture is within the stated permission. Select `test-only` for examples, replay, and handcrafted samples. The review is a human assertion; it does not authenticate a scanner or create authorization.
6. Review normalized observations and source pointers. Confirm the network, web, and API-definition coverage labels; inspect any ZAP/Nikto correlation candidate; merge, split, or leave it unresolved with a rationale. Record asset context only with references that the reviewer actually inspected.
7. If using the API-check worker, enter restricted credentials in the deployed application only. Select exact declared operations, inspect the impact and reset instructions, and approve that digest as a human reviewer. Never infer identity from a successful HTTP status. Do not enable native scanner candidates until the worker/network gate has been independently verified.
8. Freeze the selected source revisions and download the PDF. Open every page. Trace a reported observation to its source evidence ID, pointer, capture time, and SHA-256. Check that source observation, reviewer decision, inference, and unknown fields remain distinguishable.
9. Repeat one relevant path with a missing/unavailable tool or a deliberately excluded operation. Preserve the actual failure/denial state and ensure the report shows the resulting gap without claiming success.
10. Save the real assessment, scope, plan, run, import, normalized source, reviewer-decision, export, and audit IDs; exact tool versions; UTC times; original artifact hashes; and test run link. Keep credentials and private originals out of the issue. Attach only sanitized review material that the participant is permitted to share.

## T30 closure evidence checklist

- [ ] Hosted integration test for the test-only vertical slice passes on the exact implementation commit (local Windows run passed; hosted CI evidence remains pending).
- [ ] One genuine participant-owned authorized assessment contains at least three version-matched network/web sources (Nmap plus web scanner/import sources); synthetic tests and an OpenAPI definition alone do not satisfy this count.
- [ ] Reviewer has inspected and correctly classified each original source and its authorization basis.
- [ ] A real end-to-end run demonstrates scope rejection, safe denial, normalized evidence links, correlation/risk review, a complete reviewed PDF, and one truthful failure path.
- [ ] Any live API session result is linked to declared operations, approved credentials, and the actual isolated worker run; identity remains unknown unless independently verified.
- [ ] A reviewer has opened the PDF and confirmed its sections, pagination, trace links, limitations, and frozen-source digest.
- [ ] Implementation and hosted CI evidence are pushed after the participant approves the concrete reviewable diff. The issue is closed only after all evidence above is available and reviewed.

If genuine authorized artifacts, isolated worker deployment, or the live demonstration are not available, leave T30 and the affected integration issues open and report the missing evidence explicitly.

# Evidence-derived coverage and integration transparency — T29 / #46

## One snapshot for workspace and exports

`GET /api/v1/assessments/{id}/coverage` enforces assessment membership and builds the shared coverage v2 snapshot. It includes capture time and a SHA-256 digest of the canonical JSON excluding the digest field itself. Reviewer-frozen result exports embed that same snapshot and its seven-tool capability matrix; PDF rendering reads those frozen values rather than the current registry. Later source data, credential revocation or disabled tools affect the current view, not a historical report. Reports pin referenced normalization evidence IDs using existing report retention rules. A coverage snapshot describes the assessment at freeze time and may include more sources than the selected observation revisions.

The current workspace may be newer than a report. Compare capture time and snapshot digest; a historical report is not silently refreshed. Old reports without a coverage snapshot remain readable and do not acquire invented current metadata.

## Scanner status and source observations

All seven named scanners have an explicit capability record: mode/status, edition, version, API version, license state/reference, verified supported formats, candidate guarded containers, verification timestamp/run, implementation identifier and limitations. Parsed/imported files do not promote that status. Source runs, recorded-import counts, normalization states, source evidence/run IDs and native job states are shown separately. A completed request or parsed alert is not evidence that a commercial product is licensed or a native scanner ran.

The registry is an operator-controlled in-process verification boundary. `verify_and_register` still requires the existing reviewed proof checks. `revoke` immediately marks a known tool unsupported, clears currently supported formats, records a bounded reason and optionally marks its license missing. It retains the last successful verification as history. There is no public availability toggle or automatic license discovery. Restarting with the conservative default registry does not restore working claims. Runtime license discovery, persisted deployment attestations and additional actual tool integrations remain adapter work.

## Endpoint/method counting

The denominator consists only of endpoint IDs from normalized OpenAPI definitions, intersected with the assessment's endpoint catalog. IDs preserve separate assets even when paths and methods match. Imported web alerts and scanner observations never establish which endpoints were attempted. Hidden routes remain unknown.

Only terminal API-check results with a valid content digest, matching check/source/evidence IDs and recognized execution mode are counted. Endpoint/method identity and attempted/state/status coherence are validated. Pending, tampered, foreign-source and impossible-success results are rejected and their check IDs are exposed for review; unverifiable result bodies are not repeated in the snapshot.

`live-request` and `disposable-test` results have independent counters and endpoint tables. Latest terminal outcome per endpoint/method is selected by completion time, with check ID as a deterministic tie-break. `attempted_count` describes those latest outcomes. `ever_attempted_count` preserves historical attempts even when a later result is blocked or excluded. Neither metric proves the API is secure or that identity was verified.

States distinguish succeeded, failed, blocked, excluded and untested. HTTP success remains an HTTP outcome. 401/403, unavailable/expired credentials and missing attempts remain visible; identity verification is explicitly not established. Current credential metadata is counted without decrypting values; revocation does not erase historical requests. A stale running lease/deadline displays unknown without inventing completion. Native scanner jobs and API-check jobs remain separate.

## Bounds and gaps

Each database collection is bounded to 1,000 rows in deterministic ID order. Total source/asset/endpoint/observation counts are queried separately. Any truncated collection is explicitly listed, `snapshot_complete` becomes false, and overall coverage becomes `bounded-snapshot-incomplete`. Per-tool breakdowns and declared-operation denominators then refer to the bounded snapshot. The workspace displays at most 100 endpoint rows per mode and identifies this UI limit; the authenticated API and frozen JSON retain the full bounded data.

Network/web source gaps and absent verified integrations are visible. Broad prototype/demo/authenticated-identity/professional-report gates remain open unless the required evidence exists. Real reviewed API requests are no longer described as globally disabled, and disposable tests never satisfy live coverage or competition demonstration gates. The evidence-summary PDF remains explicitly incomplete as a professional VAPT report.

## Verification

- `tests/test_coverage.py`: separate modes/assets, recorded imports, latest versus historical attempts, stale workers, source/digest/state integrity, license disable/revocation, test credential revocation, unknown commercial capability, bounded truncation, workspace/JSON/PDF agreement and immutable historical snapshots.
- Existing PostgreSQL result and API-check acceptance tests exercise the new snapshot path in hosted CI.
- `frontend/scripts/check-coverage-ui.mjs`: renders the actual React component through the installed Vite transform, verifies seven tools, mode/truncation labels and escaped untrusted text. No new dependency or local installation was needed.
- A test-only PDF preview was rendered and visually inspected. Long capability metadata has a regression test proving page text remains above the footer.

Source mapping: R05/R06/R29 seven-tool status and honest supported modes; R23 minimum integration evidence stays distinct from source presence; R27 source trace and safe unknown results; R34 observed evidence versus unknown claims; W07 actionable gaps and source-linked outcomes. Exact commit and hosted CI acceptance are recorded in GitHub #46.

## Participant work

None for this software acceptance. No real API key, local setup or organizer input was needed. Real source provenance and independent benchmark labels remain their own work items; production runner deployment remains #28. Missing inputs do not justify inventing coverage or enabling unavailable scanners.

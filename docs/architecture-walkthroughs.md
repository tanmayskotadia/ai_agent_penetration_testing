# Five architecture walkthroughs - T02

These are design reviews, not executed scans, fixture results, product tests or proof of implemented enforcement. References use component/boundary/invariant IDs from the [architecture](architecture.md) and [threat model](threat-model.md). Organizer lab authorization is absent, so no real target is used.

## W01 - Approved scan

**Preconditions:** hypothetical current organizer manifest, permitted target/profile/rate, authenticated analyst and required plan/action approvals. A live check requires T04 to establish these inputs first.

1. C01 submits intent; C02 validates actor, manifest and scope revision. C03 returns a typed plan/rationale, not a command.
2. C02 records approved action/job/outbox and audit atomically in C04 (I12). C05 publishes a job ID; C06 may deliver it more than once.
3. C07 requests a claim. C05 reloads current scope/profile/grant/stop state and atomically binds lease, attempt and required single-use approval (I01-I03/I11).
4. C07 uses a reviewed adapter template and actual allowed destination through B04. It records external run identity/status and sends artifacts through C08 into C09.
5. C08 registers hashed originals and normalized observations. C10 preserves occurrences and computes supported priorities; C03 selects another permitted useful action or stops.

**Expected review outcome:** no tool execution bypasses deterministic authorization; queue duplication cannot relaunch an already claimed active action. **Deferred proof:** T19/T20/T30/T61/T62 live/import and negative cases. **Manual input:** organizer permission before this can execute.

## W02 - Denied target or changed authorization

**Input:** a proposed target outside the current manifest, an excluded target, or a previously valid job whose scope/grant expired before claim.

1. C02 rejects invalid scope at intake and writes an attributable denial. No executable outbox/job is created for the forbidden action.
2. If the proposal came through a model or tampered queue message, C05 still reloads canonical policy and denies claim (I01/I04/I11).
3. A DNS/redirect escape found by C07 is blocked by runtime checks and independent egress rules at B04. C01 shows denied/partial status and a real reason.
4. Revocation after a claim triggers cancellation/restriction and reconciliation. A request already transmitted cannot be retroactively undone; do not claim otherwise.

**Expected review outcome:** a chat instruction, model claim, old grant or job ID does not widen authority. **Deferred proof:** T13/T14/T16/T62 canonicalization, DNS/IPv6/redirect and revocation races. **Manual input:** none to implement denial logic; valid organizer permission is needed only for a permitted live control case.

## W03 - Imported native result

**Input:** a future genuine permitted native export with capture provenance, redistribution/redaction record and known tool/version. No such genuine corpus is currently supplied.

1. C02 checks import ownership; C08 places bounded bytes in quarantine and disables external entity/resource resolution (B05).
2. C09 stores original hash/object ID; C04 registers tool/version/capture-time/mode/pointer. Out-of-scope asset content remains quarantined for association review, not treated as target permission.
3. C08 normalizes observations. C10 can merge genuine duplicates but retains each occurrence and all source records (I05/I06).
4. UI/report mark the source import-only/recorded as appropriate. This import does not consume a validation grant or issue scanner traffic.

**Expected review outcome:** supported import is useful but never presented as live assessment or authorization. **Deferred proof:** T05/T11/T22/T35/T48 fixtures and parser/correlation cases. **Manual input:** genuine permitted capture artifacts and independent labels for T05; test-only handcrafted malformed files remain explicitly non-evidence.

## W04 - Worker crash and duplicate delivery

**Failure positions:** before claim; after claim but before known submission; after external submission; during collection; after domain result commit but before queue acknowledgement.

1. Before claim, outbox/queue redelivery can safely ask for the same canonical job. Only one valid lease/grant claim succeeds.
2. After claim, C05 sees the existing attempt; a duplicate cannot create a second one. A consumed grant stays consumed.
3. If submission might have occurred, external run ID/status/collector evidence is reconciled. No evidence of submission is not proof it never happened.
4. Verified running work resumes observation/collection; verified completed work resumes idempotent normalization. Ambiguous work becomes unknown with human review and a report limitation.
5. C03 checkpoint resume reloads revisions. It cannot repeat external effects merely because its node runs again (I03/I10).

**Expected review outcome:** availability may be delayed but no blind retry of consequential actions. **Deferred proof:** T19/T23/T39/T63 actual fault injection and tool-specific reconciliation. **Manual input:** an operator may need to inspect an external tool when its API cannot resolve an unknown run; this is a runtime residual, not an M01 test already performed.

## W05 - Report export

**Preconditions:** future reviewed findings plus source evidence; authorized report requester; explicit limitations and approval outcomes.

1. C02 verifies assessment membership/reviewer revision. C11 freezes scope, runs, observations, occurrences, findings, approvals and mappings in C04.
2. C11 builds a structured document from the snapshot; model prose must cite validated facts and cannot introduce new identifiers/confirmed claims (I06).
3. ReportLab uses packaged fonts/registered sanitized assets with no external fetch or arbitrary paths. Generated bytes become a private registered artifact (B07).
4. Authorized download emits audit metadata. A later scan/import creates new observations/report revision and cannot silently mutate the delivered report.
5. A selected finding resolves through occurrence/source pointer to preserved original bytes. Missing/mismatched evidence blocks a verified traceability claim; failures/unknowns remain in limitations.

**Expected review outcome:** complete snapshot-consistent report and attributable source trace; safe repeat rendering is separate from scan execution. **Deferred proof:** T55-T60 content, visual, confidentiality and source-reference checks. **Manual input:** none for report implementation; later genuine evidence and reviewer decisions are needed for a real sample, and Drive delivery needs explicit artifact/sharing setup.

## Review conclusion

The five flows have component owners, policy points, persistent state, failure outcomes, source/provenance handling and explicit deferred tests. This satisfies T02's design walkthrough requirement. It does not satisfy the later actual runtime/lab/prototype acceptance gates.

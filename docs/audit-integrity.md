# Audit integrity — T09

Every canonical audit event has an assessment, event UUID, per-assessment sequence, attributed human/service/AI-proposal identity, server UTC timestamp, request/correlation UUIDs, policy version, optional scope/plan revision, resource ID, action digest and explicit outcome. The contract has no arbitrary raw-body or credential field. Evidence storage, read, redaction, review and purge append canonical audit events in the same transaction as their change. HTTP request attribution propagates across async/synchronous handlers. T10 integrates the remaining API request/resource contracts; later scanner/report producers must use the same append service.

An assessment-specific head row is upserted and locked for append. Each digest covers canonical JSON, sequence and previous digest. A unique event UUID rejects replay. SQLite's write lock supports smoke tests; PostgreSQL uses row locking to serialize concurrent writers. Failure rolls back the audit record together with the associated change.

Migration 0004 installs database triggers denying UPDATE/DELETE (and PostgreSQL TRUNCATE) of audit history, including from application roles with those SQL grants. Consumers have no history edit/delete API. Audit heads are mutable serialization state, not externally trusted anchors. Evidence access-event rows are an operational index; canonical audit history is authoritative.

Verification detects changed content, sequence gaps, duplicates, altered identity, and missing tail events relative to an expected head. A retained signed checkpoint binds assessment/sequence/digest outside the working history. `scripts/export_audit_checkpoint.py ASSESSMENT_UUID --output PRIVATE_NEW_FILE` writes an exclusive new file; an operator must retain it independently of the database. The script never prints keys or overwrites an old anchor. T10 exposes an authenticated checkpoint download so participant-side CLI setup is unnecessary. Exported checkpoints include no raw evidence; keep assessment metadata private nonetheless.

## Limits and operational obligations

This is tamper-evident, not absolutely tamper-proof. A database owner can disable triggers, drop objects or rewrite an entire unanchored chain/head. An administrator controlling application signing keys and all stored checkpoints can forge those too. Independent retention, least-privilege deployment roles and protected key backups matter. No external immutable storage provider, scheduled checkpoint retention or public notarization is claimed. Keep old checkpoint-verification keys on secret rotation.

Incomplete real assessments must retain explicit failed/partial/unknown events; a requested report does not mean a PDF was generated. Missing approval is detected as changed/missing recorded history, not proof that unimplemented scanner controls have run. Automated action digests identify canonical inputs; source evidence remains separately hash-linked.

## Verification

`uv run pytest tests/test_audit.py -m 'not services'` exercises a clearly labelled handcrafted request → plan → approval → recorded execution → review → report-request chain, omission/change/replay checks, trigger denial and 12 concurrent appends with resumable cursors. The hosted service test exercises migration-installed PostgreSQL guards, including an actual restricted application role and TRUNCATE denial. Evidence API tests verify real attributed audit writes. Existing fresh-database tests exercise rollback and forward migrations.

Requirement links: R02/R09 attributable decisions and provenance; R12/R26 human-approval trace; R18 limitations/outcomes; R31/R34 transparent authority and evidence. Test lifecycle records are not live scanning, real human approval evidence or report-generation proof.

# ADR 0002 - One canonical relational store, checkpoints and outbox

**Status:** accepted for implementation; 4 November 2026.

## Context and decision

Use PostgreSQL for canonical assessments, revisions, findings/occurrences, jobs, approval grants, audit and report references. Commit domain changes, attributable events and outbox intent in the same transaction. Redis is not job truth. LangGraph checkpoint tables retain bounded reasoning context and cursors, but canonical domain revisions win on resume.

Store evidence graph edges relationally first. Raw artifact bytes live in private storage with transactional metadata references. No atomic transaction across database, broker, model calls, filesystem/object storage and external scanners is assumed.

## Alternatives and consequences

A separate graph/vector database is deferred until a measured query/retrieval need exists. Model transcript memory alone loses normalized facts and makes consistency unclear. Broker-only status can disappear or diverge. One DB simplifies constraints, backup and audit, but needs migrations, authorization and query profiling.

Checkpoint writes may lag a domain commit; resumed planning validates revisions and rebuilds stale summaries. Outbox duplicates are expected; consumers must be idempotent. Orphan raw objects remain quarantined until safely reconciled. T07-T09/T19/T39 implement; T61/T63/T66 verify consistency, crashes and restore. See [LangGraph persistence](https://docs.langchain.com/oss/python/langgraph/persistence).

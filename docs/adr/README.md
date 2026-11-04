# Architecture decision records

T02 decisions are accepted implementation directions under the participant's instruction to complete and push the next issue, then all of M01. They do not certify runtime enforcement, organizer permission, license entitlement or measured model quality.

| ADR | Decision | Main tradeoff |
|---|---|---|
| [0001](0001-authority-and-process-boundaries.md) | Bounded reasoning, deterministic authority, isolated execution | More explicit contracts; avoids model authority and an unnecessary agent swarm |
| [0002](0002-state-memory-and-outbox.md) | PostgreSQL canonical state; separate checkpoints and durable outbox | Revision reconciliation required; avoids competing stores of truth |
| [0003](0003-dispatch-and-reconciliation.md) | Celery/Redis transport with leases and conservative reconciliation | Unknown work may wait for review; no false exactly-once promise |
| [0004](0004-evidence-and-report-snapshots.md) | Private original evidence and immutable snapshots; ReportLab | Structured templates over arbitrary HTML flexibility |
| [0005](0005-model-and-adapter-contracts.md) | Provider-neutral model proposals and edition-aware adapters | Some modes remain unavailable; honest partial coverage over invented integration |
| [0006](0006-deployment-and-pinning.md) | Local-first modular processes, exact implementation locks and verified boundaries | More prerequisite checks; no unverified container-isolation claim |

Each record states context, decision, alternatives, consequences and verification ownership. Revisit a decision only with a new requirement or measured limitation; record the replacement rather than silently rewriting its rationale.

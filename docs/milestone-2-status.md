# M02 evidence platform — implementation and acceptance

M02's six engineering scopes are implemented and each delivery is closed only after its exact commit passes hosted CI. [GitHub tracker #3](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/3) links the actual commits/runs and is the live closure record.

| Issue | Implemented behavior | Reproducible proof | Participant intervention |
|---|---|---|---|
| T07 #20 | Fourteen canonical domain contracts, assessment-bound links, null unknowns, distinct occurrences, source attribution and reviewer confirmation | `tests/test_domain.py`, migration round trip, generated domain schemas | None |
| T08 #21 | Bounded encrypted originals, private exact-byte retrieval, integrity checks, separate reviewed redactions, expiry and report pinning | `tests/test_evidence.py`, real PostgreSQL round trip in CI | None for engineering acceptance; private encryption key before deployment |
| T09 #22 | Attributed events, serialized hash chain, append-only SQL guards and external checkpoint export | `tests/test_audit.py`, actual restricted PostgreSQL role in CI | None for engineering acceptance; independently retain checkpoints for rollback detection |
| T10 #24 | Runtime assessment/scope inputs, private versioned APIs, atomic idempotency, typed errors, persisted finite SSE, generated frontend contracts | `tests/test_api_contracts.py`, actual PostgreSQL concurrency/replay, frontend build | None |
| T11 #23 | Bounded isolated container inspection, malformed/unsupported/out-of-scope quarantine and preserved originals/partial diagnostics | `tests/test_ingestion.py`, actual PostgreSQL authenticated import flow | None |
| T12 #25 | Seven-tool registry shared by API/UI/report facade, typed worker protocol and verification-gated status transitions | `tests/test_capabilities.py`, generated matrix/adapter schemas and frontend types | None |

## Integrated acceptance boundary

The API acceptance flow creates an owning assessment, inputs a scope at runtime, records source metadata, uploads a hash-matching encrypted original, requests/inspects an import, persists diagnostics, traces audit events, retrieves exact originals privately, and keeps unimplemented findings empty. Replay/concurrency does not duplicate resource requests. Hostile files preserve source evidence and produce no invented findings. API/status/report consumers use the same capability registry.

The suite uses explicitly labelled handcrafted records and parser inputs. This proves software contracts and control behavior, not capture authenticity, native scanner accuracy or calibrated confidence. All seven real integrations remain planned. Working native normalizers and the minimum three-tool network/web gate belong to M05/M06. Plans/approvals are drafts/requests; jobs and reports remain explicitly blocked until their real engines and controls exist. No live scanner, actual human-approved exploit or PDF is represented as working.

## Verification and source coverage

Hosted CI runs lint/format/strict types, requirements/source hygiene, generated schema/matrix drift checks, all non-service acceptance cases, actual PostgreSQL migration and API/evidence/quarantine/audit tests, Redis/Celery diagnostics, frontend production compilation and fresh container HTTP/proxy startup. CI also checks database rollback/forward and a restricted audit application role.

Each `docs/verification/T07-review.json` through `T12-review.json` maps task scope to original requirement groups and the executable checks. The source-linked compliance matrix records partial implementation evidence without marking broader end-to-end PDF requirements verified. The milestone's completion does not close M01's genuine lab/corpus gaps or the later submission gates.

## Deployment and next work

The separate Supabase `dataops` project exists, and the participant selected Render `My Workspace`; other projects are not changed. No local installation is required. Public application deployment is not part of this acceptance: full shared sign-in/revocation, deployed least-privilege/RLS policy, provider secret injection, hosted job execution/storage capacity and deployment verification remain ahead. Existing short-lived operator-issued identities are an API foundation, not public user onboarding.

M03 can implement deterministic scope/approval/identity/network boundaries without organizer questions or preloaded targets. Actual live use still needs valid user-provided authority; the hackathon profile retains the original organizer-lab restriction. Genuine captures, independent labels and a selected approved AI endpoint are later real-data/evaluation inputs, not a reason to invent success now.

# Threat model - T02 design baseline

**Scope:** the architecture in [architecture.md](architecture.md). Controls below are required implementation directions and future verification targets; they are not deployed or independently penetration-tested by T02. No authorized lab targets currently exist in this project.

## Assets and assumptions

Protect organizer target permission, analyst identity/membership, credentials, approval grants, worker/coordinator identity, original scan evidence, findings/risk provenance, report snapshots, audit and dependency integrity. Scanner outputs, imported XML/JSON, banners/HTTP responses, model output, retrieved advisory text, queue deliveries and browser inputs are untrusted.

Trust only authenticated human/service identity plus current canonical policy, verified registered source objects and deployed network boundaries. An organization/host administrator can control the host and primary database; application-level hashing alone does not defeat a malicious administrator. A container is not claimed equivalent to a hardened VM boundary. Commercial availability, organizer credentials and cloud services are not assumed.

## Security invariants

| ID | Invariant | Enforcement owner | Future proof |
|---|---|---|---|
| I01 | No live traffic without current organizer scope and a permitted profile | API/coordinator, worker and network boundary | T04/T13/T14/T62 target, expiry, exclusion, DNS/redirect and IPv6 denial cases |
| I02 | Human-only action-specific approval before offensive validation | Auth/approval API and atomic execution claim | T16/T34/T62 denial, stale/replayed/forged grant and race cases |
| I03 | At most one new external execution attempt per consumed grant; unknown outcomes never auto-relaunch | Coordinator lease/attempt state and reconciliation | T19/T63 crash before/after external submission and redelivery cases |
| I04 | Model content is a proposal, never execution/approval authority | Typed API boundary and deterministic validation | T18/T40/T62 prompt injection, arbitrary command and self-approval attempts |
| I05 | Original evidence and distinct occurrences survive normalization/correlation | Private objects, immutable observations and reviewed clusters | T08/T43/T48 hash/source trace and multi-asset merge cases |
| I06 | Inference, confidence, supported severity and validation state remain distinct | Grounding/risk/reviewer/report contracts | T40/T44/T45/T60 unsupported CVE/proof/score and contradictory-source cases |
| I07 | No cross-assessment private evidence, report or approval access | Resource authorization and object retrieval service | T15/T52/T62 identifier guessing, role change and download tests |
| I08 | Stop/revocation blocks new claims and never implies unverified termination | Coordinator, network controller and worker reconciliation | T17/T63 cancellation races, disconnected tools and unknown status |
| I09 | Secrets and raw private scan data do not enter public source/logs or unapproved model requests | Secret injection, redaction, private storage and egress policy | T06/T15/T18/T62/T65 canary/access checks |
| I10 | Checkpoint replay cannot bypass authorization or repeat an external effect | Effect-free graph proposals and idempotent coordinator | T39/T63 resume at approval/submission boundaries |
| I11 | Broker messages cannot widen the approved job | Job-ID messages, service identity and canonical job reload | T19/T62 tampered/replayed message tests |
| I12 | Domain action and its attributable audit/outbox state commit together | PostgreSQL transactions and per-assessment ordering | T09/T19/T63 rollback/outbox delivery and integrity review |

## Threat and control register

| Threat | Boundary / affected invariant | Required controls | Residual risk / honest limitation |
|---|---|---|---|
| Scanner banner or imported file tells AI to scan another host, reveal keys or approve a module | B02/B05; I01/I02/I04/I09 | Untrusted evidence typing, constrained proposals, no shell interface, policy outside model, redacted context | A model can still produce poor suggestions; rejected suggestions are logged and do not execute |
| Scope escape through DNS rebinding, redirected HTTP, IPv6, userinfo, alternative IP spelling or excluded path | B04; I01 | Canonicalization, current resolved allowlist, redirect checks and actual network egress deny rules | Time-of-check/effect race remains; independent network restrictions and bounded profiles reduce it |
| New parameters, scope or tool profile reuse an earlier human approval | B01/B03; I02 | Bind grant to digests/revisions/expiry; require authorized reviewer; consume once with attempt | Human can approve a harmful in-scope action; show impact and keep organizer constraints authoritative |
| API/broker request claims a forged actor, targets a sibling assessment or submits an arbitrary binary | B01/B03/B07; I04/I07/I11 | Server-derived identity, membership, typed job IDs, capability/profile templates, service-auth claims | Host/service credential compromise exceeds browser controls; least privilege and rotation required |
| Worker crashes after submitting a scan but before recording its external ID/result | B03/B04; I03/I08 | Persist submission intent, capture run ID early, reconcile via supported tool APIs, unknown state and human review | Cannot promise exactly-once external effects without tool-side idempotency; never blind retry |
| Queue redelivery or Redis loss repeats active validation | B03; I03/I11 | Canonical leases/attempts/outbox, consumed-grant guard and retry-class policy | Availability can be delayed; safe uncertainty is preferable to duplicate offensive execution |
| Scope expires or is revoked while a long scan is already running | B03/B04; I01/I08 | Short claim validity, bounded scan durations, stop events, network restriction and supported cancellation | In-flight requests cannot be recalled; unsupported tool cancellation remains explicit unknown |
| XXE, archive traversal, decompression bomb, hostile HTML, deeply nested/oversized output | B05; I04/I05/I09 | Entity-disabled parsing, no resource fetch, quotas/timeouts, generated paths, quarantine and sanitized display | Parser/image libraries still need pinned patches and process isolation; malformed input stays untrusted |
| Object ID guessing, public bucket/static path or unredacted PDF leaks evidence/credentials | B07; I07/I09 | Private storage, per-request membership, opaque IDs, redacted derivatives, authorized exports | A permitted recipient can copy a delivered report; sharing must be a deliberate later action |
| Report rendering fetches attacker URL or reads an arbitrary local file | B05/B07; I07/I09 | Structured ReportLab document, escaped text, registered packaged assets only, no external network | Rich markup/images can still be dangerous if admitted; arbitrary HTML and user-supplied paths remain forbidden |
| Correlation hides a second affected asset or misclassifies an unconfirmed banner match | B05/B07; I05/I06 | Immutable observations, separate occurrences, conservative matching, reversible review and explicit suspected state | Detection/false positives depend on source quality; evaluate independently rather than claim certainty |
| AI invents a CVE, proof, impact story or precise risk score | B02; I06 | Evidence/identifier applicability checks, null/unknown, grounded narrative and versioned priority policy | Vetted advisories may be stale or ambiguous; source dates and uncertainty remain visible |
| Database operator edits audit chain and regenerates hashes | B08; I12 | Restricted roles, append-only app access, externally retained digest checkpoints/backups and restore review | Same-store hash chain alone is not tamper-proof against administrators |
| Logs, traces, CI artifacts or model requests leak raw sensitive data | B06/B08; I09 | Redacted identifiers/diagnostics, sanitized fixtures, log/prompt allowlists, disabled external processing by default | Redaction can miss data; reviewed data classification and canary checks are required |
| Unpinned dependency/image/feed change introduces malicious or incompatible behavior | B08; I09/I12 | Exact locks/digests, supported sources, compatibility checks, no commercial binaries/feeds committed | Pinning is not a security audit; updates need review and relevant checks |

## Required failure handling

- Authorization/policy storage unavailable: do not dispatch new work. Existing workers follow bounded timeout/cancellation policy and report unknown when not verified.
- Model unavailable: preserve source evidence; allow analyst review and evidence-only reporting, without inventing a replacement model decision.
- Broker unavailable: retain committed jobs/outbox for repair; do not mark queued as running.
- Evidence integrity failure: quarantine, flag affected findings/report snapshots and do not present missing bytes as verified proof.
- Scanner unavailable or license/API mismatch: show unsupported/import-only/planned as appropriate, with no synthetic successful run.
- Report render failure: retain frozen input and explicit error; retry rendering by snapshot ID, never silently substitute another assessment revision.

## Assurance plan and residual decisions

The [walkthroughs](architecture-walkthroughs.md) inspect five required design flows. Later T62/T63 must run actual adversarial/fault cases against implemented controls. They should cover both forbidden and permitted control cases so denial is not achieved merely by breaking everything.

Manual prerequisites: organizer scope/actions/rates and credentials supplied through a secure local mechanism; genuine captured data and independent labels; licensed tool/API/feed availability; chosen model/data policy. These are listed in [open questions](open-questions.md). No manual action is needed to finish this architecture deliverable itself.

T03 must prove the runtime dependency/configuration path; T04 must verify real network isolation and lab reset. Do not close those gates based on this design or assume Linux container behavior on an unverified Windows/Docker environment.

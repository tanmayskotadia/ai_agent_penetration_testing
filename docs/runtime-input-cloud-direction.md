# Runtime inputs and hosted deployment direction

Participant direction, 4 November 2026: build a general-purpose assessment application; collect scope and evidence inside the application when an assessment is created. Do not require organizer questions or participant-side local setup to continue development.

## Assessment intake contract

The implementation must collect the assessment name, owner, target/asset identifiers, exclusions, authorization source and reviewer, validity period, permitted actions/profiles, rate/concurrency limits, evidence-processing permissions, and private credential references at runtime. Do not hardcode a participant's current targets or authorization into builds. Scope changes create a new revision and invalidate affected approvals.

Provide distinct recorded-import and live-assessment paths. Recorded imports collect original supported exports, tool/version/time, source, rights/redaction review, hashes and asset associations. They must not be described as live runs performed by the application. Missing live authorization may block live execution without blocking unrelated development or permitted import processing. A checkbox alone is not proof of authority.

General-purpose customer-owned assessments and hackathon demonstration eligibility are separate contexts. Preserve the PDF's organizer-authorized-target requirement in the hackathon profile; runtime input does not waive it. A general-purpose workflow cannot by itself establish that a demonstration satisfies the event rules.

## Cloud direction and verified connections

- No participant-side Docker, scanner, database or model installation is required.
- Render MCP access works. Participant confirmed `My Workspace` on 4 November 2026. Three existing unrelated free web services were discovered; leave their configuration unchanged. Free compute hours are shared, so inspect remaining allowance before creating another service.
- Supabase MCP access works. Participant requested a separate project named `dataops` and explicitly selected `tanmayskotadia's Org`. Created project `gpztgfmhxhacqngteeqr` in `ap-south-1` on 4 November 2026; creation returned `ACTIVE_HEALTHY`. The existing `smart cities` project was not modified. Configure application database and storage only in `dataops`.
- Proposed hosting: Render static frontend and free FastAPI web service, with Supabase PostgreSQL and private evidence storage. This requires deployment configuration and application integration; it is not yet deployed.
- Render's free web service is interruptible and its filesystem ephemeral; free background workers are unavailable. Preserve canonical job state and evidence outside the web instance. Scanner execution needs separately approved remote compute. Do not relabel a web process or CI runner as an unrestricted scanning worker to bypass hosting constraints.
- Model endpoint selection remains a later input. Keep credentials server-side and require an explicit evidence-processing policy before external model calls. No free inference entitlement is assumed.

## Acceptance and remaining inputs

This direction removes current organizer answers as a prerequisite for general-purpose implementation. It does not complete T04's actual authorized lab/health/reset acceptance or T05's genuine independently reviewed corpus. Keep those evidence-dependent items open and track application functionality separately from demo readiness.

Project/account selection is complete: Render `My Workspace` and the separate Supabase `dataops` project. Later, provider Git access or private secret entry may require participant interaction if the connectors cannot complete it. Actual live use requires valid scope and approved remote execution; measured accuracy requires genuine data and independent review. Final PPT/video and submission access review remain participant deliverables.

This document records a requested implementation direction, not a claim that runtime intake, authentication, storage or scanner adapters are implemented.

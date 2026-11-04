# Lab provisioning boundary

**Current state:** no organizer lab authorization; no vulnerable target has been provisioned or contacted. The development PostgreSQL/Redis/API Compose profile is not an authorized security lab.

T04 provides a strict offline manifest contract and denial tests, not a substitute for organizer permission or the later runtime policy. See [lab authorization](../docs/lab-authorization.md). Never turn the example into approval merely by changing its status.

After genuine organizer authorization arrives, record the exact targets, exclusions, allowed actions, validity, rate limits and a hash/reference to the privately retained authorization document. A human must verify the organizer source and its applicability; local text/hash consistency does not authenticate that source.

If a local lab is explicitly permitted, select and pin only the permitted training-target images, establish a separate target/worker network with verified deny rules, and document accounts, reset, health and teardown. Do not expose training targets publicly. If remote targets are supplied, follow the organizer's health/reset procedure rather than inventing reset commands.

No start/reset command is shipped for an unspecified target. A reset must stop active jobs, revoke unused approvals, preserve evidence/report/audit volumes, reset only authorized target state, obtain new test sessions, and verify permitted health before any next scan. Actual provisioning, egress, health and reset proof remain pending permission and execution.

# M01 delivery status and manual handoff

**Review date:** 4 November 2026. **Milestone:** [M01](https://github.com/tanmayskotadia/ai_agent_penetration_testing/milestone/1). Four issue scopes are complete; two have tested preparatory implementation but missing real-world acceptance inputs. The milestone remains open.

| Work item | Status / proof | Manual intervention |
|---|---|---|
| [T01 #14](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/14) | Completed: 181 requirement records, source trace, rubric/demo and submission gates | None for the baseline |
| [T02 #15](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/15) | Completed: architecture, component/boundary ownership, threat model, six ADRs and five design walkthroughs | None for architecture |
| [T03 #16](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/16) | Completed: locked runnable foundation, migrations, actual PostgreSQL/Redis CI, image builds, service startup and API/frontend proxy verification | Docker installation only if full local Compose use is wanted; hosted CI already verifies it |
| [T04 #17](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/17) | Partial / blocked: offline manifest gate and 19 tests pass; no actual lab provisioned or health/reset proof | Organizer authorization, targets/exclusions/actions/rates/validity, allowed local/remote setup and private credential process |
| [T05 #19](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/19) | Partial / blocked: provenance/split validator and seven tests pass; corpus intentionally has zero genuine captures/labels | Genuine permitted captures and independent duplicate/distinct-asset/contradiction/clean-case labels after T04 permission |
| [T06 #18](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/18) | Completed inventory/policy: seven tools, unknown editions/entitlements, actual resource checks, licenses, model/data handling and notices | None to finish inventory; actual optional licensed tools/model endpoint choices remain future prerequisites |

## Verification completed

- Thirty non-service acceptance cases pass locally; Python lint/format and strict types pass.
- Requirements CSV/scorecard/gates still match the 181-row canonical register.
- [CI for the combined T04/T05 code](https://github.com/tanmayskotadia/ai_agent_penetration_testing/actions/runs/41810042880) passed real service, build and fresh-container checks. T03's original successful acceptance is recorded in [its CI record](verification/T03-ci.json).
- No target security scan, genuine capture, independent benchmark label or calibrated model result was manufactured.

## What the participant needs to obtain

1. Organizer-provided authorization source with exact target scope, exclusions, valid period, permitted actions and rate limits. Explicit permission is required if using a local training lab. Keep credential values and private authorization documents outside public issues/source.
2. Once authorized, genuine tool exports with capture/edition/time/hash/rights/redaction records, plus independent ground-truth review. Handcrafted policy/parser test data cannot replace them.
3. For heavy **local** Docker/scanner/feed/model use, provide suitable Linux/container runtime and storage. Docker is absent on PATH and only about 5.8 GiB was free on the workspace drive at review. Use more available storage or another approved host before that setup; no local Docker installation is needed merely to inspect the working native scaffold or hosted CI evidence.

## Resume procedure

Validate the genuine scope with the offline CLI, then implement and verify the actual authorized target provisioning/network boundary/health/reset before closing T04. Capture and independently review real data before closing T05. Keep the status matrix truthful: all seven scanner adapters remain planned until their later implementation and genuine verification. Do not close M01 based on this handoff document alone.

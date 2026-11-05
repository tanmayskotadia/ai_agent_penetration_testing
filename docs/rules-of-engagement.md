# Reviewed impact profiles and consent — T28 / #45

The packaged rules in `aegistrace.scan_profiles` are shared by human review and worker dispatch. `config/scan-profiles.json` is a generated, digest-bearing review snapshot; editing that JSON does not enable execution. CI checks it with `scripts/export_profiles.py --check`. The catalogue endpoint remains read-only and never grants consent.

| Profile | Purpose and traffic | Available path | Required controls and side effects |
|---|---|---|---|
| discovery | Bounded host/service discovery; connection attempts generate traffic/logs | Native Nmap execution remains blocked; planning and recorded input are available | Exact scope, policy, template and action approval; no exploitation permission |
| passive-web | Process captured HTTP evidence without fetching targets | Offline import/analysis | No crawling, spidering, fetching, active scanning or redirect following; protect private captured data |
| active-web | Explicit selected target requests; even GET can change state | Reviewed concrete HTTPS API checks only; native ZAP/Nikto execution remains unavailable | Human consent binds method/URL selection, credentials, policy, impact statement, reset instructions, profile digest and actual limits |
| controlled-validation | Offensive validation | Disabled | No arbitrary console/module/payload path. Requires separate single-action human approval and isolated validation implementation under #42 before it can execute |

## Parameter and limit enforcement

Unknown profiles/templates and extra options are denied. Each generic template must match its tool and profile. Only `timeout_seconds` is accepted for discovery/passive contracts; active-web also permits bounded `max_redirects`. Timeout must be an integer from 1 through the smaller of the profile timeout ceiling (30 seconds) and the reviewed action runtime. Runtime is limited to 300 seconds. Only active-web may declare redirects, at most three; the implemented API-check worker always follows zero redirects. Controlled validation accepts no execution options and cannot be approved for execution.

Profile catalogue suggestions are not authority. The exact rate and concurrency come from the reviewed execution policy; its digest is part of consent. API plans display those effective limits plus runtime and zero redirects. Network-capable profiles have an eight-job ceiling consistent with the execution-policy contract; a policy can specify a smaller value. Global policy reservations enforce the runtime rate/concurrency across API workers. Exact URL scope/exclusions, DNS pins, TLS verification, subprocess deadline, stop epoch, reviewer revocation and cancellation are rechecked outside model output.

## Binding review to rules

Generic action requests and API-check plans include a hash of the full versioned impact rule. The generic action digest also binds parameters, plan/scope/policy/evidence and rollback instructions. API-check digests bind selected concrete operations, credential IDs, profile rules, impact statement, reset instructions, policy and execution limits. Changing settings after approval invalidates the digest. Changing the packaged rule invalidates the stored profile hash, including already queued work; fresh requests and fresh human review are required.

Old generic records without a profile hash remain readable but cannot be approved/consumed. They can be denied or revoked. A stale API plan can be cancelled; it cannot run under changed rules. No database migration or edit of old records is needed to turn old consent into new consent.

`expected_impact` and `reset_instructions` are mandatory API-check request fields. They are shown in the reviewed plan and terminal export. They describe the operator-approved restoration procedure, not evidence that a target reset actually happened. The worker does not invent a reset or execute arbitrary reset commands. Full offensive validation and reset proof remain #42.

## Acceptance evidence

`tests/test_scan_profiles.py` exercises unknown options, crawling disguised as passive, active/passive template mismatch, timeout/runtime/redirect bounds, wildcard target rejection, and rule changes between approval and dispatch in both approval systems. Existing approval tests exercise parameter tampering and single-use claims. The API workflow tests exercise denied and revoked authority, excluded destructive operations, stale scope, cancellation and crash handling. The real HTTPS harness executes approved requests only against a disposable test-owned server, verifies certificate/pin/redirect/deadline behavior, and saves source-linked results. Test-generated records remain labelled as such and establish software behavior, not competition lab or scanner-accuracy claims.

Source links: R03/R31 scope and boundaries; R04/R12 explicit single-action human consent; R07 review tied to current settings; R18 actual outcomes and limitations; W01 safety boundary. Exact delivered commit/hosted verification is recorded in GitHub #45. Generic native scanners remain unavailable until their own adapter/runner acceptance; catalogue entries alone never cause tool execution.

## Participant work

None for this software delivery or its disposable acceptance tests. No API keys, local setup or organizer input is required. For a future real assessment, supply runtime scope, actual permitted rates/actions, restricted credential references, expected impact and reset instructions; a human reviewer then approves the exact digest. Production runner deployment is tracked separately by #28.

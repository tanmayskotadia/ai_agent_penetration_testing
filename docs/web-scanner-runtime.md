# ZAP and Nikto worker runtime

This document describes the candidate worker path for T25 and T26. It is disabled by default and does not upgrade either tool's capability-registry status. The scanner worker must be deployed separately from the API/control plane and must have a kernel or platform egress policy that denies direct scanner traffic. A per-job HTTP proxy alone is not a network security boundary.

## Implemented path

- A job starts only from the existing single-use, reviewer-approved action and current worker lease. The worker rechecks the current scope, policy, approval, and pinned executable digest before invoking a fixed argument vector.
- ZAP passive mode reads one encrypted HAR evidence object selected in the approved action. It rejects requests outside the approved origin/path scope and creates an Automation Framework plan with `sendRequests: false`; the worker has no per-job egress proxy in this mode.
- ZAP active and Nikto modes use bounded fixed plans, a per-job pinned-address proxy, cancellation checks, a private temporary workspace, and a 2 MiB JSON output ceiling. Nikto refuses path exclusions it cannot enforce. Redirect following is not enabled.
- A successful run creates a live-mode `ToolRun`, a hash-linked `EvidenceReference`, a 30-day encrypted original, and a pending import resource in one transaction. Normalization remains an offline step and labels source observations as suspected; it does not confirm vulnerabilities or create findings.
- The integration registry remains `planned` until genuine tool/version, license, live-run, source-evidence, authorization, and runtime-gate verification are reviewed. Parser fixtures and generated plans are test-only evidence.

## Required operator configuration

All are server-side secrets/configuration; never put values in a browser or commit them:

- `WEB_SCANNER_CANDIDATE_ENABLED=true` (default `false`)
- `WEB_SCANNER_EGRESS_GATE_REFERENCE` pointing to a reviewable deployment record for the actual scanner-network firewall
- `ZAP_EXECUTABLE_PATH` and `ZAP_EXECUTABLE_SHA256` for a supported, pinned ZAP launcher, or `NIKTO_EXECUTABLE_PATH` and `NIKTO_EXECUTABLE_SHA256`
- Existing `EVIDENCE_KEY` configuration for authenticated encryption

Do not set the candidate flag on a service whose platform cannot deny direct scanner egress and isolate the worker from the control plane. The reference is an audit pointer, not a firewall implementation or a self-verifying proof. The service does not currently discover or independently attest a Render network policy.

## Manual acceptance steps

1. Deploy the worker only into a private scanner network with default-deny outbound rules. Allow only the required control-plane/database/broker destinations and the per-job proxy's approved pinned target. Verify direct scanner sockets fail from inside the worker container.
2. Install one supported ZAP or Nikto version, record its license/edition status and exact version, and configure the absolute executable path and SHA-256 digest as deployment secrets/config.
3. Use a disposable app that the participant owns. Add only its exact origin and path to a versioned live scope, set a short validity window and low request rate, and record the authorization reference. No organizer target or authorization is presumed.
4. For passive ZAP, upload a HAR from that app as encrypted evidence, approve `zap.passive.v1` bound to its evidence ID and scope, and verify the completed run created one pending import without any target requests.
5. For active ZAP or Nikto, create an action with explicit impact and reset instructions, have a human reviewer approve that exact action, then verify the run stayed inside the scope and that cancellation stops the process and egress.
6. Normalize each pending import. Review the source run, scanner version, capture time, evidence hash, scope, parser limitations, and asset mapping. Do not treat an alert or server configuration observation as a confirmed vulnerability.
7. Preserve the actual run ID, UTC start/end times, version, artifact SHA-256, authorization reference, firewall verification reference, and review decision. Those records are required before marking either integration live or closing T25/T26.

## Not verified in this repository session

No scanner binaries, disposable authorized target, private worker network, Render deployment, firewall proof, license evidence, or genuine captured output was available. Unit tests use synthetic test-only data. These limitations prevent a live acceptance claim and issue closure.

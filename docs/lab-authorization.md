# Organizer lab authorization - T04

The participant confirmed **no organizer lab authorization yet**. T04 remains open for actual authorized provisioning, health and reset evidence. The code delivered here checks a proposed manifest offline and never contacts a target.

## Manual input required

Obtain a dated organizer-provided scope document/reference with exact targets, exclusions, allowed techniques/profiles, validity, rate limits and credential handling. If a local lab is allowed, obtain explicit permission and permitted training targets. Do not paste passwords/API keys into public issues; retain private evidence/credentials outside source.

Create ignored `config/authorized-lab.yaml` only after reviewing the real document. `config/authorized-lab.example.yaml` is pending, contains reserved documentation data and cannot authorize any assessment. The authorization record must reference the organizer source, its SHA-256 and the human who reviewed it. That reference is not a digital signature or proof of organizer identity; source authenticity remains a human responsibility until a trusted identity mechanism is implemented.

## Offline readiness check

```powershell
uv run python scripts/check_lab.py --target assessment.test --profile discovery
```

Without an actual manifest this returns exit code 2 and `missing-manifest`, with `live_execution_enabled: false`. With a proposed manifest, provide `--manifest` and `--authorization-document` private paths. It validates bounded YAML, exact targets, canonical addresses, network inclusion, exclusion precedence, permitted profiles, timezone-aware validity, reviewed source hash and positive bounded concurrency/rates. It performs no DNS lookup or network request. An authorization problem is distinguished from tooling, which is explicitly not checked by this command.

Even a consistent manifest does not enable scans. Actual DNS/redirect validation, service identity, egress enforcement, approvals and cancellation belong to T13-T19/T28. Controlled offensive validation is always denied here until its separate action-bound human gate exists. No process may interpret `ready: true` as permission to bypass those runtime controls.

## Provisioning and acceptance checklist

- [ ] Genuine organizer permission recorded and source authenticity reviewed.
- [ ] Exact authorized local/remote targets and credentials available through a private mechanism.
- [ ] Control plane, worker egress and target network isolated with actual routing/deny evidence.
- [ ] Permitted health check run and recorded.
- [ ] Reset/teardown followed; only target side effects cleared, original evidence/audit/report references preserved.
- [x] Missing/pending/expired/mismatched/out-of-scope/excluded/profile cases denied by offline contract tests.

Rates in the example are illustrative, not organizer-approved values. The implementation caps concurrent jobs at eight as a defensive prototype bound; organizer limits may be lower and always take precedence. No scanner output or positive lab proof is manufactured to complete this checklist.

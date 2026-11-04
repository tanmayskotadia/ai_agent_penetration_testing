# ADR 0005 - Configurable model and truthful tool contracts

**Status:** accepted for implementation; 4 November 2026.

## Decision

Use a provider-neutral model adapter with explicit disabled state, endpoint/model identity, schema/prompt versions, time/token/step budgets and approved data policy. Do not select a model through marketing assumptions: T42 compares available permitted models on held-out reasoning/grounding cases. No raw secrets or unapproved sensitive output is sent externally.

Each of seven adapters exposes health/capability/plan validation/submit/status/cancel/collect/normalize operations only where supported. Registry states are live, import-only, planned or unsupported, with edition/version/license/format limitations. Minimum acceptance needs three working integrations or supported imports, including network/web, not seven imaginary live integrations.

## Alternatives and consequences

Hard-wiring a hosted model assumes credentials/privacy/cost and blocks offline work. Arbitrary tools inside an agent bypass permissions. Pretending commercial APIs are interchangeable creates false integration claims. Explicit contracts need more version/error handling but enable honest degradation and model-unavailable evidence-only review.

T06/T12/T20/T25-T42 implement; T35/T48/T62 verify format, claim-grounding and unsafe-output cases. No current model quality, tool entitlement or calibrated confidence is asserted.

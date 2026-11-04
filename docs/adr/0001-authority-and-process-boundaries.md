# ADR 0001 - Separate reasoning, authority and execution

**Status:** accepted for implementation; 4 November 2026. **Scope:** T02.

## Context

The PDF demands contextual decisions, lab-only scope and explicit human approval before offensive validation. Untrusted target content and model output cannot grant permission. Running scanners inside API handlers also obscures timeouts, concurrency and fault recovery.

## Decision

Use React/TypeScript for analyst interaction, FastAPI for authenticated domain policy, a bounded LangGraph reasoning graph for structured suggestions, and isolated workers for approved adapter execution. The control-plane coordinator, not the LLM or browser, verifies current scope, profiles, actor/grants and job attempt state. Workers receive restricted job envelopes and network reachability.

## Alternatives

- A fixed scanner chain with chat narration: easy to build but fails adaptive reasoning goals.
- An unrestricted autonomous agent with shell tools: weak scope/approval boundary and unnecessary risk.
- A microservice/agent per concern: excessive coordination for the initial product.

## Consequences and verification

Typed contracts and duplicate policy checks require deliberate engineering, but make responsibility inspectable. Human-review interrupts aid UX; they are not security gates. T10/T13-T19/T37-T42 implement boundaries; T62/T63 verify bypass and recovery cases. See architecture I01-I04 and B01-B04. No runtime claim is made by this ADR.

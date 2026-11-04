# ADR 0003 - Broker transport with conservative external execution

**Status:** accepted for implementation; 4 November 2026.

## Decision

Use Celery/Redis to deliver job-ID wakeups to bounded workers. PostgreSQL attempts/leases are authoritative. On an authenticated worker claim, atomically check scope/profile/stop state, rate budget and exact grant, then consume the required single-use approval for one attempt. Redelivery attaches/exits rather than starts another active attempt.

Classify retries: pure parsing/rendering and external status reads can be retried with stable IDs and limits; active submission cannot be retried blindly. Store external run ID early. A crash that might follow a tool side effect yields reconciliation or unknown/manual review, not another scan. Tune/test transport visibility and acknowledgement settings during implementation.

## Alternatives and consequences

Synchronous API execution blocks lifecycle management. An assumed exactly-once broker guarantee is false for external side effects. Universal automatic retries can duplicate consequential work. Conservative unknown states reduce availability but preserve human control. Database queue claims may use row locking; outbox delivery alone does not authorize execution.

T19/T21/T23 implement; T63 injects failures before/after submission, collection and acknowledgement. Source semantics: [Celery tasks](https://docs.celeryq.dev/en/stable/userguide/tasks.html), [Redis caveats](https://docs.celeryq.dev/en/stable/getting-started/backends-and-brokers/redis.html).

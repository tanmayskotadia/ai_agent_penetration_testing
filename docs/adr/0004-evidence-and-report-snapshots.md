# ADR 0004 - Private originals, immutable report input and structured PDF

**Status:** accepted for implementation; 4 November 2026.

## Decision

Preserve genuine original tool bytes in private storage with server-generated IDs, hashes, source pointers and controlled retrieval. Quarantine untrusted imports before parsing. Keep sanitized snippets separate from originals, observations separate from inferences, and occurrences separate from consolidated findings. Snapshot all report source revisions before export.

Use ReportLab structured PDF generation with packaged resources and escaped limited text. The renderer has no external network and accepts only registered assets, never user-supplied paths. JSON/CSV and optional semantically supported SARIF derive from the same snapshot.

## Alternatives and consequences

Public object URLs or mutable summary-only findings break confidentiality/traceability. An unrestricted HTML/browser renderer adds resource-fetch and markup complexity. ReportLab reduces that exposure and dependencies but still needs safe text/image handling, fonts, pagination and visual QA. This is a refinement of the earlier proposed HTML-to-PDF direction, not a change to required report contents.

Object writes and DB metadata are reconciled rather than claimed atomic. Never delete referenced evidence during orphan cleanup. T08/T11/T43/T55-T60 implement; source-integrity, authorization and complete-page review remain mandatory. [ReportLab documentation](https://docs.reportlab.com/reportlab/userguide/ch1_intro/).

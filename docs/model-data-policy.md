# Model, credentials and assessment-data policy - T06

**Current implementation:** no model client/endpoint is configured; the foundation reports model processing disabled. No model reasoning result, confidence calibration or provider privacy guarantee is claimed. Model selection/evaluation is T42; domain authorization and evidence controls are later implementation issues.

## Data classes and allowed processing

| Class | Examples | Default handling |
|---|---|---|
| Public source/configuration | Public advisories, project docs, sanitized capability descriptions | May be used for development; preserve source/date and applicability |
| Test-only handcrafted input | Parser/policy tests with reserved targets and no genuine scan proof | Keep clearly labelled; never use as actual scanner evidence or benchmark ground truth |
| Private operational data | Lab targets, source scan artifacts, HTTP messages, internal topology, reviewer context | Private access-controlled storage; exclude from public repo/issues/logs; no external model transmission by default |
| Secrets | Passwords, session tokens, scanner/API keys, license keys, application signing secrets | Runtime injection only; never send to model/browser variables or log/commit them |
| Reviewed derivatives | Redacted evidence snippets and authorized report excerpts | Allow only under explicit assessment/provider policy, with source references and redaction review |

No boolean status in a model response can approve data transfer or execution. A local model also requires configured access/storage/log policy; locality alone does not make sensitive processing safe.

## Before enabling a model

Record exact provider/endpoint/model/version, operator authorization, data classes, retention/training/location terms as applicable, permitted destinations, prompt/schema versions, request/response/step budgets and timeouts. Have the participant choose/approve the policy for real sensitive data. Store credential values only in ignored local configuration or a separately chosen runtime secret mechanism; do not paste them into this chat or public GitHub issues.

Only send allowlisted sanitized fields. Preserve original source evidence privately; a prompt summary is not canonical fact. Banners, reports and retrieved advisory text remain untrusted. Require typed proposals with evidence IDs and uncertainty; do not expose arbitrary shell, self-approval, direct scanner APIs or unrestricted retrieval/network access to the model.

## Storage, retention and logs

The foundation has no scan-evidence retention service yet. T08/T66 must implement private object access, digest checks, retention/restore and snapshot-aware deletion. Do not claim that a written policy already enforces those controls. Until then, do not add real scan artifacts to the public repository.

Preserve credentials in `.env` generated locally (ignored); the generator refuses overwrite and prints no values. Windows file access still depends on the user's actual directory ACLs. CI generates disposable credentials, masks the application secret and uses isolated temporary services. Logs should contain IDs/status/errors rather than raw private messages, secrets or full prompts; future redaction must be verified with labelled canaries.

Retention must distinguish raw originals, derivatives, audit, model/checkpoint context and delivered report snapshots. Do not delete evidence referenced by retained reports under an orphan-cleanup policy. Choose actual retention periods with the organizer/data owner rather than inventing universal periods here.

## Outage and review behavior

Without an approved endpoint, keep model actions disabled. On future model failure, preserve evidence and permit analyst review/evidence-only reporting rather than inventing a replacement conclusion. Confidence probabilities require independent representative outcomes and T48 evaluation. Source facts, hypotheses, unknowns, reviewer decisions and confirmed validation must stay distinct.

Manual model/key work is not required to finish T06's policy/inventory. It becomes required before real model evaluation/data processing, and it must use a private configuration path.

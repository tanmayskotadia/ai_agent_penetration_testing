# Bounded evidence-driven reasoning — T38 / issue #52

## Behavior and architecture

The authenticated `POST /api/v1/assessments/{assessment_id}/reasoning/replan` endpoint implements this bounded sequence: current-scope evidence summary → server-owned candidate generation → one Groq text-model call → schema, capability and citation filtering → grounded proposal and immutable draft revision → separate human plan review. No tool functions, scanner commands, target URLs, redirects, model-controlled destinations or automatic execution are exposed to the model. This is a single-pass staged planner; autonomous graph loops and durable multi-step memory remain future work (#55). The PDF requires contextual reasoning, not a particular orchestration library.

Only a human reviewer/admin can authorize the external reasoning request. `allow_external_processing=true` and a `data_policy_reference` matching the operator's configured policy are both required. Every source must belong to the assessment and exact current scope, and have a reviewed, unexpired derivative. The derivative is checked for access but its raw text is not transmitted. Context contains sanitized normalized titles, opaque observation/asset/evidence IDs, observed service fields, timestamps, source-reported metadata, available candidate IDs, capability modes, failed sources, conflicts and same-scope prior tool names. The sanitized user request is also transmitted and may still contain private context; this is not an anonymity guarantee. The operator must approve the provider's data terms for the intended inputs.

An observed HTTP service can justify requesting a missing recorded ZAP/Nikto source. SSH-only evidence does not produce a web-import action. Failed sources and conflicting port states or same-asset/CVE values allow only review/stop. Existing normalized same-scope/asset tool sources suppress repeated imports, including sources not selected as prompt input. Identity matching uses exact stored asset IDs; it does not infer equivalence between different host/web assets. Unsupported capabilities are filtered out without pretending their status is verified. Candidate parser availability and genuine integration status remain separate.

The model must select a supplied candidate, cite its real supporting observations, explain expected information gain, list every unchosen candidate with reasons/citations, disclose assumptions and give stop conditions. Invalid citations, unknown actions, extra fields, incomplete alternatives, unsupported identifiers, changed scope/capabilities or malformed output produce a blocked plan. Unknown validation states are not automatically source contradictions. Benefits and rationales remain `ai-inference`, never confirmed findings or factual report prose. The stored proposal passes through #53 grounding and retains source pointers, context digest and attributable audit history.

Success creates a `request-only` draft containing one fixed recorded-import request. Review/stop creates a blocked plan with no actionable steps. Approving a draft through #51's digest-bound plan review still grants no execution permission; active validation remains separately prohibited without its action approval and isolated runtime. Model failure never creates a replacement conclusion, approval or confirmed vulnerability.

## Budgets and failure behavior

- One provider invocation per endpoint request; no automatic retry or model loop.
- Default 3 adaptive revisions per conversation and 20 provider attempts per assessment. Configuration bounds are enforced; a new conversation does not reset the assessment budget.
- An action fingerprint binds the exact scope revision, evidence observations, capability snapshot, failures/conflicts, prior same-scope tools and permitted candidates. It excludes conversational wording and conversation IDs. Rephrasing the same evidence/action set therefore reuses the stored plan instead of spending another provider call.
- A provider-invoked attempt that fails is persisted with its stable failure code. The same action fingerprint is blocked across new conversations until a human reviewer explicitly sets `retry_failed_attempt: true`; the retry still consumes the assessment call and conversation revision budgets. Successful decisions cannot be retried through this override. Missing configuration or policy approval does not consume a provider-call budget because no provider invocation occurred.
- Existing normalized same-scope tool results suppress repeat imports by exact asset ID and tool. Failed sources/conflicting evidence suppress import actions and leave source review as the only generated alternative. No scanner execution or active-action retry is possible in this planner.
- At most 25 selected revisions, 200 observations and 1,000 current-scope source-history rows; larger contexts abstain instead of silently reasoning over a partial history.
- Fixed TLS endpoint `api.groq.com/openai/v1/chat/completions`; no redirects or proxy-derived model destinations. Compound/tool systems are rejected as model choices.
- Default 20-second network timeout/deadline checks, 2,048 completion tokens, 64 KiB request/response bounds, and 16,000 characters of model content. Streaming/tool-call/truncated or mismatched-model responses are rejected. The provider's own rate/account limits may be lower.
- Provider errors expose only stable codes and sanitized HTTP/known error categories, never credentials, prompts or raw response bodies. Idempotent receipt replay avoids ordinary duplicate requests. This synchronous bounded call does not claim exactly-once remote inference across a process/database crash; durable recovery and wider efficiency controls remain #59/#55 work.

## API and review procedure

1. Import and normalize the permitted source artifacts; retain the returned `result_revision_id`. Create/inspect a scope using the existing scope API.
2. Generate the source derivative with `POST .../evidence/{evidence_id}/redaction`, inspect it, then record a human review through `POST .../evidence/{evidence_id}/redaction-review`. Do not mark private content safe without checking it.
3. Send the replan request with standard bearer authentication, UUID `X-Request-ID`, and `Idempotency-Key`:

```json
{
  "scope_id": "<current scope UUID>",
  "scope_revision": 1,
  "conversation_id": "<conversation UUID>",
  "request_text": "Explain the next justified recorded-evidence review step",
  "result_revision_ids": ["<normalized result revision UUID>"],
  "allow_external_processing": true,
  "data_policy_reference": "<operator-approved policy reference>",
  "retry_failed_attempt": false
}
```

`retry_failed_attempt` is optional and defaults to `false`. Set it to `true` only after reviewing a prior persisted provider failure and deciding that a manual retry is justified. It does not bypass data policy, scope, evidence review, per-conversation revision limits, or the assessment call budget.

4. Inspect `request.proposal.decision`, its source citations, candidates/rejected alternatives, assumptions, stop conditions and provider trace. `model_called` is true only for a real provider response; recorded test-provider responses explicitly remain `test-only`.
5. Review a draft using `POST .../plans/{plan_id}/reviews` with its revision and `request.review_digest`. Reload plans through the existing plan list and decisions through plan reviews. UI controls consuming these contracts remain #54/#58; Swagger `/docs` exposes the endpoint now.

## Private configuration and Render

Set `ADAPTIVE_PLANNER_ENABLED=true`, `GROQ_API_KEY` privately, `GROQ_MODEL` to a model available to your account, and `MODEL_DATA_POLICY_REFERENCE` to your approved policy reference. Optional budget variables are listed in `.env.example`. Missing configuration leaves the planner blocked. Do not commit a key or copy it into an issue, CLI argument, frontend variable, report or screenshot.

On 6 November 2026, the configured Llama example was not in this account's authenticated model list. The acceptance run uses Groq-hosted `openai/gpt-oss-120b`. Keep the model configurable and verify account availability; changing the configured model does not change tool permissions. The transport uses Groq JSON-object mode plus local strict Pydantic validation, so JSON syntax alone never establishes a valid decision. Sources: [Groq API reference](https://console.groq.com/docs/api-reference), [structured output and model support](https://console.groq.com/docs/structured-outputs).

For production hosting, enter the values in **Render → dataops → Environment**, save and redeploy. The private desktop `.env` used for acceptance is not deployed and is never pushed. Account/hosting activation is separate from proving the #52 software/provider path. Keep real sensitive data disabled until its data policy is approved.

## Verification and limits

`tests/test_adaptive_planner.py` covers different observed services, conflicts, unavailable tools, no evidence, unreviewed sources, consent, idempotency, action-fingerprint repeat suppression across paraphrased requests, explicit bounded retry after a provider failure, step limits and stale scope. `tests/test_model_provider.py` covers the fixed TLS destination, no redirects/tools, bounded output, truncation, rate limit and secret-safe failure handling. These fixtures and recorded-provider responses are explicitly synthetic.

`evaluation/replanning-cases.json` defines the scenario and rationale rubric. `scripts/verify_groq_acceptance.py` exercises the complete normalized-import → real Groq → grounded plan path against a disposable SQLite database, never production data or real targets. It requires a private env file and explicit `--approve-synthetic-data`. It writes only synthetic-case decisions, model/usage metadata, response hashes, context/code/prompt hashes and limitations. Use `--interval-seconds 20` when pacing is needed; failed cases are not automatically retried.

```powershell
$env:GROQ_MODEL='openai/gpt-oss-120b'
uv run python scripts/verify_groq_acceptance.py --env-file <private-env-path> --approve-synthetic-data --interval-seconds 20 --output tmp/groq-acceptance.json
```

The dated live record is `docs/verification/T38-live-acceptance.json`; its model responses are real, while its source inputs are synthetic. This demonstrates the bounded reasoning path and policy filter, not genuine scanner coverage, calibrated confidence, independently reviewed security accuracy, production enablement or T30 acceptance.

import { useEffect, useMemo, useRef, useState } from "react";
import { mutate } from "./api-client";
import type { ApiSchemas } from "./generated/api";
import { EvidenceInspector } from "./EvidenceInspector";

type Scope = ApiSchemas["ScopeVersion"] & { id: string };
type Plan = ApiSchemas["WorkflowResource"];
type Revision = {
  id: string;
  run_id: string;
  revision: number;
  tool: string;
  state: string;
  mode: string;
  captured_at: string;
  evidence_id: string;
  source_sha256: string;
  normalization_id: string;
  observation_ids: string[];
  scope_id?: string;
  scope_revision?: number;
};
type SourceReview = { normalization_id: string; decision: string; provenance: string };
type Coverage = Record<string, unknown>;
type Row = Record<string, unknown>;
type Inspector = ApiSchemas["EvidenceInspectorView"];

const asRecord = (value: unknown): Row =>
  value !== null && typeof value === "object" && !Array.isArray(value) ? value as Row : {};
const asList = (value: unknown): Row[] =>
  Array.isArray(value) ? value.filter(item => item !== null && typeof item === "object") as Row[] : [];
const stringList = (value: unknown): string[] => Array.isArray(value) ? value.map(String) : [];
function hasRetryableProviderFailure(plans: Plan[], latest: Plan | null | undefined): boolean {
  if (!latest) return false;
  const latestProposal = asRecord(latest.request.proposal);
  const latestProvider = asRecord(latestProposal.provider);
  const latestDecision = asRecord(latestProposal.decision);
  const latestBlockers = stringList(latestProposal.blockers);
  if (latestBlockers.includes("prior-provider-failure; explicit-reviewer-retry-required")) return true;

  const fingerprint = latest.request.action_fingerprint;
  if (typeof fingerprint !== "string" || !fingerprint) return false;
  const sameAction = plans.filter(plan => plan.request.adaptive === true
    && plan.request.action_fingerprint === fingerprint);
  // A successful prior decision takes precedence: the server will not repeat it.
  if (sameAction.some(plan => Object.keys(asRecord(asRecord(plan.request.proposal).decision)).length > 0)) {
    return false;
  }
  return sameAction.some(plan => {
    const proposal = asRecord(plan.request.proposal);
    return asRecord(proposal.provider).provider_invoked === true
      && Object.keys(asRecord(proposal.decision)).length === 0;
  }) || (latestProvider.provider_invoked === true && !Object.keys(latestDecision).length);
}
const displayTime = (value: string) => {
  const time = new Date(value);
  return Number.isNaN(time.valueOf()) ? value : time.toLocaleString();
};

function explainBlocker(code: string): string {
  const messages: Record<string, string> = {
    "provider-not-configured": "The hosted model provider is not configured. Ask the service operator to check its private provider settings; do not paste a key into this page.",
    "provider-rate-limited": "The provider rate-limited this request. No recommendation was accepted; check the provider status, then use the explicit retry action only if appropriate.",
    "provider-unavailable-or-invalid-response": "The provider was unavailable or returned an invalid response. No recommendation was accepted; inspect the sanitized trace before deciding whether to retry.",
    "external-data-policy-approval-required": "The consent or policy reference did not match the server-approved policy. No model request was made. Confirm the approved reference with your service operator.",
    "reviewed-unexpired-evidence-required": "A selected source needs a current human-reviewed redacted derivative. Inspect the evidence below, create the redacted derivative, then review it.",
    "scope-changed-during-reasoning": "The scope changed while reasoning was in progress. Reload the current scope and evidence before trying again.",
    "prior-provider-failure; explicit-reviewer-retry-required": "The previous provider attempt failed. Review the trace, then choose the explicit retry action if another call is appropriate.",
    "no-observed-evidence; stop-and-request-input": "No normalized observations were available. Import or select eligible evidence before asking for a recommendation.",
    "model-output-or-evidence-not-valid": "The provider response or its citations failed validation. The response was rejected; no recommendation was accepted.",
    "model-requested-review-or-stop": "The model recommended review or stopping. No new action is proposed.",
    "unchanged-evidence-or-action; reuse-prior-plan-instead-of-repeating-model-call": "The selected evidence and available actions match a prior plan. Review that saved plan instead of spending another provider call.",
  };
  return messages[code] ?? code.replaceAll("-", " ");
}

export function ReplanPanel({ assessmentId, token, coverage, onChanged }: {
  assessmentId: string;
  token: string;
  coverage: Coverage | null;
  onChanged: () => void;
}) {
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [revisions, setRevisions] = useState<Revision[]>([]);
  const [plans, setPlans] = useState<Plan[]>([]);
  const [selectedRevisionIds, setSelectedRevisionIds] = useState<string[]>([]);
  const [inspectors, setInspectors] = useState<Record<string, Inspector | null>>({});
  const [inspectorReload, setInspectorReload] = useState(0);
  const [requestText, setRequestText] = useState("");
  const [policyReference, setPolicyReference] = useState("");
  const [allowExternalProcessing, setAllowExternalProcessing] = useState(false);
  const [result, setResult] = useState<Plan | null>(null);
  const [status, setStatus] = useState("");
  const [loadError, setLoadError] = useState("");
  const [busy, setBusy] = useState(false);
  const [retry, setRetry] = useState(false);
  const [reviewedBeforeNewConversation, setReviewedBeforeNewConversation] = useState(false);
  const [conversationId, setConversationId] = useState<string>(() => crypto.randomUUID());
  const pendingMutation = useRef<{ body: string; key: string } | null>(null);
  const active = useRef(true);
  const base = `/api/v1/assessments/${encodeURIComponent(assessmentId)}`;

  const currentScope = useMemo(
    () => [...scopes].sort((a, b) => b.revision - a.revision)[0],
    [scopes],
  );
  const eligible = useMemo(
    () => revisions
      .filter(row => row.state === "normalized" && row.scope_id === currentScope?.id)
      .sort((a, b) => b.captured_at.localeCompare(a.captured_at)),
    [revisions, currentScope?.id],
  );
  const selected = useMemo(
    () => eligible.filter(row => selectedRevisionIds.includes(row.id)),
    [eligible, selectedRevisionIds],
  );
  const sourceReviews = useMemo(() => new Map(
    asList(coverage?.source_reviews).map(value => [String(value.normalization_id ?? ""), value as SourceReview]),
  ), [coverage]);
  const selectedEvidenceIds = useMemo(
    () => [...new Set(selected.map(row => row.evidence_id).filter(Boolean))],
    [selected],
  );

  async function get<T>(path: string, signal?: AbortSignal): Promise<T> {
    const response = await fetch(base + path, { signal, cache: "no-store", headers: { Authorization: `Bearer ${token}` } });
    if (!response.ok) {
      const body = asRecord(await response.json().catch(() => ({})));
      throw Object.assign(new Error(String(body.message ?? `Workspace request failed (${response.status}).`)), { status: response.status });
    }
    return response.json() as Promise<T>;
  }

  async function reload() {
    setLoadError("");
    const [nextScopes, nextRevisions, nextPlans] = await Promise.all([
      get<Scope[]>("/scopes"), get<Revision[]>("/result-revisions"), get<Plan[]>("/plans"),
    ]);
    if (!active.current) return;
    setScopes(nextScopes);
    setRevisions(nextRevisions);
    setPlans(nextPlans);
    const latest = [...nextScopes].sort((a, b) => b.revision - a.revision)[0];
    const adaptivePlans = nextPlans.filter(plan => plan.request.adaptive === true);
    const latestAdaptivePlan = adaptivePlans
      .sort((a, b) => (b.revision ?? 0) - (a.revision ?? 0))[0];
    const previousConversation = latestAdaptivePlan?.request.conversation_id;
    if (typeof previousConversation === "string") setConversationId(previousConversation);
    if (!requestText.trim() && typeof latestAdaptivePlan?.request.request_text === "string") {
      setRequestText(latestAdaptivePlan.request.request_text);
    }
    if (!policyReference.trim() && typeof latestAdaptivePlan?.request.data_policy_reference === "string") {
      setPolicyReference(latestAdaptivePlan.request.data_policy_reference);
    }
    setRetry(hasRetryableProviderFailure(nextPlans, latestAdaptivePlan));
    if (latest) {
      const validIds = new Set(nextRevisions
        .filter(row => row.state === "normalized" && row.scope_id === latest.id)
        .map(row => row.id));
      const savedSelection = stringList(latestAdaptivePlan?.request.result_revision_ids)
        .filter(id => validIds.has(id));
      setSelectedRevisionIds(current => {
        const currentSelection = current.filter(id => validIds.has(id));
        return currentSelection.length ? currentSelection : savedSelection;
      });
    } else setSelectedRevisionIds([]);
  }

  useEffect(() => {
    active.current = true;
    void reload().catch(error => {
      if (active.current) setLoadError(error instanceof Error ? error.message : "Replanning data is unavailable.");
    });
    return () => { active.current = false; };
  }, [assessmentId, token]);

  useEffect(() => {
    let cancelled = false;
    const evidenceIds = selectedEvidenceIds;
    if (!evidenceIds.length) { setInspectors({}); return; }
    void Promise.all(evidenceIds.map(async evidenceId => {
      try {
        const metadata = await get<Inspector>(`/evidence/${encodeURIComponent(evidenceId)}/inspector`);
        return [evidenceId, metadata] as const;
      } catch {
        return [evidenceId, null] as const;
      }
    })).then(values => {
      if (!cancelled) setInspectors(Object.fromEntries(values));
    });
    return () => { cancelled = true; };
  }, [assessmentId, token, selectedEvidenceIds.join("|"), inspectorReload]);

  async function submit(retryFailedAttempt: boolean) {
    if (!currentScope || !selected.length || !requestText.trim()) return;
    const request = {
      scope_id: currentScope.id,
      scope_revision: currentScope.revision,
      conversation_id: conversationId,
      request_text: requestText.trim(),
      result_revision_ids: selected.map(row => row.id),
      allow_external_processing: allowExternalProcessing,
      data_policy_reference: policyReference.trim() || null,
      retry_failed_attempt: retryFailedAttempt,
    };
    const serialized = JSON.stringify(request);
    if (!pendingMutation.current || pendingMutation.current.body !== serialized) {
      pendingMutation.current = { body: serialized, key: crypto.randomUUID() };
    }
    setBusy(true);
    setRetry(false);
    setStatus("Saving a bounded reasoning request…");
    try {
      const saved = await mutate<Plan>("", `${base}/reasoning/replan`, token, request, pendingMutation.current.key);
      pendingMutation.current = null;
      setResult(saved);
      setPlans(current => [...current.filter(plan => plan.id !== saved.id), saved]);
      const proposal = asRecord(saved.request.proposal);
      const blockers = stringList(proposal.blockers);
      setStatus(blockers.length
        ? `Saved blocked plan ${saved.id}. ${explainBlocker(blockers[0])}`
        : `Saved plan ${saved.id}. AI recommendation is ready for separate human review.`);
      setRetry(hasRetryableProviderFailure([...plans.filter(plan => plan.id !== saved.id), saved], saved));
      setConversationId(String(saved.request.conversation_id ?? conversationId));
      setInspectorReload(value => value + 1);
      setPlans(current => current.map(plan => plan.id === saved.id ? saved : plan));
      onChanged();
    } catch (error) {
      const failure = error as Error & { status?: number };
      if (failure.status === 409) {
        const conversationBudgetExhausted = failure.message.includes("Adaptive plan budget exhausted");
        if (conversationBudgetExhausted) {
          setRetry(hasRetryableProviderFailure(plans, latestPlan));
          setStatus("This conversation reached its adaptive-plan limit. No provider call was made for this request. Review the saved plan above, acknowledge the review, then start a new conversation. The assessment-wide provider-call limit still applies.");
        } else {
          setStatus(`The server rejected this stale or over-budget request. ${failure.message} Your request text and consent stay in this form; reload the current scope before trying again.`);
        }
        await reload().catch(() => {});
      } else {
        setStatus(failure.message || "The request failed. Your inputs remain available; retry only after reviewing the reason.");
      }
    } finally { setBusy(false); }
  }

  const latestPlan = result ?? plans
    .filter(plan => plan.request.adaptive === true)
    .sort((a, b) => (b.revision ?? 0) - (a.revision ?? 0))[0] ?? null;
  const proposal = asRecord(latestPlan?.request.proposal);
  const decision = asRecord(proposal.decision);
  const provider = asRecord(proposal.provider);
  const citations = stringList(decision.observation_ids);
  const candidates = asList(proposal.candidates);
  const rejected = asList(decision.rejected_alternatives);
  const blockers = stringList(proposal.blockers);
  const testOnly = provider.provider_source === "test-only" || String(decision.rationale ?? "").includes("TEST ONLY");

  return <section className="replan-panel" aria-labelledby="evidence-replan">
    <div className="replan-heading"><div><p className="eyebrow">EVIDENCE → NEXT STEP</p><h3 id="evidence-replan">Replan from evidence</h3></div><span className="badge">AI inference · human review required</span></div>
    <p>Ask the configured model to reconsider a bounded next step using normalized observations and human-reviewed redacted source snippets. It cannot run a scanner, authorize an action, or confirm a vulnerability.</p>
    {loadError && <p role="alert">{loadError}</p>}
    <div className="replan-context" aria-label="Current scope context">
      <strong>Active scope</strong>
      <span>{currentScope ? `Revision ${currentScope.revision} · ${currentScope.targets.join(", ") || "no targets recorded"}` : "No scope recorded yet."}</span>
      {currentScope?.exclusions?.length ? <span>Excluded: {currentScope.exclusions.join(", ")}</span> : null}
      <span>Eligible evidence: {eligible.length} normalized result revision(s) in this exact scope.</span>
    </div>
    <fieldset disabled={busy || Boolean(loadError)}>
      <legend>Select evidence for this decision</legend>
      {eligible.length === 0
        ? <p>No normalized evidence revisions match the active scope. Import permitted evidence in the Evidence stage, then refresh this panel. Quarantined and older-scope results are not eligible.</p>
        : <div className="replan-revisions">{eligible.slice(0, 50).map(revision => {
          const sourceReview = sourceReviews.get(revision.normalization_id);
          const selectedHere = selectedRevisionIds.includes(revision.id);
          return <label className="replan-revision" key={revision.id}>
            <input type="checkbox" checked={selectedHere} onChange={event => setSelectedRevisionIds(current => event.target.checked
              ? current.length < 25 ? [...current, revision.id] : current
              : current.filter(id => id !== revision.id))} />
            <span><strong>{revision.tool} · result revision {revision.revision}</strong>
              <small>Captured {displayTime(revision.captured_at)} · {revision.observation_ids.length} observation(s) · source {revision.source_sha256.slice(0, 12)}…</small>
              <small>Provenance: {sourceReview
                ? sourceReview.provenance === "genuine-permitted-capture" && sourceReview.decision === "verify" ? "reviewer-asserted genuine permitted capture" : "reviewed as test-only or rejected"
                : "not reviewed; authenticity remains unverified"}</small>
            </span>
          </label>;
        })}</div>}
    </fieldset>
    {selected.map(revision => {
      const inspector = inspectors[revision.evidence_id];
      const sourceReview = sourceReviews.get(revision.normalization_id);
      return <article className="replan-evidence" id={`replan-evidence-${revision.evidence_id}`} key={revision.id}>
        <h4>{revision.tool} · evidence checks</h4>
        <p>Source provenance: {sourceReview ? `${sourceReview.decision} · ${sourceReview.provenance}` : "No source provenance review is recorded. Review it only if you personally checked the original and its permission basis."}</p>
        <p>Redaction: {inspector === undefined ? "Checking status…" : inspector?.reviewed_derivative_available ? "Human-reviewed derivative available" : "A current reviewed redacted derivative is required before provider context can be sent."}</p>
        <a href="#source-review">Go to source provenance review</a>
        <EvidenceInspector assessmentId={assessmentId} token={token} evidenceId={revision.evidence_id} onChanged={() => setInspectorReload(value => value + 1)} />
      </article>;
    })}
    {selected.length === 0 && <p className="replan-blocker">Select at least one normalized result from the active scope. Nothing is sent without an explicit evidence selection.</p>}
    <label>What should the model reconsider?
      <textarea value={requestText} onChange={event => setRequestText(event.target.value)} maxLength={1000} placeholder="For example: Given the current evidence, what is the safest useful next recorded-evidence step?" />
    </label>
    <label className="replan-consent"><input type="checkbox" checked={allowExternalProcessing} onChange={event => setAllowExternalProcessing(event.target.checked)} />
      <span>I explicitly consent to send bounded assessment context for the selected observations and my request to the configured external model provider. The server requires a current human-reviewed redacted derivative for each source, but does not send derivative text or raw originals. Do not include secrets in the request. This does not authorize a scan or action.</span>
    </label>
    <label>Approved data-processing policy reference
      <input value={policyReference} onChange={event => setPolicyReference(event.target.value)} maxLength={300} placeholder="Enter the exact reference approved for this hosted service" />
    </label>
    <p className="capability-description">The reference must match the service’s private approved policy setting. Never enter API keys, credentials, original source text, or secrets here.</p>
    <div className="replan-actions">
      <button disabled={busy || !currentScope || selected.length === 0 || !requestText.trim()} onClick={() => void submit(false)}>{busy ? "Reconsidering…" : "Replan from selected evidence"}</button>
      {retry && <button disabled={busy} onClick={() => void submit(true)}>Retry failed provider call</button>}
      <button disabled={busy} onClick={() => { void reload().then(() => setStatus("Reloaded active scope, normalized evidence, and saved plans." )).catch(error => setLoadError(error instanceof Error ? error.message : "Reload failed.")); }}>Reload scope and evidence</button>
    </div>
    {latestPlan?.state === "blocked" && retry && <div className="replan-new-conversation" role="group" aria-label="Start a fresh replanning conversation">
      <label><input type="checkbox" checked={reviewedBeforeNewConversation} onChange={event => setReviewedBeforeNewConversation(event.target.checked)} />
        I reviewed the saved blocked plan above. Start a separate conversation if I still need a new provider attempt.</label>
      <button disabled={busy || !reviewedBeforeNewConversation} onClick={() => {
        setConversationId(crypto.randomUUID());
        setAllowExternalProcessing(false);
        setReviewedBeforeNewConversation(false);
        setStatus("Started a new conversation. The prior plan remains saved. Review it, confirm external-processing consent again, then explicitly retry if another provider call is appropriate. Assessment-wide budget and duplicate-decision checks still apply.");
      }}>Start new conversation</button>
    </div>}
    <p role="status" aria-live="polite">{status}</p>
    {latestPlan && <article className="replan-result" aria-label="Saved replanning result">
      <div className="replan-heading"><h4>Saved plan revision {latestPlan.revision} · {latestPlan.state}</h4>{testOnly && <strong className="test-only-badge">TEST ONLY · synthetic response</strong>}</div>
      <p><strong>Information kind:</strong> {String(proposal.information_kind ?? "unknown; no accepted model decision")}. {provider.model_called === true ? "A configured provider returned this inference." : provider.provider_source === "test-only" ? "A test fixture produced this response; it is not real model output." : provider.provider_invoked === true ? "The provider was invoked, but no decision passed validation." : "No provider call is recorded."}</p>
      {blockers.length > 0 && <div role="alert"><strong>Blocked or abstained:</strong><ul>{blockers.map(code => <li key={code}>{explainBlocker(code)}</li>)}</ul></div>}
      {Object.keys(decision).length > 0 && <>
        <p><strong>Decision:</strong> {String(decision.decision)}{decision.selected_candidate_id ? ` · ${String(decision.selected_candidate_id)}` : ""}</p>
        <p><strong>Why it changed:</strong> {String(decision.rationale ?? "No validated rationale was returned.")}</p>
        <p><strong>Expected information gain:</strong> {String(decision.expected_information_gain ?? "unknown")}</p>
        <p><strong>Supporting observations:</strong> {citations.length ? citations.map((observationId, index) => {
          const source = selected.find(revision => revision.observation_ids.includes(observationId));
          return <span key={observationId}>{index > 0 ? ", " : ""}{source
            ? <a href={`#replan-evidence-${source.evidence_id}`}>{observationId} · inspect source</a>
            : observationId}</span>;
        }) : "none cited"}</p>
        <details><summary>Show rejected candidates and model assumptions</summary>
          <h5>Rejected candidates</h5>{rejected.length ? <ul>{rejected.map(item => <li key={String(item.candidate_id)}><strong>{String(item.candidate_id)}</strong>: {String(item.reason)} · observations {stringList(item.observation_ids).join(", ") || "none"}</li>)}</ul> : <p>None recorded.</p>}
          <h5>Assumptions</h5><ul>{stringList(decision.assumptions).map((item, index) => <li key={index}>{item}</li>)}</ul>
          <h5>Stop conditions</h5><ul>{stringList(decision.stop_conditions).map((item, index) => <li key={index}>{item}</li>)}</ul>
        </details>
      </>}
      <h5>Available bounded candidates</h5>
      {candidates.length ? <ul>{candidates.map(item => <li key={String(item.id)}><strong>{String(item.id)}</strong> · {String(item.action)}{item.tool ? ` · ${String(item.tool)}` : ""} · observations {stringList(item.observation_ids).join(", ") || "none"}</li>)}</ul> : <p>No safe candidate is available from the supplied evidence.</p>}
      <p><strong>Provider trace:</strong> {String(provider.provider ?? "provider unknown")} · {String(provider.model ?? "model unavailable")} · {provider.provider_invoked === true ? "invoked" : "not invoked"} · {provider.model_called === true ? "live provider response" : testOnly ? "test-only fixture" : "no live response"}</p>
      <p>Plan ID: <code>{latestPlan.id}</code> · Context SHA-256: <code>{String(latestPlan.request.context_sha256 ?? "not recorded")}</code></p>
      <p><a href="#assessment-setup">Open saved plan and its separate human review</a> · <a href="#assessment-timeline">Open audit trace</a></p>
      <p className="notice">A recommendation is a draft. A separate human plan review is required. It never grants execution permission or creates a scan job.</p>
      <details><summary>Exact stored plan and sanitized provider trace</summary><pre tabIndex={0}>{JSON.stringify(latestPlan, null, 2)}</pre></details>
    </article>}
  </section>;
}

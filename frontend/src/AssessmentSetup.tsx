import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import type { ApiSchemas } from "./generated/api";
import { mutate } from "./api-client";

type Plan = ApiSchemas["WorkflowResource"];
type Scope = ApiSchemas["ScopeVersion"];
type Row = Record<string, unknown>;
const object = (value: unknown): Row => value !== null && typeof value === "object" ? value as Row : {};
const list = (value: unknown): unknown[] => Array.isArray(value) ? value : [];
const lines = (text: string) => text.split("\n").map(value => value.trim()).filter(Boolean);

export function planReviewProblem(plan: Plan, plans: Plan[], scopes: Scope[], reviews: Plan[]): string {
  const scope = [...scopes].sort((a, b) => b.revision - a.revision)[0];
  if (!scope || plan.request.scope_id !== scope.id || plan.request.scope_revision !== scope.revision) return "Scope changed. Create a new plan against the current scope.";
  if (plans.some(other => other.request.conversation_id === plan.request.conversation_id && (other.revision ?? 1) > (plan.revision ?? 1))) return "Superseded by a newer conversation revision.";
  if (reviews.some(review => review.request.plan_id === plan.id)) return "Decision already recorded. Create a new revision to change the plan.";
  if (typeof plan.request.review_digest !== "string") return "This plan has no review digest. Create a new plan.";
  return "";
}

export function PlanCard({ plan, problem, decision, rationale, busy, onRationale, onReview }: {
  plan: Plan; problem: string; decision?: string; rationale: string; busy: boolean;
  onRationale: (value: string) => void; onReview: (decision: "approve" | "reject") => void;
}) {
  const proposal = object(plan.request.proposal);
  return <article className="review-card" aria-label={`Plan revision ${plan.revision}`}>
    <h4>Plan revision {plan.revision} · {plan.state}</h4>
    <p>Plan ID: {plan.id} · Scope ID: {String(plan.request.scope_id ?? "unknown")} · Scope revision: {String(plan.request.scope_revision ?? "unknown")}</p>
    <p>Information: {String(proposal.information_kind ?? "stored plan proposal")}</p>
    <p>Request: {String(proposal.request_text ?? plan.request.message ?? "not supplied")}</p>
    <p>Targets: {list(proposal.scope_targets).map(String).join(", ") || "not supplied"} · Exclusions: {list(proposal.scope_exclusions).map(String).join(", ") || "none recorded"}</p>
    <p>Permission boundary: reviewing this proposal records a decision only. Execution needs its own authorized scope and action approval.</p>
    {list(proposal.clarifications).map((value, index) => <p key={index}>Clarification: {String(value)}</p>)}
    {list(proposal.blockers).map((value, index) => <p key={index}>Blocker: {String(value)}</p>)}
    <ol>{list(proposal.steps).map((value, index) => {
      const step = object(value);
      return <li key={index}><strong>{String(step.tool ?? step.action ?? "Proposed step")}</strong><p>{String(step.rationale ?? "Rationale unavailable")}</p><p>Capability: {String(step.capability_status ?? "unknown")} · Mode: {String(step.mode ?? "unknown")}</p><p>Limits: {list(step.limits).map(String).join("; ") || "not supplied"}</p><p>Required input: {list(step.requires).map(String).join("; ") || "not supplied"}</p><p>Evidence references: {list(step.evidence).map(String).join("; ") || "none supplied"}</p></li>;
    })}</ol>
    {problem && <p role="status">{problem}</p>}{decision && <p>Recorded reviewer decision: {decision}</p>}
    <label>Review rationale<textarea value={rationale} maxLength={2000} onChange={event => onRationale(event.target.value)} /></label>
    <button disabled={busy || !!problem || plan.state !== "draft" || rationale.trim().length < 10} onClick={() => onReview("approve")}>Approve plan proposal</button>
    <button disabled={busy || !!problem || rationale.trim().length < 10} onClick={() => onReview("reject")}>Reject plan proposal</button>
    <details><summary>Exact persisted plan and source references</summary><pre tabIndex={0}>{JSON.stringify(plan, null, 2)}</pre></details>
  </article>;
}

export function AssessmentSetup({ assessmentId, token, onChanged }: { assessmentId: string; token: string; onChanged: () => void }) {
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [plans, setPlans] = useState<Plan[]>([]);
  const [reviews, setReviews] = useState<Plan[]>([]);
  const [targets, setTargets] = useState("");
  const [exclusions, setExclusions] = useState("");
  const [reference, setReference] = useState("");
  const [constraints, setConstraints] = useState("");
  const [message, setMessage] = useState("");
  const [conversation, setConversation] = useState("");
  const [rationales, setRationales] = useState<Record<string, string>>({});
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const [ready, setReady] = useState(false);
  const active = useRef(true);
  const base = `/api/v1/assessments/${encodeURIComponent(assessmentId)}`;
  async function get<T>(path: string): Promise<T> {
    const response = await fetch(base + path, { headers: { Authorization: `Bearer ${token}` } });
    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new Error(error.message ?? `Workspace request failed (${response.status}).`);
    }
    return response.json() as Promise<T>;
  }
  async function reload() {
    const [nextScopes, nextPlans, nextReviews] = await Promise.all([get<Scope[]>("/scopes"), get<Plan[]>("/plans"), get<Plan[]>("/plan-reviews")]);
    if (active.current) { setScopes(nextScopes); setPlans(nextPlans); setReviews(nextReviews); }
    return nextScopes;
  }
  useEffect(() => {
    active.current = true;
    void reload().then(values => {
      if (!active.current) return;
      const latest = [...values].sort((a, b) => b.revision - a.revision)[0];
      if (latest) { setTargets(latest.targets.join("\n")); setExclusions(latest.exclusions?.join("\n") ?? ""); setReference(latest.authorization_reference ?? ""); }
      setReady(true);
    }).catch(error => { if (active.current) setStatus(error instanceof Error ? error.message : "Setup unavailable."); });
    return () => { active.current = false; };
  }, [assessmentId, token]);
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!lines(targets).length) { setStatus("Enter at least one explicit target, one per line."); return; }
    if (!message.trim()) { setStatus("Describe the evidence you want to assess."); return; }
    setBusy(true); setStatus("Saving scope and plan...");
    try {
      const currentScopes = await get<Scope[]>("/scopes");
      const latest = [...currentScopes].sort((a, b) => b.revision - a.revision)[0];
      const same = latest && JSON.stringify(latest.targets) === JSON.stringify(lines(targets)) && JSON.stringify(latest.exclusions ?? []) === JSON.stringify(lines(exclusions)) && (latest.authorization_reference ?? "") === reference.trim() && latest.mode === "recorded-import";
      const scope = same ? latest : await mutate<Scope>("", base + "/scopes", token, { revision: (latest?.revision ?? 0) + 1, targets: lines(targets), exclusions: lines(exclusions), authorization_reference: reference.trim() || null, mode: "recorded-import" }, crypto.randomUUID());
      if (!active.current) return;
      const conversationId = conversation || crypto.randomUUID();
      const priorResults = await get<Row[]>("/result-revisions");
      if (!active.current) return;
      const priorIds = priorResults.slice(-100).flatMap(value => typeof value.id === "string" ? [value.id] : []);
      const plan = await mutate<Plan>("", base + "/plans/intake", token, { message: message.trim(), scope_id: scope.id, scope_revision: scope.revision, conversation_id: conversationId, constraints: lines(constraints), prior_result_revision_ids: priorIds }, crypto.randomUUID());
      if (!active.current) return;
      setConversation(conversationId); await reload();
      setStatus(plan.state === "blocked" ? "Plan saved with blockers. Read the clarification and revise your request." : "Plan saved. Review its exact revision and record your decision below.");
      onChanged();
    } catch (error) { if (active.current) { setStatus(error instanceof Error ? error.message : "Plan could not be saved. Reload current scope and retry."); await reload().catch(() => {}); } }
    finally { if (active.current) setBusy(false); }
  }
  async function review(plan: Plan, decision: "approve" | "reject") {
    setBusy(true);
    try {
      await mutate<Plan>("", base + `/plans/${plan.id}/reviews`, token, { plan_revision: plan.revision, plan_digest: plan.request.review_digest, decision, rationale: rationales[plan.id]?.trim() }, crypto.randomUUID());
      if (active.current) { await reload(); setStatus(`Plan ${decision === "approve" ? "approved" : "rejected"}. Decision recorded; execution is not authorized by this review.`); onChanged(); }
    } catch (error) { if (active.current) { setStatus(error instanceof Error ? error.message : "Review failed; refresh the plan."); await reload().catch(() => {}); } }
    finally { if (active.current) setBusy(false); }
  }
  return <section aria-labelledby="assessment-setup"><h3 id="assessment-setup">Assessment request and plan review</h3>
    <p>1. Record exact targets and exclusions. 2. Describe your request and constraints. 3. Review the saved plan and record a decision.</p>
    <p>Conversation and a supplied permission reference do not establish scan authorization. This setup prepares recorded evidence review.</p>
    <form onSubmit={event => void submit(event)}>
      <label>In-scope targets, one per line<textarea aria-label="In-scope targets, one per line" value={targets} onChange={event => setTargets(event.target.value)} placeholder="app.example.test or https://app.example.test" /></label>
      <label>Excluded targets, one per line<textarea value={exclusions} onChange={event => setExclusions(event.target.value)} /></label>
      <label>Source / authorization reference<input value={reference} maxLength={500} onChange={event => setReference(event.target.value)} /></label>
      <label>Assessment request<textarea aria-label="Assessment request" value={message} maxLength={4000} onChange={event => setMessage(event.target.value)} /></label>
      <label>Constraints, one per line<textarea value={constraints} onChange={event => setConstraints(event.target.value)} placeholder="For example: recorded evidence only" /></label>
      <button disabled={busy || !ready}>Create or revise plan</button>
    </form>
    <button disabled={busy} onClick={() => { void reload().then(() => { if (active.current) { setReady(true); setStatus("Reloaded current scope and persisted plans."); } }).catch(error => { if (active.current) setStatus(String(error)); }); }}>Reload current plans</button>
    <p role="status" aria-live="polite">{status}</p>
    {ready && !plans.length && <p>No saved plans yet. Enter your scope and request above.</p>}
    {plans.map(plan => <PlanCard key={plan.id} plan={plan} problem={planReviewProblem(plan, plans, scopes, reviews)} decision={reviews.find(value => value.request.plan_id === plan.id)?.request.decision as string | undefined} rationale={rationales[plan.id] ?? ""} busy={busy} onRationale={value => setRationales(current => ({ ...current, [plan.id]: value }))} onReview={decision => void review(plan, decision)} />)}
  </section>;
}

import { useEffect, useRef, useState } from "react";
import type { ApiSchemas } from "./generated/api";
import { mutate } from "./api-client";
import { EvidenceInspector } from "./EvidenceInspector";
type Approval = ApiSchemas["ApprovalView"];
type Scope = ApiSchemas["ScopeVersion"];
const safe = (value: unknown) => String(value ?? "not supplied")
  .replace(/Bearer\s+\S+/gi, "Bearer [redacted]")
  .replace(/((?:password|secret|token|api[_-]?key)\s*[:=]\s*)[^\s&,;]+/gi, "$1[redacted]");

export function ActionApprovalPanel({ assessmentId, token, onChanged }: { assessmentId: string; token: string; onChanged: () => void }) {
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [scope, setScope] = useState<Scope | null>(null);
  const [ready, setReady] = useState(false);
  const [pending, setPending] = useState<{ item: Approval; decision: "approve" | "deny" } | null>(null);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("");
  const active = useRef(false);
  const confirmation = useRef<HTMLElement>(null);
  const returnFocus = useRef<HTMLButtonElement | null>(null);
  const statusFocus = useRef<HTMLParagraphElement>(null);
  useEffect(() => {
    if (pending) confirmation.current?.focus();
    else if (returnFocus.current) {
      if (!returnFocus.current.disabled) returnFocus.current.focus();
      else statusFocus.current?.focus();
    }
  }, [pending]);
  const keys = useRef(new Map<string, string>());
  const base = `/api/v1/assessments/${encodeURIComponent(assessmentId)}`;
  async function get<T>(path: string): Promise<T> {
    const response = await fetch(base + path, { headers: { Authorization: `Bearer ${token}` }, cache: "no-store" });
    if (!response.ok) throw new Error(`Approval review unavailable (${response.status}). Reload current state.`);
    return response.json() as Promise<T>;
  }
  async function reload() {
    const [values, scopes] = await Promise.all([get<Approval[]>("/action-approvals"), get<Scope[]>("/scopes")]);
    if (active.current) { setApprovals(values); setScope([...scopes].sort((a, b) => b.revision - a.revision)[0] ?? null); setReady(true); }
  }
  useEffect(() => {
    active.current = true;
    void reload().catch(error => { if (active.current) setStatus(String(error)); });
    return () => { active.current = false; };
  }, [base, token]);
  function problem(item: Approval) {
    if (item.expired || !Number.isFinite(Date.parse(item.valid_until)) || Date.parse(item.valid_until) <= Date.now()) return "Expired or invalid expiry: action cannot be approved.";
    if (!scope || scope.id !== item.scope_id || scope.revision !== item.scope_revision) return "Stale scope: request a new action against the current scope.";
    if (!item.profile_current) return "Stale tool profile: approval is unavailable; review the current template.";
    return "";
  }
  async function confirm() {
    if (!pending) return;
    setBusy(true); setStatus("");
    try {
      const fresh = await get<Approval>(`/action-approvals/${pending.item.id}`);
      if (fresh.action_digest !== pending.item.action_digest || JSON.stringify(fresh.action) !== JSON.stringify(pending.item.action)) throw new Error("Action changed since display. Reload and review the exact parameters again.");
      if (!fresh.allowed_decisions.includes(pending.decision) || (pending.decision === "approve" && problem(fresh))) throw new Error("Permission, expiry, profile or scope changed. Reload this action before deciding.");
      const keyId = `${fresh.id}:${fresh.action_digest}:${pending.decision}`;
      const key = keys.current.get(keyId) ?? crypto.randomUUID(); keys.current.set(keyId, key);
      await mutate("", base + `/action-approvals/${fresh.id}/decision`, token, { decision: pending.decision, action_digest: pending.item.action_digest }, key);
      if (!active.current) return;
      setStatus(`Backend recorded ${pending.decision === "approve" ? "approval" : "denial"} for the reviewed action digest. No execution was submitted by this screen.`);
      await reload(); setPending(null); onChanged();
    } catch (error) {
      if (active.current) { setStatus(error instanceof Error ? error.message : "Decision was not confirmed."); setPending(null); await reload().catch(() => setReady(false)); }
    } finally { if (active.current) setBusy(false); }
  }
  return <section aria-labelledby="action-approval-review"><h3 id="action-approval-review">Action-bound approval review</h3>
    <p>Inspect the exact action, evidence and limits. Opening this view records no approval. A separate explicit decision is required; execution stays disabled in this screen.</p>
    <button disabled={busy} onClick={() => { setPending(null); void reload().catch(error => { setReady(false); setStatus(String(error)); }); }}>Reload action approvals</button>
    {ready && !approvals.length && <p>No action approvals recorded.</p>}
    {approvals.map(item => <article className="review-card" key={item.id} aria-label={`Action ${item.id}`}>
      <h4>{item.action.tool} · {item.action.profile} · {item.state}</h4>
      <p>{problem(item)}</p>
      <dl><dt>Exact target</dt><dd>{safe(item.action.destination_url)}</dd><dt>Template/module</dt><dd>{item.action.template}</dd><dt>Parameters</dt><dd><code>{JSON.stringify(item.action.parameters)}</code></dd>
      <dt>Runtime limit</dt><dd>{item.action.max_runtime_seconds} seconds</dd><dt>Expected impact</dt><dd>{safe(item.action.expected_impact)}</dd><dt>Rollback</dt><dd>{safe(item.action.rollback_instructions)}</dd>
      <dt>Rationale</dt><dd>No separate rationale is supplied by the action contract. <a href="#assessment-setup">Review the referenced plan</a>: {item.action.plan_id}, revision {item.action.plan_revision}.</dd>
      <dt>Scope</dt><dd>{item.scope_id} · revision {item.scope_revision}</dd><dt>Expiry</dt><dd>{item.valid_until}</dd><dt>Enforced action digest</dt><dd><code>{item.action_digest}</code></dd><dt>Parameter hash</dt><dd><code>{item.parameter_hash}</code></dd><dt>Policy/profile digests</dt><dd>{item.policy_digest} · {item.profile_digest ?? "not supplied"}</dd><dt>Reviewer</dt><dd>{item.reviewer ?? "no recorded reviewer"}</dd></dl>
      {!item.action.evidence_ids?.length && <p>No evidence references supplied by this action.</p>}
      {item.action.evidence_ids?.map(id => <div key={id}><p>Action evidence {id}</p><EvidenceInspector assessmentId={assessmentId} token={token} evidenceId={id} /></div>)}
      <button disabled={busy || !ready || !!problem(item) || !item.allowed_decisions.includes("approve")} onClick={event => { returnFocus.current = event.currentTarget; setPending({ item, decision: "approve" }); }}>Review approval</button>
      <button disabled={busy || !ready || !item.allowed_decisions.includes("deny")} onClick={event => { returnFocus.current = event.currentTarget; setPending({ item, decision: "deny" }); }}>Review denial</button>
      {!item.allowed_decisions.length && <p>No decision permitted for this identity or action state.</p>}
    </article>)}
    {pending && <section ref={confirmation} tabIndex={-1} role="region" aria-label="Confirm exact action decision" className="review-card"><p>Confirm {pending.decision} for action {pending.item.id}. Enforced digest: {pending.item.action_digest}. This decision applies only to that exact action.</p><button disabled={busy} onClick={() => void confirm()}>Confirm {pending.decision === "approve" ? "approval" : "denial"}</button><button disabled={busy} onClick={() => setPending(null)}>Cancel decision</button></section>}
    <p ref={statusFocus} tabIndex={-1} role="status" aria-live="polite">{status}</p>
  </section>;
}

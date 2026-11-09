import { useEffect, useRef, useState } from "react";
import { eventBatch, jobEventBatch, mutate } from "./api-client";
import type { JobProgressEvent } from "./api-client";
import type { ApiSchemas } from "./generated/api";

type Job = ApiSchemas["JobStatusSnapshot"];
type Audit = ApiSchemas["AuditEvent"];
type Resource = ApiSchemas["WorkflowResource"];
type Control = { stopped: boolean; epoch: number; jobs: Array<{ claim_id: string; state: string }> };
const safeText = (value: unknown) => String(value ?? "unknown").slice(0, 2000)
  .replace(/Bearer\s+\S+/gi, "Bearer [redacted]")
  .replace(/((?:api[_-]?key|password|secret|token)\s*[:=]\s*)\S+/gi, "$1[redacted]");
const stamp = (value: number | string | undefined) => value == null ? "unknown" : new Date(typeof value === "number" ? value * 1000 : value).toLocaleString();

export function recovery(job: Job): string {
  if (job.status === "unknown" || job.heartbeat_stale) return "Retry eligibility: blocked pending reconciliation. Verify worker termination and retained evidence before requesting fresh approval.";
  if (["failed", "partial", "blocked", "cancelled"].includes(job.status)) return "Retry requires review. Inspect the diagnostic and retained evidence, correct the cause, then create a fresh scoped request and approval. No automatic retry is offered.";
  return "Retry eligibility: not established. Reconnecting only refreshes status and never resubmits work.";
}

export function AssessmentTimeline({ assessmentId, token, onChanged }: { assessmentId: string; token: string; onChanged: () => void }) {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [progress, setProgress] = useState<JobProgressEvent[]>([]);
  const [audit, setAudit] = useState<Audit[]>([]);
  const [decisions, setDecisions] = useState<Resource[]>([]);
  const [control, setControl] = useState<Control | null>(null);
  const [connected, setConnected] = useState(false);
  const [lastSync, setLastSync] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [acting, setActing] = useState(false);
  const refreshRef = useRef<() => Promise<void>>(async () => {});
  const active = useRef(false);
  const actionKeys = useRef(new Map<string, string>());
  const base = `/api/v1/assessments/${encodeURIComponent(assessmentId)}`;
  useEffect(() => {
    active.current = true;
    const controller = new AbortController();
    let polling = false, auditCursor = 0;
    const cursors = new Map<string, number>();
    const auditHistory = new Map<string, Audit>();
    const jobHistory = new Map<string, JobProgressEvent>();
    async function read<T>(path: string): Promise<T> {
      const response = await fetch(base + path, { signal: controller.signal, headers: { Authorization: `Bearer ${token}` } });
      if (!response.ok) throw new Error(`Assessment status unavailable (${response.status}). Reconnect; verify access if it remains denied.`);
      return response.json() as Promise<T>;
    }
    async function sync() {
      if (polling || controller.signal.aborted) return;
      polling = true;
      try {
        const [snapshots, controls, reviews, triage, events] = await Promise.all([
          read<Job[]>("/scan-jobs"), read<Control>("/controls"), read<Resource[]>("/plan-reviews"),
          read<{ reviews: Resource[] }>("/finding-reviews"),
          eventBatch("", assessmentId, token, auditCursor, controller.signal),
        ]);
        const batches = await Promise.all(snapshots.map(async job => ({ id: job.id, batch: await jobEventBatch("", assessmentId, job.id, token, cursors.get(job.id) ?? 0, controller.signal) })));
        if (controller.signal.aborted) return;
        // Commit cursors only with the corresponding successfully received event records.
        for (const event of events.events) auditHistory.set(event.event_id!, event);
        auditCursor = events.cursor;
        for (const { id, batch } of batches) {
          for (const event of batch.events) jobHistory.set(`${id}:${event.sequence}`, event);
          cursors.set(id, batch.cursor);
        }
        while (auditHistory.size > 1000) auditHistory.delete(auditHistory.keys().next().value!);
        while (jobHistory.size > 1000) jobHistory.delete(jobHistory.keys().next().value!);
        setJobs(snapshots); setControl(current => current && current.epoch > controls.epoch ? current : controls);
        setDecisions([...reviews, ...triage.reviews]);
        setAudit([...auditHistory.values()].slice(-1000));
        setProgress([...jobHistory.values()].sort((a, b) => a.created_at - b.created_at || a.sequence - b.sequence).slice(-1000));
        setConnected(true); setLastSync(new Date().toLocaleString()); setError("");
      } catch (failure) {
        if (!controller.signal.aborted) { setConnected(false); setError(failure instanceof Error ? failure.message : "Connection lost. Reconnect to reconcile persisted status."); }
      } finally { polling = false; }
    }
    refreshRef.current = sync;
    void sync();
    const timer = window.setInterval(() => void sync(), 5000);
    return () => { active.current = false; controller.abort(); window.clearInterval(timer); };
  }, [assessmentId, token, base]);
  async function act(action: "stop" | "resume") {
    setActing(true); setNotice(`${action} requested; awaiting backend confirmation.`);
    const key = actionKeys.current.get(action) ?? crypto.randomUUID();
    actionKeys.current.set(action, key);
    try {
      const result = await mutate<{ stopped: boolean; epoch: number; running_cancel_requests?: number; unknown_disconnected?: number }>("", base + `/controls/${action}`, token, {}, key);
      if (!active.current) return;
      actionKeys.current.delete(action);
      setControl(current => ({ stopped: result.stopped, epoch: result.epoch, jobs: current?.jobs ?? [] }));
      setNotice(action === "stop" ? `Backend confirmed stop for new work. Cancellation requests: ${result.running_cancel_requests ?? 0}; disconnected/unknown: ${result.unknown_disconnected ?? 0}. Worker termination must still be reconciled.` : "Backend confirmed resume. Old approvals are not restored; no work was automatically submitted.");
      await refreshRef.current(); onChanged();
    } catch (failure) {
      if (active.current) { setConnected(false); setNotice(`Control outcome unconfirmed. ${safeText(failure instanceof Error ? failure.message : failure)} Reconnect to inspect backend state; retrying this control uses the same receipt key.`); }
    } finally { if (active.current) setActing(false); }
  }
  return <section aria-labelledby="assessment-timeline">
    <h3 id="assessment-timeline">Assessment timeline and recovery</h3>
    <p role="status" aria-live="polite">{connected ? `Connected; last reconciled ${lastSync}` : "Status unknown while disconnected; retained entries are historical."}</p>
    {error && <p role="alert">{safeText(error)}</p>}
    <button onClick={() => void refreshRef.current()}>Reconnect and reconcile</button>
    <p>Assessment control: {control ? `${connected ? "confirmed" : "last confirmed"} ${control.stopped ? "stopped for new work" : "open for approved work"} · epoch ${control.epoch}` : "unknown"}. Stop does not prove worker termination.</p>
    <button disabled={acting} onClick={() => void act("stop")}>Stop assessment</button>
    <button disabled={acting || !connected || !control?.stopped} onClick={() => void act("resume")}>Resume for new approvals</button>
    <p role="status">{notice}</p>
    {control?.jobs.map(execution => <p key={execution.claim_id}>Execution claim {execution.claim_id}: {connected ? safeText(execution.state) : "unknown while disconnected"}. Unconfirmed termination requires evidence reconciliation before retry.</p>)}
    <p>Persisted finite event batches refresh every five seconds. No completion percentage is estimated. Up to 50 current jobs and the latest 1,000 received events are displayed; each stream may need multiple refreshes to catch up. Reload replays persisted history from cursor zero.</p>
    {!jobs.length && <p>{connected ? "No execution jobs recorded." : "Job inventory unavailable."}</p>}
    {jobs.map(job => <article className="review-card" key={job.id} aria-label={`Job ${job.id}`}>
      <h4>Job {job.id} · {connected ? job.status : "unknown (connection lost)"}</h4>
      <p>Last stored: {job.state} · Attempt {job.attempt} · Mode: execution mode not supplied by status API; a job event alone does not prove a live scan.</p>
      <p>Elapsed: {job.duration_ms == null ? "unknown" : `${job.duration_ms} ms`} · Tool version: {job.tool_version ?? "unknown"} · Exit: {job.exit_code ?? "unknown"}</p>
      <p>Heartbeat: {job.heartbeat_stale ? "stale" : job.heartbeat_at ? stamp(job.heartbeat_at) : "not supplied"}</p>
      {job.diagnostic && <p>{safeText(job.diagnostic_code)}: {safeText(job.diagnostic)}</p>}
      <p>{recovery(connected ? job : { ...job, status: "unknown" })}</p>
      <ol aria-label={`Events for ${job.id}`}>{progress.filter(event => event.job_id === job.id).map(event => <li key={event.sequence}>#{event.sequence} · {stamp(event.created_at)} · {safeText(event.kind)} · {safeText(event.state)} · attempt {event.attempt}{event.diagnostic && <p>{safeText(event.diagnostic)}</p>}</li>)}</ol>
    </article>)}
    <h4>Persisted reviewer decisions</h4>
    {!decisions.length && <p>No reviewer decisions in this response.</p>}
    {decisions.map(decision => <article className="review-card" key={decision.id}><p>Reviewer decision · {safeText(decision.request.decision ?? decision.request.validation_state)} · {stamp(String(decision.request.reviewed_at ?? decision.request.recorded_at ?? ""))}</p><p>Rationale: {safeText(decision.request.rationale)}</p><p>Reference: {safeText(decision.request.plan_id ?? decision.request.observation_id)} · record {decision.id}</p><a href={decision.request.plan_id ? "#assessment-setup" : "#source-priority"}>Review referenced plan or evidence</a><p>Contradiction observation references: {safeText(JSON.stringify(decision.request.contradictory_observation_ids ?? []))}</p></article>)}
    <h4>Assessment audit timeline</h4>
    <p>Audit metadata identifies proposals, decisions and outcomes. It does not expose internal model reasoning or private source bodies. Import actions are recorded-input events; inference events are proposals.</p>
    <ol aria-label="Assessment audit events">{audit.map(event => <li key={event.event_id}>{stamp(event.created_at)} · {safeText(event.action)} · {safeText(event.outcome)} · {event.actor_kind === "ai-proposal" ? "Proposed action" : event.action.includes("import") ? "recorded import" : "persisted action metadata"}<p>Resource: {event.resource_id ?? "not supplied"} · event {event.event_id} · scope revision {event.scope_revision ?? "unknown"} · plan revision {event.plan_revision ?? "unknown"}</p></li>)}</ol>
  </section>;
}

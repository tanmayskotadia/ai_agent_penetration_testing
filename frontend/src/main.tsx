import { StrictMode, useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { createRoot } from "react-dom/client";
import { jobEventBatch } from "./api-client";
import type { ApiSchemas } from "./generated/api";
import "./style.css";

type Status = { stage: string; live_scans_enabled: boolean; tools: ApiSchemas["Capability"][] };
type JobSnapshot = ApiSchemas["JobStatusSnapshot"];

function formatDuration(milliseconds: number | null | undefined): string {
  if (milliseconds == null) return "Not started";
  const seconds = Math.floor(milliseconds / 1000);
  return seconds < 60 ? `${seconds}s` : `${Math.floor(seconds / 60)}m ${seconds % 60}s`;
}

function HumanReview() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [token, setToken] = useState("");
  const [assessments, setAssessments] = useState<ApiSchemas["Assessment"][]>([]);
  const [selected, setSelected] = useState("");
  const [queue, setQueue] = useState<ApiSchemas["ApprovalView"][]>([]);
  const [jobs, setJobs] = useState<JobSnapshot[]>([]);
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const keys = useRef(new Map<string, string>());
  const jobCursors = useRef(new Map<string, number>());
  async function signIn(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); setBusy(true); setMessage("");
    try {
      const response = await fetch("/api/v1/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ username, password }) });
      if (!response.ok) throw new Error("Sign-in failed or temporarily rate limited.");
      const session = await response.json() as { access_token: string };
      setToken(session.access_token); setMessage("Signed in. Select an assessment to review.");
    } catch (failure) { setMessage(failure instanceof Error ? failure.message : "Unable to sign in."); }
    finally { setPassword(""); setBusy(false); }
  }
  useEffect(() => {
    if (!token) return;
    const controller = new AbortController();
    fetch("/api/v1/assessments", { signal: controller.signal, headers: { Authorization: `Bearer ${token}` } })
      .then(response => { if (!response.ok) throw new Error("Session unavailable; sign in again."); return response.json() as Promise<ApiSchemas["Assessment"][]>; })
      .then(values => { setAssessments(values); setSelected(values[0]?.id ?? ""); })
      .catch(failure => { if (!controller.signal.aborted) setMessage(failure instanceof Error ? failure.message : "Unable to load assessments."); });
    return () => controller.abort();
  }, [token]);
  useEffect(() => {
    setQueue([]);
    if (!selected || !token) return;
    const controller = new AbortController();
    fetch(`/api/v1/assessments/${encodeURIComponent(selected)}/action-approvals`, { signal: controller.signal, headers: { Authorization: `Bearer ${token}` } })
      .then(response => { if (!response.ok) throw new Error("Review access unavailable or revoked."); return response.json() as Promise<ApiSchemas["ApprovalView"][]>; })
      .then(values => { if (!controller.signal.aborted) setQueue(values); })
      .catch(failure => { if (!controller.signal.aborted) setMessage(failure instanceof Error ? failure.message : "Unable to load reviews."); });
    return () => controller.abort();
  }, [selected, token, refresh]);
  useEffect(() => {
    setJobs([]);
    if (!selected || !token) return;
    const controller = new AbortController();
    let refreshing = false;
    async function refreshJobs() {
      if (refreshing) return;
      refreshing = true;
      try {
        const response = await fetch(`/api/v1/assessments/${encodeURIComponent(selected)}/scan-jobs`, {
          signal: controller.signal, headers: { Authorization: `Bearer ${token}` },
        });
        if (!response.ok) throw new Error("Job status unavailable or assessment access changed.");
        const snapshots = await response.json() as JobSnapshot[];
        const updated = await Promise.all(snapshots.map(async job => {
          const cursor = jobCursors.current.get(job.id) ?? 0;
          const batch = await jobEventBatch("", selected, job.id, token, cursor, controller.signal);
          jobCursors.current.set(job.id, batch.cursor);
          return job;
        }));
        if (!controller.signal.aborted) setJobs(updated);
      } catch (failure) {
        if (!controller.signal.aborted) setMessage(failure instanceof Error ? failure.message : "Unable to refresh job status.");
      } finally { refreshing = false; }
    }
    void refreshJobs();
    const timer = window.setInterval(() => { void refreshJobs(); }, 5000);
    return () => { controller.abort(); window.clearInterval(timer); };
  }, [selected, token, refresh]);
  async function decide(item: ApiSchemas["ApprovalView"], decision: "approve" | "deny") {
    setBusy(true); setMessage("");
    const key = `${item.id}:${item.action_digest}:${decision}`;
    if (!keys.current.has(key)) keys.current.set(key, crypto.randomUUID());
    try {
      const response = await fetch(`/api/v1/assessments/${item.assessment_id}/action-approvals/${item.id}/decision`, { method: "POST", headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json", "X-Request-ID": crypto.randomUUID(), "Idempotency-Key": keys.current.get(key)! }, body: JSON.stringify({ decision, action_digest: item.action_digest }) });
      if (!response.ok) throw new Error("Review rejected: permission, expiry or action may have changed. Reload the assessment.");
      const updated = await response.json() as ApiSchemas["ApprovalView"];
      setQueue(current => current.map(value => value.id === updated.id ? updated : value));
      setRefresh(value => value + 1);
      setMessage("Review response received; refreshing the current state. No scanner execution is claimed.");
    } catch (failure) { setMessage(failure instanceof Error ? failure.message : "Unable to save review."); }
    finally { setBusy(false); }
  }
  async function signOut() {
    let revoked = false;
    try { const response = await fetch("/api/v1/auth/logout", { method: "POST", headers: { Authorization: `Bearer ${token}`, "X-Request-ID": crypto.randomUUID(), "Idempotency-Key": crypto.randomUUID() } }); revoked = response.ok; }
    catch { /* Local sign-out still clears the in-memory credential. */ }
    finally { setToken(""); setAssessments([]); setSelected(""); setQueue([]); setJobs([]); keys.current.clear(); jobCursors.current.clear(); setMessage(revoked ? "Signed out; server session revoked." : "Signed out in this browser. Server revocation was not confirmed; sessions also expire automatically."); }
  }
  async function stopAssessment() {
    if (!selected) return;
    setBusy(true);
    try {
      const response = await fetch(`/api/v1/assessments/${selected}/controls/stop`, { method: "POST", headers: { Authorization: `Bearer ${token}`, "X-Request-ID": crypto.randomUUID(), "Idempotency-Key": crypto.randomUUID() } });
      if (!response.ok) throw new Error("Stop request rejected or not confirmed. Refresh current status.");
      const result = await response.json() as { cancelled_before_start: number; running_cancel_requests: number; unknown_disconnected: number };
      setMessage(`Assessment stopped for new work. Queued claims cancelled: ${result.cancelled_before_start}. Running cancellation requests: ${result.running_cancel_requests}. Disconnected/unknown: ${result.unknown_disconnected}.`);
      setRefresh(value => value + 1);
    } catch (failure) { setMessage(failure instanceof Error ? failure.message : "Stop was not confirmed."); }
    finally { setBusy(false); }
  }
  return <section aria-labelledby="human-review"><h2 id="human-review">Human action review</h2>
    <p>Review the exact destination, impact and rollback before recording a decision. Scanner execution remains disabled.</p>
    {!token ? <form onSubmit={signIn}><label>Username<input autoComplete="username" value={username} onChange={event => setUsername(event.target.value)} required /></label><label>Password<input type="password" autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} required minLength={12} maxLength={128} /></label><button disabled={busy}>Sign in</button></form> : <><label>Assessment<select value={selected} onChange={event => setSelected(event.target.value)}><option value="">Select an assessment</option>{assessments.map(value => <option key={value.id} value={value.id}>{value.name}</option>)}</select></label><button onClick={signOut} disabled={busy}>Sign out</button><button disabled={busy || !selected} onClick={stopAssessment}>Stop assessment</button><button disabled={busy || !selected} onClick={() => setRefresh(value => value + 1)}>Refresh reviews</button>{selected && queue.length === 0 && <p>No action reviews are available for this assessment.</p>}{queue.map(item => <article className="review-card" key={item.id}><h3>{item.action.tool} Ã‚Â· {item.action.profile}</h3><p><strong>Destination:</strong> <code>{item.action.destination_url}</code></p><p><strong>Impact:</strong> {item.action.expected_impact}</p><p><strong>Parameters:</strong> <code>{JSON.stringify(item.action.parameters)}</code></p><p><strong>Rollback:</strong> {item.action.rollback_instructions}</p><p><strong>Maximum runtime:</strong> {item.action.max_runtime_seconds} seconds</p><p><strong>Scope revision:</strong> {item.scope_revision} Ã‚Â· <strong>Expires:</strong> {item.valid_until}</p><p className="digest"><strong>Action digest:</strong> <code>{item.action_digest}</code></p><p>Status: {item.expired ? "expired" : item.state}</p>{item.allowed_decisions.map(choice => <button key={choice} disabled={busy || item.expired} onClick={() => decide(item, choice)}>{choice === "approve" ? "Approve this action" : "Deny this action"}</button>)}</article>)}</>}
    {token && selected && <section aria-labelledby="scan-jobs"><h3 id="scan-jobs">Scan job status</h3><p>Statuses come from persisted worker events. No estimated completion percentage is shown.</p>{jobs.length === 0 ? <p>No scan jobs are recorded for this assessment.</p> : jobs.map(job => <article className="review-card" key={job.id}><h4>{job.status === job.state ? job.state : `${job.status} (last stored: ${job.state})`}</h4><p><strong>Attempt:</strong> {job.attempt} · <strong>Elapsed:</strong> {formatDuration(job.duration_ms)}</p>{job.heartbeat_at !== null && <p><strong>Worker heartbeat:</strong> {job.heartbeat_stale ? `stale (${job.heartbeat_age_seconds}s ago)` : `${job.heartbeat_age_seconds}s ago`}</p>}{job.tool_version && <p><strong>Tool version:</strong> {job.tool_version}</p>}{job.exit_code !== null && <p><strong>Exit code:</strong> {job.exit_code}</p>}{job.diagnostic && <p role="status"><strong>{job.diagnostic_code}:</strong> {job.diagnostic}</p>}{job.latest_event_kind && job.latest_event_at && <small>Latest persisted event: {job.latest_event_kind} · {new Date(job.latest_event_at * 1000).toLocaleString()}</small>}</article>)}</section>}
    <p role="status" aria-live="polite">{message}</p>
  </section>;
}

function App() {
  const [status, setStatus] = useState<Status | null>(null);
  const [error, setError] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    fetch("/api/v1/system/status", { signal: controller.signal })
      .then((response) => { if (!response.ok) throw new Error("Workspace status unavailable"); return response.json() as Promise<Status>; })
      .then(setStatus)
      .catch((failure: unknown) => { if (!controller.signal.aborted) setError(failure instanceof Error ? failure.message : "Unable to connect"); });
    return () => controller.abort();
  }, []);
  return <main>
    <header><p className="eyebrow">EVIDENCE. REASONING. HUMAN CONTROL.</p><h1>AegisTrace</h1><p>A clearer path from security evidence to action.</p></header>
    <section aria-labelledby="readiness"><h2 id="readiness">Evidence platform</h2><p>Authenticated assessment, evidence and audit APIs are available. Analyst screens and scanner integrations are being built.</p><p className="notice">Live testing is disabled. Authorized scope and verified execution controls are required before live testing.</p>
      <div role="status" aria-live="polite">{error || (status ? "Connected to the workspace" : "Connecting to the workspaceÃ¢â‚¬Â¦")}</div>
    </section>
    {status && <section aria-labelledby="coverage"><h2 id="coverage">Integration capabilities</h2><ul>{status.tools.map((tool) => <li key={tool.name}><div><span>{tool.name}</span><small className="capability-description">{tool.demonstration_label}</small><small className="capability-description">{(tool.limitations ?? []).join(". ")}</small></div><span className="badge">{tool.mode ?? "planned"}</span></li>)}</ul><p>Container inspection does not count as a working native integration. Recorded imports remain distinct from live scans.</p></section>}
    <HumanReview />
    <footer>Assessment permission, evidence provenance and human review come first.</footer>
  </main>;
}

const root = document.getElementById("root");
if (!root) throw new Error("Missing application root");
createRoot(root).render(<StrictMode><App /></StrictMode>);

import { StrictMode, useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { createRoot } from "react-dom/client";
import { jobEventBatch } from "./api-client";
import type { ApiSchemas } from "./generated/api";
import "./style.css";

type Status = { stage: string; live_scans_enabled: boolean; tools: ApiSchemas["Capability"][] };
type JobSnapshot = ApiSchemas["JobStatusSnapshot"];
type RecordedResult = Record<string, unknown>;

async function apiJson<T>(token: string, path: string, method: string, body?: unknown): Promise<T> {
  const response = await fetch(path, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      "X-Request-ID": crypto.randomUUID(),
      "Idempotency-Key": crypto.randomUUID(),
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  if (!response.ok) {
    const error = await response.json().catch(() => null) as { message?: string } | null;
    throw new Error(error?.message ?? `Request failed (${response.status}).`);
  }
  return response.json() as Promise<T>;
}

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
  const [newAssessmentName, setNewAssessmentName] = useState("");
  const [artifact, setArtifact] = useState<File | null>(null);
  const [targets, setTargets] = useState("");
  const [exclusions, setExclusions] = useState("");
  const [authorizationReference, setAuthorizationReference] = useState("");
  const [toolVersion, setToolVersion] = useState("7.95");
  const [importTool, setImportTool] = useState<"Nmap" | "OWASP ZAP" | "Nikto" | "OpenAPI">("Nmap");
  const [capturedAt, setCapturedAt] = useState("");
  const [recordedResult, setRecordedResult] = useState<RecordedResult | null>(null);
  const [recordedImportId, setRecordedImportId] = useState("");
  const [manifestResult, setManifestResult] = useState<RecordedResult | null>(null);
  const [captureReference, setCaptureReference] = useState("");
  const [rightsBasis, setRightsBasis] = useState("");
  const [replayResult, setReplayResult] = useState<RecordedResult | null>(null);
  const [coverage, setCoverage] = useState<RecordedResult | null>(null);
  const [intakeBusy, setIntakeBusy] = useState(false);
  const [intakeMessage, setIntakeMessage] = useState("");
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
    setCoverage(null);
    if (!selected || !token) return;
    const controller = new AbortController();
    fetch(`/api/v1/assessments/${encodeURIComponent(selected)}/coverage`, { signal: controller.signal, headers: { Authorization: `Bearer ${token}` } })
      .then(response => { if (!response.ok) throw new Error("Coverage summary unavailable."); return response.json() as Promise<RecordedResult>; })
      .then(value => { if (!controller.signal.aborted) setCoverage(value); })
      .catch(failure => { if (!controller.signal.aborted) setMessage(failure instanceof Error ? failure.message : "Unable to load coverage."); });
    return () => controller.abort();
  }, [selected, token, refresh]);
  useEffect(() => {
    setRecordedResult(null);
    setRecordedImportId("");
    setReplayResult(null);
    setManifestResult(null);
    setIntakeMessage("");
  }, [selected]);
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
  async function createAssessment(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!token || !newAssessmentName.trim()) return;
    setBusy(true);
    try {
      const created = await apiJson<ApiSchemas["Assessment"]>(token, "/api/v1/assessments", "POST", { name: newAssessmentName.trim() });
      setAssessments(values => [...values, created]);
      setSelected(created.id ?? "");
      setNewAssessmentName("");
      setMessage("Assessment created.");
    } catch (failure) { setMessage(failure instanceof Error ? failure.message : "Unable to create assessment."); }
    finally { setBusy(false); }
  }
  async function importArtifact(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!token || !selected || !artifact) return;
    if (artifact.size < 1 || artifact.size > 2 * 1024 * 1024) {
      setIntakeMessage("Choose a non-empty supported evidence file up to 2 MiB.");
      return;
    }
    const targetList = targets.split(/[\n,]/).map(value => value.trim()).filter(Boolean);
    if (!targetList.length) { setIntakeMessage("Enter at least one in-scope host or address."); return; }
    if (!authorizationReference.trim()) { setIntakeMessage("Enter the source or authorization reference. It is recorded as supplied and is not independently verified."); return; }
    if (!capturedAt) { setIntakeMessage("Enter the capture time reported by the source artifact."); return; }
    setIntakeBusy(true); setIntakeMessage("Saving encrypted artifact and normalizing recorded input…"); setRecordedResult(null); setReplayResult(null); setRecordedImportId("");
    try {
      const assessmentBase = `/api/v1/assessments/${encodeURIComponent(selected)}`;
      const priorScopes = await apiJson<ApiSchemas["ScopeVersion"][]>(token, `${assessmentBase}/scopes`, "GET");
      const scope = await apiJson<ApiSchemas["ScopeVersion"]>(token, `${assessmentBase}/scopes`, "POST", {
        revision: (priorScopes.at(-1)?.revision ?? 0) + 1,
        targets: targetList,
        exclusions: exclusions.split(/[\n,]/).map(value => value.trim()).filter(Boolean),
        authorization_reference: authorizationReference.trim(),
        mode: "recorded-import",
      });
      const run = await apiJson<ApiSchemas["ToolRun"]>(token, `${assessmentBase}/runs`, "POST", {
        scope_id: scope.id,
        tool: importTool,
        tool_version: toolVersion.trim(),
        captured_at: new Date(capturedAt).toISOString(),
        mode: "recorded-import",
      });
      const bytes = await artifact.arrayBuffer();
      const digest = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))).map(value => value.toString(16).padStart(2, "0")).join("");
      const evidence = await apiJson<ApiSchemas["EvidenceReference"]>(token, `${assessmentBase}/runs/${run.id}/evidence`, "POST", {
        sha256: digest,
        pointer: "/",
        pointer_type: "whole-file",
        captured_at: new Date(capturedAt).toISOString(),
      });
      const expiry = new URLSearchParams({ expires_at: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString() });
      const uploaded = await fetch(`${assessmentBase}/evidence/${evidence.id}/original?${expiry}`, {
        method: "PUT", body: bytes,
        headers: { Authorization: `Bearer ${token}`, "X-Request-ID": crypto.randomUUID(), "Idempotency-Key": crypto.randomUUID() },
      });
      if (!uploaded.ok) throw new Error(`Encrypted evidence upload failed (${uploaded.status}).`);
      const imported = await apiJson<ApiSchemas["WorkflowResource"]>(token, `${assessmentBase}/imports`, "POST", {
        scope_id: scope.id, scope_revision: scope.revision, tool: importTool, format: importTool === "Nmap" ? "nmap-xml" : importTool === "OWASP ZAP" ? "zap-alerts-json" : importTool === "Nikto" ? "nikto-json" : "openapi-json", evidence_id: evidence.id,
      });
      setRecordedImportId(imported.id);
      const normalizer = importTool === "Nmap" ? "normalize-nmap" : importTool === "OWASP ZAP" ? "normalize-zap" : importTool === "Nikto" ? "normalize-nikto" : "normalize-openapi";
      const normalized = await apiJson<RecordedResult>(token, `${assessmentBase}/imports/${imported.id}/${normalizer}`, "POST", { asset_mapping: {} });
      setRecordedResult(normalized);
      setIntakeMessage("Recorded XML processed. No network scan was run; source authenticity and rights are not independently verified.");
      setRefresh(value => value + 1);
    } catch (failure) {
      setIntakeMessage(failure instanceof Error ? failure.message : "The artifact could not be processed. Check the saved source metadata and retry with a new import.");
    } finally { setIntakeBusy(false); }
  }
  async function replayNmap() {
    if (!token || !selected || !recordedImportId) return;
    if (!captureReference.trim() || !rightsBasis.trim() || !authorizationReference.trim()) {
      setIntakeMessage("Add the capture, rights and authorization references to create a reviewer-declared replay.");
      return;
    }
    setIntakeBusy(true); setIntakeMessage("Creating immutable replay manifest and replaying the recorded import…");
    try {
      const base = `/api/v1/assessments/${encodeURIComponent(selected)}/replays`;
      const manifest = await apiJson<RecordedResult>(token, base, "POST", {
        import_id: recordedImportId,
        provenance: "reviewer-declared-capture",
        capture_reference: captureReference.trim(),
        rights_basis: rightsBasis.trim(),
        authorization_reference: authorizationReference.trim(),
      });
      setManifestResult(manifest);
      const result = await apiJson<RecordedResult>(token, `${base}/${String(manifest.id)}/ingest`, "POST", {});
      setReplayResult(result);
      setIntakeMessage("Replay finished with recorded provenance. It did not request approval or contact a target.");
    } catch (failure) { setIntakeMessage(failure instanceof Error ? failure.message : "Recorded replay failed."); }
    finally { setIntakeBusy(false); }
  }
  async function downloadOriginal(evidenceId: string) {
    if (!token || !selected) return;
    try {
      const base = `/api/v1/assessments/${encodeURIComponent(selected)}/evidence/${encodeURIComponent(evidenceId)}`;
      const ticket = await apiJson<{ ticket: string }>(token, `${base}/download-ticket`, "POST", {});
      const response = await fetch(`${base}/original`, {
        headers: { Authorization: `Bearer ${token}`, "X-Download-Ticket": ticket.ticket },
      });
      if (!response.ok) throw new Error(`Original artifact download failed (${response.status}).`);
      const url = URL.createObjectURL(await response.blob());
      const link = document.createElement("a");
      link.href = url; link.download = "recorded-nmap-capture.xml"; link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch (failure) { setIntakeMessage(failure instanceof Error ? failure.message : "The private original could not be downloaded."); }
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
    {!token ? <form onSubmit={signIn}><label>Username<input autoComplete="username" value={username} onChange={event => setUsername(event.target.value)} required /></label><label>Password<input type="password" autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} required minLength={12} maxLength={128} /></label><button disabled={busy}>Sign in</button></form> : <><form onSubmit={createAssessment}><label>New assessment<input value={newAssessmentName} onChange={event => setNewAssessmentName(event.target.value)} maxLength={200} required /></label><button disabled={busy}>Create assessment</button></form><label>Assessment<select value={selected} onChange={event => setSelected(event.target.value)}><option value="">Select an assessment</option>{assessments.map(value => <option key={value.id} value={value.id}>{value.name}</option>)}</select></label><button onClick={signOut} disabled={busy}>Sign out</button><button disabled={busy || !selected} onClick={stopAssessment}>Stop assessment</button><button disabled={busy || !selected} onClick={() => setRefresh(value => value + 1)}>Refresh reviews</button>{selected && queue.length === 0 && <p>No action reviews are available for this assessment.</p>}{queue.map(item => <article className="review-card" key={item.id}><h3>{item.action.tool} Ã‚Â· {item.action.profile}</h3><p><strong>Destination:</strong> <code>{item.action.destination_url}</code></p><p><strong>Impact:</strong> {item.action.expected_impact}</p><p><strong>Parameters:</strong> <code>{JSON.stringify(item.action.parameters)}</code></p><p><strong>Rollback:</strong> {item.action.rollback_instructions}</p><p><strong>Maximum runtime:</strong> {item.action.max_runtime_seconds} seconds</p><p><strong>Scope revision:</strong> {item.scope_revision} Ã‚Â· <strong>Expires:</strong> {item.valid_until}</p><p className="digest"><strong>Action digest:</strong> <code>{item.action_digest}</code></p><p>Status: {item.expired ? "expired" : item.state}</p>{item.allowed_decisions.map(choice => <button key={choice} disabled={busy || item.expired} onClick={() => decide(item, choice)}>{choice === "approve" ? "Approve this action" : "Deny this action"}</button>)}</article>)}</>}
    {token && selected && <section aria-labelledby="recorded-import"><h3 id="recorded-import">Import evidence and API definitions</h3><p>Upload an existing capture you are authorized to process. This flow never runs a scanner or contacts a target. OpenAPI server URLs and external references are never fetched, and credentials are not accepted. Captures are encrypted at rest, hashed, scope-checked and labeled as recorded input. A supplied authorization reference is recorded but not independently verified.</p><form onSubmit={importArtifact}><label>Evidence format<select value={importTool} onChange={event => { const nextTool = event.target.value as "Nmap" | "OWASP ZAP" | "Nikto" | "OpenAPI"; setImportTool(nextTool); setToolVersion(nextTool === "Nmap" ? "7.95" : nextTool === "Nikto" ? "2.6.1" : nextTool === "OpenAPI" ? "3.1.0" : "2.16.0"); setArtifact(null); }}><option value="Nmap">Nmap XML</option><option value="OWASP ZAP">OWASP ZAP Alerts JSON</option><option value="Nikto">Nikto 2.6 JSON</option><option value="OpenAPI">OpenAPI 3.1 JSON definition</option></select></label><label>{importTool === "Nmap" ? "Nmap XML file" : `${importTool} JSON file`}<input type="file" accept={importTool === "Nmap" ? ".xml,application/xml,text/xml" : ".json,application/json"} onChange={event => setArtifact(event.target.files?.[0] ?? null)} required /></label><label>Targets represented in the input<textarea value={targets} onChange={event => setTargets(event.target.value)} placeholder="One host, address or URL per line" required /></label><label>Excluded hosts/addresses<textarea value={exclusions} onChange={event => setExclusions(event.target.value)} placeholder="Optional; one host/address/URL per line" /></label><label>Source / authorization reference<input value={authorizationReference} onChange={event => setAuthorizationReference(event.target.value)} maxLength={500} required /></label><label>Source version reported by file<input value={toolVersion} onChange={event => setToolVersion(event.target.value)} maxLength={100} required /></label><label>Capture time reported by source<input type="datetime-local" value={capturedAt} onChange={event => setCapturedAt(event.target.value)} required /></label><button disabled={intakeBusy || !artifact}>Store and normalize recorded evidence</button></form>{intakeMessage && <p role="status" aria-live="polite">{intakeMessage}</p>}{recordedResult && <article className="review-card"><h4>IMPORTED / RECORDED · {String(recordedResult.state ?? "unknown")}</h4><p>The system does not report this input as a live scan. Findings created: {String(recordedResult.findings_created ?? 0)}.</p><pre>{JSON.stringify(recordedResult, null, 2)}</pre>{typeof recordedResult.evidence_id === "string" && <button onClick={() => void downloadOriginal(recordedResult.evidence_id as string)}>Download exact original artifact</button>}{importTool === "Nmap" && <><label>Capture reference<input value={captureReference} onChange={event => setCaptureReference(event.target.value)} maxLength={300} /></label><label>Rights basis<input value={rightsBasis} onChange={event => setRightsBasis(event.target.value)} maxLength={300} /></label><button disabled={intakeBusy || !recordedImportId || !captureReference || !rightsBasis} onClick={() => void replayNmap()}>Create manifest and replay recorded input</button></>}</article>}{manifestResult && <article className="review-card"><h4>{String(manifestResult.label ?? "RECORDED / provenance unverified")}</h4><p>Immutable manifest evidence for reviewer inspection:</p><pre>{JSON.stringify(manifestResult, null, 2)}</pre></article>}{replayResult && <article className="review-card"><h4>{String(replayResult.replay_label ?? "RECORDED / provenance unverified")}</h4><pre>{JSON.stringify(replayResult, null, 2)}</pre></article>}</section>}
    {token && selected && <section aria-labelledby="scan-jobs"><h3 id="scan-jobs">Scan job status</h3><p>Statuses come from persisted worker events. No estimated completion percentage is shown.</p>{jobs.length === 0 ? <p>No scan jobs are recorded for this assessment.</p> : jobs.map(job => <article className="review-card" key={job.id}><h4>{job.status === job.state ? job.state : `${job.status} (last stored: ${job.state})`}</h4><p><strong>Attempt:</strong> {job.attempt} · <strong>Elapsed:</strong> {formatDuration(job.duration_ms)}</p>{job.heartbeat_at !== null && <p><strong>Worker heartbeat:</strong> {job.heartbeat_stale ? `stale (${job.heartbeat_age_seconds}s ago)` : `${job.heartbeat_age_seconds}s ago`}</p>}{job.tool_version && <p><strong>Tool version:</strong> {job.tool_version}</p>}{job.exit_code !== null && <p><strong>Exit code:</strong> {job.exit_code}</p>}{job.diagnostic && <p role="status"><strong>{job.diagnostic_code}:</strong> {job.diagnostic}</p>}{job.latest_event_kind && job.latest_event_at && <small>Latest persisted event: {job.latest_event_kind} · {new Date(job.latest_event_at * 1000).toLocaleString()}</small>}</article>)}</section>}
    {coverage && <section aria-labelledby="assessment-coverage"><h3 id="assessment-coverage">Assessment coverage</h3><p><strong>Coverage status:</strong> {String(coverage.coverage_state)}. An imported alert or API definition does not prove that every endpoint was tested.</p><ul><li>Recorded source runs: {String(coverage.source_run_count)}</li><li>Assets: {String(coverage.asset_count)}</li><li>Catalogued endpoints: {String(coverage.endpoint_catalog_count)}</li><li>OpenAPI-defined endpoints: {String(coverage.openapi_defined_endpoint_count)}</li><li>Endpoints with imported web alerts: {String(coverage.endpoints_with_imported_web_alerts)}</li><li>Source observations: {String(coverage.observed_record_count)}</li></ul><pre>{JSON.stringify(coverage.source_runs_by_tool, null, 2)}</pre></section>}
    {coverage && <section aria-labelledby="prototype-gate"><h3 id="prototype-gate">Prototype acceptance gate</h3><p>Each check uses verified artifacts. Recorded file uploads and test fixtures do not count as an authorized live demonstration.</p><ul>{Object.entries(coverage.prototype_gate as Record<string, { passed: boolean; evidence: unknown }>).map(([name, item]) => <li key={name}><strong>{item.passed ? "PASS" : "OPEN"}</strong> · {name.replaceAll("_", " ")}{item.evidence !== null && <small className="capability-description">{String(item.evidence)}</small>}</li>)}</ul></section>}
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
    <section aria-labelledby="readiness"><h2 id="readiness">Evidence platform</h2><p>Authenticated assessment, evidence and audit APIs are available. Recorded Nmap, OWASP ZAP and Nikto evidence import plus OpenAPI endpoint cataloging are available for user-supplied artifacts.</p><p className="notice">Live testing is disabled. Authorized scope and verified execution controls are required before live testing.</p>
      <div role="status" aria-live="polite">{error || (status ? "Connected to the workspace" : "Connecting to the workspaceÃ¢â‚¬Â¦")}</div>
    </section>
    {status && <section aria-labelledby="integration-capabilities"><h2 id="integration-capabilities">Integration capabilities</h2><ul>{status.tools.map((tool) => <li key={tool.name}><div><span>{tool.name}</span><small className="capability-description">{tool.demonstration_label}</small><small className="capability-description">{(tool.limitations ?? []).join(". ")}</small></div><span className="badge">{tool.mode ?? "planned"}</span></li>)}</ul><p>Container inspection does not count as a working native integration. Recorded imports remain distinct from live scans.</p></section>}
    <HumanReview />
    <footer>Assessment permission, evidence provenance and human review come first.</footer>
  </main>;
}

const root = document.getElementById("root");
if (!root) throw new Error("Missing application root");
createRoot(root).render(<StrictMode><App /></StrictMode>);

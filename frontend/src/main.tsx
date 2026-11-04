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
  const [reportBusy, setReportBusy] = useState(false);
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
  async function downloadEvidenceReport() {
    if (!selected || !token) return;
    setReportBusy(true);
    setMessage("");
    try {
      const revisions = await apiJson<Array<{ id: string; run_id: string; revision: number; captured_at: string }>>(
        token, `/api/v1/assessments/${encodeURIComponent(selected)}/result-revisions`, "GET",
      );
      const latestByRun = new Map<string, { id: string; run_id: string; revision: number; captured_at: string }>();
      for (const revision of revisions) {
        const previous = latestByRun.get(revision.run_id);
        if (!previous || revision.revision > previous.revision) latestByRun.set(revision.run_id, revision);
      }
      const selectedRevisions = [...latestByRun.values()]
        .sort((a, b) => a.captured_at.localeCompare(b.captured_at))
        .slice(-50);
      if (selectedRevisions.length === 0) throw new Error("Import authorized evidence before creating an export.");
      const frozen = await apiJson<{ id: string }>(
        token,
        `/api/v1/assessments/${encodeURIComponent(selected)}/result-exports`,
        "POST",
        { revision_ids: selectedRevisions.map(revision => revision.id) },
      );
      const response = await fetch(
        `/api/v1/assessments/${encodeURIComponent(selected)}/result-exports/${encodeURIComponent(frozen.id)}/pdf`,
        { headers: { Authorization: `Bearer ${token}`, "X-Request-ID": crypto.randomUUID() } },
      );
      if (!response.ok) throw new Error(`PDF download failed (${response.status}).`);
      const blob = await response.blob();
      if (blob.type !== "application/pdf") throw new Error("The server did not return a PDF document.");
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = `aegistrace-${selected}-evidence-report.pdf`;
      anchor.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setMessage(`Downloaded a frozen evidence summary using ${selectedRevisions.length} latest source revision(s). It is not a complete VAPT report.`);
      setRefresh(value => value + 1);
    } catch (failure) {
      setMessage(failure instanceof Error ? failure.message : "Unable to create the evidence report.");
    } finally {
      setReportBusy(false);
    }
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
  return <section aria-labelledby="human-review"><h2 id="human-review">Human action 
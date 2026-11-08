import { StrictMode, useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import { createRoot } from "react-dom/client";
import type { ApiSchemas } from "./generated/api";
import "./style.css";
import { CoveragePanel } from "./CoveragePanel";
import { CorrelationReviewPanel } from "./CorrelationReviewPanel";
import { SourceReviewPanel } from "./SourceReviewPanel";
import { AssessmentSetup } from "./AssessmentSetup";
import { AssessmentTimeline } from "./AssessmentTimeline";
import { ActionApprovalPanel } from "./ActionApprovalPanel";
import { ExecutiveSummary } from "./ExecutiveSummary";
import { ReportFindingPanel } from "./ReportFindingPanel";
import { ReplanPanel } from "./ReplanPanel";

type Status = { stage: string; live_scans_enabled: boolean; tools: ApiSchemas["Capability"][] };
type RecordedResult = Record<string, unknown>;
type RiskRanking = {
  policy: string;
  ranking_method: string;
  ranked_observations: Array<{
    observation_id: string;
    source_tool: string;
    title: string;
    asset_id: string;
    evidence_id: string;
    source_cvss_score: number | null;
    priority: {
      factors: Record<string, unknown>;
      available_weight: number;
      weighted_sum: number;
      local_priority_index: number | null;
      state: string;
      review_attention: string;
      missing_context: string[];
      meaning: string;
    };
  }>;
};
type ImportTool = "Nmap" | "OWASP ZAP" | "Nikto" | "OpenAPI" | "Nessus" | "Greenbone" | "Burp Suite";
type WorkspaceStage = "scope" | "evidence" | "review" | "report";
const WORKSPACE_STAGES: Array<{ id: WorkspaceStage; title: string; short: string; description: string }> = [
  { id: "scope", title: "Scope & plan", short: "Scope", description: "Set the exact assessment boundary and inspect the recorded-evidence plan. No scanner runs from this workspace." },
  { id: "evidence", title: "Evidence", short: "Evidence", description: "Import a permitted report, check its processing result, and review its source and audit trail." },
  { id: "review", title: "Findings & review", short: "Review", description: "Trace observations to source, record analyst context, and write evidence-backed report findings." },
  { id: "report", title: "Report", short: "Report", description: "Review coverage and uncertainty, then freeze a point-in-time evidence export." },
];
const IMPORT_OPTIONS: Record<ImportTool, { format: string; normalizer: string; accept: string; label: string }> = {
  "Nmap": { format: "nmap-xml", normalizer: "normalize-nmap", accept: ".xml,application/xml,text/xml", label: "Nmap XML" },
  "OWASP ZAP": { format: "zap-alerts-json", normalizer: "normalize-zap", accept: ".json,application/json", label: "OWASP ZAP Alerts JSON" },
  "Nikto": { format: "nikto-json", normalizer: "normalize-nikto", accept: ".json,application/json", label: "Nikto JSON" },
  "OpenAPI": { format: "openapi-json", normalizer: "normalize-openapi", accept: ".json,application/json", label: "OpenAPI JSON definition" },
  "Nessus": { format: "nessus-xml", normalizer: "normalize-nessus", accept: ".nessus,.xml,application/xml,text/xml", label: "Tenable Nessus .nessus XML" },
  "Greenbone": { format: "greenbone-xml", normalizer: "normalize-greenbone", accept: ".xml,application/xml,text/xml", label: "Greenbone/OpenVAS XML report" },
  "Burp Suite": { format: "burp-xml", normalizer: "normalize-burp", accept: ".xml,application/xml,text/xml", label: "Burp issue XML export" },
};

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

function HumanReview() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [token, setToken] = useState("");
  const [assessments, setAssessments] = useState<ApiSchemas["Assessment"][]>([]);
  const [selected, setSelected] = useState("");
  const [newAssessmentName, setNewAssessmentName] = useState("");
  const [assets, setAssets] = useState<ApiSchemas["Asset"][]>([]);
  const [assetContexts, setAssetContexts] = useState<ApiSchemas["WorkflowResource"][]>([]);
  const [contextAssetId, setContextAssetId] = useState("");
  const [contextExposure, setContextExposure] = useState("unknown");
  const [contextExposureReference, setContextExposureReference] = useState("");
  const [contextExploitability, setContextExploitability] = useState("unknown");
  const [contextExploitabilityReference, setContextExploitabilityReference] = useState("");
  const [contextCriticality, setContextCriticality] = useState("");
  const [contextCriticalityReference, setContextCriticalityReference] = useState("");
  const [contextNote, setContextNote] = useState("");
  const [artifact, setArtifact] = useState<File | null>(null);
  const [targets, setTargets] = useState("");
  const [exclusions, setExclusions] = useState("");
  const [authorizationReference, setAuthorizationReference] = useState("");
  const [toolVersion, setToolVersion] = useState("");
  const [importTool, setImportTool] = useState<ImportTool>("Nmap");
  const [capturedAt, setCapturedAt] = useState("");
  const [recordedResult, setRecordedResult] = useState<RecordedResult | null>(null);
  const [recordedImportId, setRecordedImportId] = useState("");
  const [manifestResult, setManifestResult] = useState<RecordedResult | null>(null);
  const [captureReference, setCaptureReference] = useState("");
  const [rightsBasis, setRightsBasis] = useState("");
  const [replayResult, setReplayResult] = useState<RecordedResult | null>(null);
  const [coverage, setCoverage] = useState<RecordedResult | null>(null);
  const [coverageLoading, setCoverageLoading] = useState(false);
  const [coverageError, setCoverageError] = useState("");
  const [reportBusy, setReportBusy] = useState(false);
  const [intakeBusy, setIntakeBusy] = useState(false);
  const [intakeMessage, setIntakeMessage] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const [refresh, setRefresh] = useState(0);
  const [presentation, setPresentation] = useState<"analyst" | "executive">("analyst");
  const [stage, setStage] = useState<WorkspaceStage>(() => {
    const saved = sessionStorage.getItem("aegistrace.workspace-stage");
    return WORKSPACE_STAGES.some(item => item.id === saved) ? saved as WorkspaceStage : "scope";
  });
  const presentationHeading = useRef<HTMLHeadingElement>(null);
  useEffect(() => { if (token && selected) presentationHeading.current?.focus(); }, [presentation, selected]);
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
      .then(values => {
        setAssessments(values);
        const remembered = sessionStorage.getItem("aegistrace.assessment-id");
        const selectedId = values.find(value => value.id === remembered)?.id ?? values[0]?.id ?? "";
        setSelected(selectedId);
        if (selectedId) sessionStorage.setItem("aegistrace.assessment-id", selectedId);
      })
      .catch(failure => { if (!controller.signal.aborted) setMessage(failure instanceof Error ? failure.message : "Unable to load assessments."); });
    return () => controller.abort();
  }, [token]);
  useEffect(() => {
    setAssets([]); setAssetContexts([]); setContextAssetId("");
    setContextExposure("unknown"); setContextExposureReference("");
    setContextExploitability("unknown"); setContextExploitabilityReference("");
    setContextCriticality(""); setContextCriticalityReference(""); setContextNote("");
    if (!selected || !token) return;
    const controller = new AbortController();
    apiJson<ApiSchemas["Asset"][]>(token, `/api/v1/assessments/${encodeURIComponent(selected)}/assets`, "GET")
      .then(values => { if (!controller.signal.aborted) { setAssets(values); setContextAssetId(values[0]?.id ?? ""); } })
      .catch(failure => { if (!controller.signal.aborted) setMessage(failure instanceof Error ? failure.message : "Unable to load assets."); });
    apiJson<ApiSchemas["WorkflowResource"][]>(token, `/api/v1/assessments/${encodeURIComponent(selected)}/asset-contexts`, "GET")
      .then(values => { if (!controller.signal.aborted) setAssetContexts(values); })
      .catch(failure => { if (!controller.signal.aborted) setMessage(failure instanceof Error ? failure.message : "Unable to load reviewer context."); });
    return () => controller.abort();
  }, [selected, token]);
  useEffect(() => {
    setCoverage(null);
    setCoverageError("");
    if (!selected || !token) return;
    setCoverageLoading(true);
    const controller = new AbortController();
    fetch(`/api/v1/assessments/${encodeURIComponent(selected)}/coverage`, { signal: controller.signal, headers: { Authorization: `Bearer ${token}` } })
      .then(response => { if (!response.ok) throw new Error("Coverage summary unavailable."); return response.json() as Promise<RecordedResult>; })
      .then(value => { if (!controller.signal.aborted) setCoverage(value); })
      .catch(failure => { if (!controller.signal.aborted) { const error = failure instanceof Error ? failure.message : "Unable to load coverage."; setCoverageError(error); setMessage(error); } })
      .finally(() => { if (!controller.signal.aborted) setCoverageLoading(false); });
    return () => controller.abort();
  }, [selected, token, refresh]);
  useEffect(() => {
    setRecordedResult(null);
    setRecordedImportId("");
    setReplayResult(null);
    setManifestResult(null);
    setIntakeMessage("");
  }, [selected]);
  async function signOut() {
    let revoked = false;
    try { const response = await fetch("/api/v1/auth/logout", { method: "POST", headers: { Authorization: `Bearer ${token}`, "X-Request-ID": crypto.randomUUID(), "Idempotency-Key": crypto.randomUUID() } }); revoked = response.ok; }
    catch { /* Local sign-out still clears the in-memory credential. */ }
    finally { setToken(""); setAssessments([]); setSelected(""); setStage("scope"); sessionStorage.removeItem("aegistrace.assessment-id"); sessionStorage.removeItem("aegistrace.workspace-stage"); setMessage(revoked ? "Signed out; server session revoked." : "Signed out in this browser. Server revocation was not confirmed; sessions also expire automatically."); }
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
  async function saveAssetContext(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!token || !selected || !contextAssetId || !contextNote.trim()) return;
    const current = assetContexts.find(value => value.request.asset_id === contextAssetId);
    setBusy(true);
    try {
      const saved = await apiJson<ApiSchemas["WorkflowResource"]>(token, `/api/v1/assessments/${encodeURIComponent(selected)}/asset-contexts`, "POST", {
        asset_id: contextAssetId,
        revision: (current?.revision ?? 0) + 1,
        exposure: contextExposure,
        exposure_reference: contextExposureReference.trim() || null,
        exploitability: contextExploitability,
        exploitability_reference: contextExploitabilityReference.trim() || null,
        criticality: contextCriticality ? Number(contextCriticality) : null,
        criticality_reference: contextCriticalityReference.trim() || null,
        reviewer_note: contextNote.trim(),
      });
      setAssetContexts(values => [...values.filter(value => value.request.asset_id !== contextAssetId), saved]);
      setContextNote(""); setMessage("Reviewer context saved as an immutable, provenance-linked revision; values are not independently verified.");
      setRefresh(value => value + 1);
    } catch (failure) { setMessage(failure instanceof Error ? failure.message : "Unable to save reviewer context."); }
    finally { setBusy(false); }
  }
  const riskRanking = (coverage?.observation_analytics as { contextual_risk_ranking?: RiskRanking } | undefined)?.contextual_risk_ranking;
  function changeStage(next: WorkspaceStage) {
    setStage(next);
    sessionStorage.setItem("aegistrace.workspace-stage", next);
    requestAnimationFrame(() => document.getElementById("workspace-flow")?.scrollIntoView({ block: "start", behavior: "smooth" }));
  }
  function openEvidenceTarget(target: "source-review" | "assessment-timeline") {
    changeStage("evidence");
    window.setTimeout(() => document.getElementById(target)?.scrollIntoView({ block: "start", behavior: "smooth" }), 100);
  }
  const currentStage = WORKSPACE_STAGES.find(item => item.id === stage) ?? WORKSPACE_STAGES[0];
  const assessmentName = assessments.find(item => item.id === selected)?.name ?? "No assessment selected";
  const sourceCount = Number(coverage?.source_run_count ?? 0);
  const observationCount = Number(coverage?.observed_record_count ?? 0);
  const stageStatus: Record<WorkspaceStage, string> = {
    scope: selected ? "Review scope and plan" : "Select an assessment",
    evidence: coverageLoading ? "Loading evidence status…" : coverageError ? "Evidence status unavailable" : sourceCount > 0 ? `${sourceCount} source run(s) recorded` : "Evidence import needed",
    review: coverageLoading ? "Loading observation status…" : coverageError ? "Review status unavailable" : observationCount > 0 ? `${observationCount} source observation(s) to review` : "Waiting for normalized observations",
    report: coverageLoading ? "Loading report coverage…" : coverageError ? "Report coverage unavailable" : sourceCount > 0 ? "Evidence snapshot available" : "Waiting for source evidence",
  };
  const nextSafeAction: Record<WorkspaceStage, string> = {
    scope: !selected ? "Select an assessment to begin." : "Set or confirm the exact targets and exclusions, then inspect the recorded-evidence plan.",
    evidence: coverageLoading ? "Evidence status is loading; wait for it to finish before interpreting counts." : coverageError ? "Refresh status and check the access message before importing or reviewing evidence." : sourceCount === 0 ? "Import a report you already have permission to process. This form does not run a scanner." : observationCount === 0 ? "Inspect the import result and source provenance; quarantined input does not create findings." : "Review the source provenance and confirm that the normalized observations match the artifact.",
    review: coverageLoading ? "Observation status is loading; wait before recording review decisions." : coverageError ? "Refresh status and check the access message before reviewing findings." : observationCount === 0 ? "Normalize permitted evidence before reviewing findings." : "Trace a finding to its source observation; keep unsupported impact and remediation unknown.",
    report: coverageLoading ? "Coverage is loading; wait before freezing a report." : coverageError ? "Refresh status and resolve the access error before exporting." : sourceCount === 0 ? "Import eligible recorded evidence before exporting." : "Review coverage and unknowns, then freeze the latest evidence snapshot as PDF.",
  };
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
        scope_id: scope.id, scope_revision: scope.revision, tool: importTool, format: IMPORT_OPTIONS[importTool].format, evidence_id: evidence.id,
      });
      setRecordedImportId(imported.id);
      const normalizer = IMPORT_OPTIONS[importTool].normalizer;
      const normalized = await apiJson<RecordedResult>(token, `${assessmentBase}/imports/${imported.id}/${normalizer}`, "POST", { asset_mapping: {} });
      setRecordedResult(normalized);
      setIntakeMessage("Recorded evidence processed. No network scan was run; source authenticity and rights are not independently verified.");
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
  return <section className="analyst-workspace" aria-labelledby="human-review">
    <div className="workspace-section-heading"><div><p className="eyebrow">ASSESSMENT WORKSPACE</p><h2 id="human-review">Human action review</h2></div><span className="badge">Recorded evidence · human control</span></div>
    <p>Review the exact destination, evidence, impact and rollback before recording a decision. Scanner execution is disabled.</p>
    {!token ? <form className="signin-card" onSubmit={signIn}><h3>Sign in to your assessment workspace</h3><p>Your assessment data is available only after authentication.</p><label>Username<input autoComplete="username" value={username} onChange={event => setUsername(event.target.value)} required /></label><label>Password<input type="password" autoComplete="current-password" value={password} onChange={event => setPassword(event.target.value)} required minLength={12} maxLength={128} /></label><button disabled={busy}>{busy ? "Signing in…" : "Sign in"}</button>{message && <p role="status" aria-live="polite">{message}</p>}</form> : <>
      <div className="workspace-context" aria-label="Selected assessment and mode"><div><span>Selected assessment</span><strong>{assessmentName}</strong></div><div><span>Workspace mode</span><strong>Recorded evidence · no live scans</strong></div><label>Assessment<select aria-label="Assessment" value={selected} onChange={event => { const value = event.target.value; setSelected(value); if (value) sessionStorage.setItem("aegistrace.assessment-id", value); }}><option value="">Select an assessment</option>{assessments.map(value => <option key={value.id} value={value.id}>{value.name}</option>)}</select></label><div className="workspace-context-actions"><button onClick={() => setRefresh(value => value + 1)} disabled={busy || !selected}>Refresh status</button><button className="button-secondary" onClick={() => void signOut()} disabled={busy}>Sign out</button></div></div>
      {!assessments.length && <div className="empty-state"><h3>Create your first assessment</h3><p>Use a short name to create a workspace for authorized, recorded evidence.</p><form onSubmit={createAssessment}><label>Assessment name<input value={newAssessmentName} onChange={event => setNewAssessmentName(event.target.value)} maxLength={200} required /></label><button disabled={busy}>Create assessment</button></form></div>}
      {assessments.length > 0 && <details className="new-assessment-details"><summary>Create another assessment</summary><form onSubmit={createAssessment}><label>Assessment name<input value={newAssessmentName} onChange={event => setNewAssessmentName(event.target.value)} maxLength={200} required /></label><button disabled={busy}>{busy ? "Creating…" : "Create assessment"}</button></form></details>}
      {selected && <>
        <nav className="stage-nav" aria-label="Assessment workflow" id="workspace-flow">{WORKSPACE_STAGES.map((item, index) => <button key={item.id} className={stage === item.id ? "stage-tab is-active" : "stage-tab"} aria-current={stage === item.id ? "step" : undefined} onClick={() => changeStage(item.id)}><span className="stage-tab-number">{index + 1}</span><span className="stage-tab-copy"><strong>{item.title}</strong><small>{stageStatus[item.id]}</small></span></button>)}</nav>
        <div className="stage-overview"><div><span className="eyebrow">STEP {WORKSPACE_STAGES.findIndex(item => item.id === stage) + 1} OF {WORKSPACE_STAGES.length}</span><h3>{currentStage.title}</h3><p>{currentStage.description}</p></div><div className="next-safe-action"><strong>Next safe action</strong><span>{nextSafeAction[stage]}</span></div><div className="stage-controls">{WORKSPACE_STAGES.findIndex(item => item.id === stage) > 0 && <button className="button-secondary" onClick={() => changeStage(WORKSPACE_STAGES[WORKSPACE_STAGES.findIndex(item => item.id === stage) - 1].id)}>Previous step</button>}{WORKSPACE_STAGES.findIndex(item => item.id === stage) < WORKSPACE_STAGES.length - 1 && <button onClick={() => changeStage(WORKSPACE_STAGES[WORKSPACE_STAGES.findIndex(item => item.id === stage) + 1].id)}>Continue to {WORKSPACE_STAGES[WORKSPACE_STAGES.findIndex(item => item.id === stage) + 1].short} <span aria-hidden="true">→</span></button>}<button className="button-tertiary" onClick={() => openEvidenceTarget("assessment-timeline")}>Open audit timeline</button></div></div>
        <div hidden={stage !== "scope"} aria-labelledby="stage-scope-title" className="stage-panel"><h3 className="visually-hidden" id="stage-scope-title">Scope and plan</h3><AssessmentSetup key={"AssessmentSetup:" + selected} assessmentId={selected} token={token} onChanged={() => setRefresh(value => value + 1)} /><ReplanPanel key={"ReplanPanel:" + selected} assessmentId={selected} token={token} coverage={coverage} onChanged={() => setRefresh(value => value + 1)} onOpenEvidence={openEvidenceTarget} /></div>
        <div hidden={stage !== "evidence"} aria-labelledby="stage-evidence-title" className="stage-panel"><h3 className="visually-hidden" id="stage-evidence-title">Evidence intake and provenance</h3>
          <section aria-labelledby="recorded-import"><h3 id="recorded-import">Import evidence and API definitions</h3><p>Upload a report you are authorized to process. This flow never runs a scanner or contacts a target. Nessus, Greenbone and Burp use offline report imports only; their live APIs and licenses are not verified. OpenAPI URLs are never fetched, credentials are not accepted, and Burp HTTP messages stay in the encrypted original rather than normalized output.</p><p className="notice">A supplied authorization reference is recorded as entered; it is not independently verified.</p><form onSubmit={importArtifact}><label>Evidence format<select value={importTool} onChange={event => { setImportTool(event.target.value as ImportTool); setToolVersion(""); setArtifact(null); }}><option value="Nmap">{IMPORT_OPTIONS.Nmap.label}</option><option value="OWASP ZAP">{IMPORT_OPTIONS["OWASP ZAP"].label}</option><option value="Nikto">{IMPORT_OPTIONS.Nikto.label}</option><option value="OpenAPI">{IMPORT_OPTIONS.OpenAPI.label}</option><option value="Nessus">{IMPORT_OPTIONS.Nessus.label}</option><option value="Greenbone">{IMPORT_OPTIONS.Greenbone.label}</option><option value="Burp Suite">{IMPORT_OPTIONS["Burp Suite"].label}</option></select></label><label>{IMPORT_OPTIONS[importTool].label} file<input type="file" accept={IMPORT_OPTIONS[importTool].accept} onChange={event => setArtifact(event.target.files?.[0] ?? null)} required /><small>Non-empty source artifact; maximum upload size 2 MiB.</small></label><label>Targets represented in the input<textarea value={targets} onChange={event => setTargets(event.target.value)} placeholder="One host, address or URL per line" required /></label><label>Excluded hosts/addresses<textarea value={exclusions} onChange={event => setExclusions(event.target.value)} placeholder="Optional; one host/address/URL per line" /></label><label>Source / authorization reference<input value={authorizationReference} onChange={event => setAuthorizationReference(event.target.value)} maxLength={500} required /></label><label>Version reported by source; not independently verified<input value={toolVersion} onChange={event => setToolVersion(event.target.value)} maxLength={100} required /></label><label>Capture time reported by source<input type="datetime-local" value={capturedAt} onChange={event => setCapturedAt(event.target.value)} required /></label><button disabled={intakeBusy || !artifact}>{intakeBusy ? "Processing recorded input…" : "Store and normalize recorded evidence"}</button></form>{intakeMessage && <p role="status" aria-live="polite">{intakeMessage}</p>}
            {recordedResult && <article className="result-summary"><h4>{String(recordedResult.state ?? "unknown") === "normalized" ? "Evidence normalized" : `Evidence ${String(recordedResult.state ?? "status unavailable")}`}</h4><p>{String(recordedResult.state ?? "unknown") === "normalized" ? "The supplied report was processed offline. Review source provenance and observation links before relying on it." : "This input did not produce usable normalized observations. Review the reason and limitations below."}</p><p>Mode: {String(recordedResult.mode ?? "recorded input")} · Findings created: {String(recordedResult.findings_created ?? 0)} · Source authenticity: {String(recordedResult.authenticity ?? "not independently verified")}</p>{typeof recordedResult.evidence_id === "string" && <button className="button-secondary" onClick={() => void downloadOriginal(recordedResult.evidence_id as string)}>Download exact original artifact</button>}<details><summary>Technical processing details</summary><pre tabIndex={0}>{JSON.stringify(recordedResult, null, 2)}</pre></details>{importTool === "Nmap" && <div className="replay-controls"><h4>Recorded Nmap replay</h4><p>Creates a replay manifest from the stored artifact. It does not contact a target or request approval.</p><label>Capture reference<input value={captureReference} onChange={event => setCaptureReference(event.target.value)} maxLength={300} /></label><label>Rights basis<input value={rightsBasis} onChange={event => setRightsBasis(event.target.value)} maxLength={300} /></label><button className="button-secondary" disabled={intakeBusy || !recordedImportId || !captureReference || !rightsBasis} onClick={() => void replayNmap()}>Create manifest and replay recorded input</button></div>}</article>}
            {manifestResult && <article className="review-card"><h4>{String(manifestResult.label ?? "Recorded provenance manifest")}</h4><p>Immutable manifest details</p><details><summary>View manifest</summary><pre tabIndex={0}>{JSON.stringify(manifestResult, null, 2)}</pre></details></article>}{replayResult && <article className="review-card"><h4>{String(replayResult.replay_label ?? "Recorded replay")}</h4><details><summary>View replay result</summary><pre tabIndex={0}>{JSON.stringify(replayResult, null, 2)}</pre></details></article>}
          </section>
          {coverage && <SourceReviewPanel assessmentId={selected} token={token} toolEvidence={coverage.tool_evidence} onChanged={() => setRefresh(value => value + 1)} />}
          <section id="audit-timeline-container" className="audit-timeline-anchor"><AssessmentTimeline key={"AssessmentTimeline:" + selected} assessmentId={selected} token={token} onChanged={() => setRefresh(value => value + 1)} /></section>
        </div>
        <div hidden={stage !== "review"} aria-labelledby="stage-review-title" className="stage-panel"><h3 className="visually-hidden" id="stage-review-title">Findings and review</h3>
          <ActionApprovalPanel key={"ActionApprovalReview:" + selected} assessmentId={selected} token={token} onChanged={() => setRefresh(value => value + 1)} />
          <section aria-labelledby="asset-context"><h3 id="asset-context">Reviewer risk context</h3><p>Record only values with a source/reference you reviewed. These are analyst-provided inputs, not independently verified facts. Unknown values stay unknown.</p>{assets.length === 0 ? <p>Import or record an asset before adding context.</p> : <form onSubmit={saveAssetContext}><label>Asset<select value={contextAssetId} onChange={event => setContextAssetId(event.target.value)}>{assets.map(asset => <option key={asset.id} value={asset.id}>{asset.identifier}</option>)}</select></label><label>Exposure<select value={contextExposure} onChange={event => setContextExposure(event.target.value)}><option value="unknown">Unknown</option><option value="internet-facing">Internet-facing</option><option value="internal">Internal</option><option value="restricted">Restricted</option></select></label>{contextExposure !== "unknown" && <label>Exposure source/reference<input value={contextExposureReference} onChange={event => setContextExposureReference(event.target.value)} required maxLength={1000} /></label>}<label>Exploitability<select value={contextExploitability} onChange={event => setContextExploitability(event.target.value)}><option value="unknown">Unknown</option><option value="suspected">Suspected</option><option value="confirmed">Reviewer confirmed</option></select></label>{contextExploitability !== "unknown" && <label>Evidence reference<input value={contextExploitabilityReference} onChange={event => setContextExploitabilityReference(event.target.value)} required maxLength={1000} /></label>}<label>Asset criticality<select value={contextCriticality} onChange={event => setContextCriticality(event.target.value)}><option value="">Unknown</option><option value="1">1 · Low</option><option value="2">2</option><option value="3">3 · Moderate</option><option value="4">4</option><option value="5">5 · Critical</option></select></label>{contextCriticality && <label>Criticality source/reference<input value={contextCriticalityReference} onChange={event => setContextCriticalityReference(event.target.value)} required maxLength={1000} /></label>}<label>Reviewer rationale<textarea value={contextNote} onChange={event => setContextNote(event.target.value)} required maxLength={1000} /></label><button disabled={busy}>Save context revision</button></form>}{assetContexts.map(value => <article className="review-card" key={value.id}><h4>Context revision {value.revision} · {String(value.request.provenance_kind)}</h4><details><summary>View reviewer context</summary><pre tabIndex={0}>{JSON.stringify(value.request, null, 2)}</pre></details></article>)}</section>
          {coverage && <><CorrelationReviewPanel key={"CorrelationReviewPanel:" + selected} assessmentId={selected} token={token} analytics={coverage.observation_analytics} onChanged={() => setRefresh(value => value + 1)} /><ReportFindingPanel key={"ReportFindingPanel:" + selected} assessmentId={selected} token={token} analytics={coverage.observation_analytics} onChanged={() => setRefresh(value => value + 1)} />{riskRanking && <section aria-labelledby="source-priority"><h3 id="source-priority">Evidence priority review</h3><p>{riskRanking.ranking_method} Scores are triage aids, not CVSS or calibrated risk. Observations with missing context remain unknown.</p>{riskRanking.ranked_observations.length === 0 ? <p>No observations are available for priority review.</p> : <ol>{riskRanking.ranked_observations.map(item => <li key={item.observation_id}><article className="review-card"><h4>{item.title || "Untitled source observation"}</h4><p>{item.source_tool} · Asset {item.asset_id} · Evidence {item.evidence_id}</p><p>Source CVSS: {item.source_cvss_score ?? "unknown"} · Local priority index: {item.priority.local_priority_index ?? "unknown"} ({item.priority.state})</p><p>Review attention: {item.priority.review_attention}</p><p>Missing context: {item.priority.missing_context.length ? item.priority.missing_context.join(", ") : "none verified"}</p><details><summary>Priority factors and provenance</summary><pre tabIndex={0}>{JSON.stringify(item.priority, null, 2)}</pre></details></article></li>)}</ol>}</section>}</>}
        </div>
        <div hidden={stage !== "report"} aria-labelledby="stage-report-title" className="stage-panel"><h3 className="visually-hidden" id="stage-report-title">Report and exports</h3>
          <section aria-labelledby="presentation-title"><h3 id="presentation-title" tabIndex={-1} ref={presentationHeading}>Assessment presentation</h3><div role="group" aria-label="Presentation mode"><button aria-pressed={presentation === "executive"} onClick={() => setPresentation("executive")}>Executive view</button><button aria-pressed={presentation === "analyst"} onClick={() => setPresentation("analyst")}>Analyst view</button></div><p>Both views use the current source snapshot. Capability limitations and uncertainty remain explicit.</p>{presentation === "executive" ? <ExecutiveSummary snapshot={coverage} onInspect={() => setPresentation("analyst")} /> : <><p>Analyst view includes source counts, coverage gaps, capability evidence and processing limits.</p>{coverage && <details><summary>Review-only source correlations</summary><pre tabIndex={0}>{JSON.stringify(coverage.observation_analytics ?? {}, null, 2)}</pre></details>}</>}<button className="primary-action" onClick={() => void downloadEvidenceReport()} disabled={reportBusy || !coverage || sourceCount === 0}>{reportBusy ? "Preparing PDF…" : "Freeze latest results and download PDF"}</button><p className="help-text">This freezes a point-in-time evidence summary. It is not a complete VAPT report; later changes require a new export.</p></section>
          {coverage ? <CoveragePanel snapshot={coverage} /> : <p role="status">Coverage is loading or unavailable. Refresh status before exporting; missing coverage is not a zero-risk result.</p>}
          {coverage && <section aria-labelledby="prototype-gate"><h3 id="prototype-gate">Prototype acceptance gate</h3><p>Each check is derived from stored source reviews, run results and frozen report records. Reviewer assertions do not establish organizer authority or hidden-surface coverage.</p><ul>{Object.entries(coverage.prototype_gate as Record<string, { passed: boolean; evidence: unknown; limitation?: string }>).map(([name, item]) => <li key={name}><strong>{item.passed ? "PASS" : "OPEN"}</strong> · {name.replaceAll("_", " ")}<small className="capability-description">Evidence: {JSON.stringify(item.evidence ?? null)}{item.limitation ? " · " + item.limitation : ""}</small></li>)}</ul></section>}
        </div>
      </>}
    </>}
    <p className="workspace-global-status" role="status" aria-live="polite">{message}</p>
  </section>;}

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
  return <><a className="skip-link" href="#workspace-main">Skip to workspace</a><main id="workspace-main" tabIndex={-1}>
    <header className="app-header"><div><p className="eyebrow">EVIDENCE · REASONING · HUMAN CONTROL</p><h1>AegisTrace</h1><p>A clear path from permitted security evidence to human review.</p></div><div className="header-status" role="status" aria-live="polite"><span className={error ? "status-indicator is-error" : status ? "status-indicator is-ready" : "status-indicator"} />{error || (status ? "Workspace connected" : "Connecting to workspace…")}</div></header>
    <section aria-labelledby="readiness" className="readiness-strip"><div><h2 id="readiness">Evidence platform</h2><p>Import scanner reports you already have permission to process. Review provenance, findings and frozen exports.</p></div><p className="notice">Live scanning is disabled. Recorded imports never contact targets.</p></section>
    {status && <details id="integration-capabilities" className="tool-status"><summary>Tool status and limitations <span className="badge">{status.tools.length} tools</span></summary><p>Recorded imports remain distinct from verified native integrations. Container inspection alone does not establish a working scanner integration.</p><ul>{status.tools.map((tool) => <li key={tool.name}><div><strong>{tool.name}</strong><small className="capability-description">{tool.demonstration_label}</small><small className="capability-description">{(tool.limitations ?? []).join(". ")}</small></div><span className="badge">{tool.mode ?? "planned"}</span></li>)}</ul></details>}
    <HumanReview />
    <footer>Assessment permission, evidence provenance and human review come first.</footer>
  </main></>;
}

const root = document.getElementById("root");
if (!root) throw new Error("Missing application root");
createRoot(root).render(<StrictMode><App /></StrictMode>);

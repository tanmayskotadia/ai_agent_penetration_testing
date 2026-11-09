import { useEffect, useRef, useState } from "react";
import { mutate } from "./api-client";
import type { ApiSchemas } from "./generated/api";

type Metadata = ApiSchemas["EvidenceInspectorView"];

export function EvidenceInspector({ assessmentId, token, evidenceId, observationId, onChanged }: { assessmentId: string; token: string; evidenceId: string; observationId?: string; onChanged?: () => void }) {
  const [open, setOpen] = useState(false);
  return <div><button onClick={() => setOpen(value => !value)}>{open ? "Close evidence inspector" : "Inspect matching evidence"}</button>{open && <Inspector key={assessmentId + evidenceId + (observationId ?? "")} assessmentId={assessmentId} token={token} evidenceId={evidenceId} observationId={observationId} onChanged={onChanged} />}</div>;
}

function Inspector({ assessmentId, token, evidenceId, observationId, onChanged }: { assessmentId: string; token: string; evidenceId: string; observationId?: string; onChanged?: () => void }) {
  const [metadata, setMetadata] = useState<Metadata | null>(null);
  const [snippet, setSnippet] = useState("");
  const [kind, setKind] = useState("");
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const active = useRef(false);
  const base = `/api/v1/assessments/${encodeURIComponent(assessmentId)}/evidence/${encodeURIComponent(evidenceId)}`;
  async function get<T>(path: string): Promise<T> {
    const response = await fetch(base + path, { headers: { Authorization: `Bearer ${token}` }, cache: "no-store" });
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      throw new Error(body.message ?? `Evidence access unavailable (${response.status}).`);
    }
    return response.json() as Promise<T>;
  }
  async function reload() {
    const value = await get<Metadata>("/inspector" + (observationId ? `?observation_id=${encodeURIComponent(observationId)}` : ""));
    if (active.current) setMetadata(value);
  }
  useEffect(() => {
    active.current = true;
    void reload().catch(error => { if (active.current) setStatus(String(error)); });
    return () => { active.current = false; };
  }, [base, observationId, token]);
  async function operation(action: "generate" | "review" | "read" | "download") {
    if (!metadata) return;
    setBusy(true); setStatus("");
    try {
      if (action === "generate") {
        const result = await mutate<{ snippet: string; information_kind: string }>("", base + "/redaction", token, {}, crypto.randomUUID());
        if (active.current) { setSnippet(result.snippet); setKind("Unreviewed redacted source derivative"); setMetadata(current => current ? { ...current, reviewed_derivative_available: false } : current); onChanged?.(); }
      } else if (action === "review") {
        await mutate("", base + "/redaction-review", token, {}, crypto.randomUUID());
        if (active.current) { await reload(); setKind("Reviewed source derivative"); setStatus("Derivative review recorded. This does not confirm a vulnerability or approve an action."); onChanged?.(); }
      } else if (action === "read") {
        const result = await get<{ snippet: string }>("/reviewed-derivative");
        if (active.current) { setSnippet(result.snippet); setKind("Reviewed source derivative"); }
      } else {
        const ticket = await mutate<{ ticket: string }>("", base + "/download-ticket", token, {}, crypto.randomUUID());
        const response = await fetch(base + "/original", { cache: "no-store", headers: { Authorization: `Bearer ${token}`, "X-Download-Ticket": ticket.ticket } });
        if (!response.ok) throw new Error(`Original download denied or unavailable (${response.status}).`);
        const bytes = await response.arrayBuffer();
        const hash = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))).map(value => value.toString(16).padStart(2, "0")).join("");
        if (hash !== metadata.sha256) throw new Error("Original hash mismatch. Download was refused; reload metadata and investigate.");
        if (!active.current) return;
        const url = URL.createObjectURL(new Blob([bytes], { type: "application/octet-stream" }));
        const link = document.createElement("a"); link.href = url; link.download = `${evidenceId}.bin`; link.click();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
        setStatus("Original download verified against the recorded SHA-256. Originals may contain private data.");
      }
    } catch (error) { if (active.current) setStatus(error instanceof Error ? error.message : "Evidence operation failed."); }
    finally { if (active.current) setBusy(false); }
  }
  return <section aria-label={`Evidence ${evidenceId}`} className="review-card">
    <h4>Evidence inspector · {evidenceId}</h4>
    {metadata && <><p>Observed source metadata; authenticity is not established by this view.</p><dl>
      <dt>SHA-256</dt><dd>{metadata.sha256}</dd><dt>Raw reference</dt><dd>{metadata.pointer_type}: {metadata.raw_reference}</dd>
      <dt>Tool/version</dt><dd>{metadata.tool} · {metadata.tool_version}</dd><dt>Run</dt><dd>{metadata.run_id} · {metadata.mode} · {metadata.run_state}</dd>
      <dt>Captured time</dt><dd>{metadata.captured_at}</dd><dt>Original access</dt><dd>{metadata.original_available ? metadata.original_access : "Original unavailable or retention expired"}</dd>
    </dl>
    <p>This preview shows a redacted copy of the source. Check it for sensitive details before approving it for use.</p>
    <button disabled={busy || !metadata.reviewed_derivative_available} onClick={() => void operation("read")}>Load reviewed snippet</button>
    <button disabled={busy || !metadata.can_generate_derivative} onClick={() => void operation("generate")}>Generate redacted snippet</button>
    {snippet && <><p>{kind}</p><pre tabIndex={0}>{snippet}</pre><button disabled={busy || !metadata.can_review_derivative || kind !== "Unreviewed redacted source derivative"} onClick={() => void operation("review")}>Mark derivative reviewed</button></>}
    <button disabled={busy || !metadata.original_available} onClick={() => void operation("download")}>Download private original</button></>}
    <p role="status" aria-live="polite">{status}</p>
  </section>;
}

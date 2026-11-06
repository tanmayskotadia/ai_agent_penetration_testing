import { useEffect, useRef, useState } from "react";
import type { FormEvent } from "react";
import type { ApiSchemas } from "./generated/api";
import { mutate } from "./api-client";
type Row = Record<string, unknown>;
type Resource = ApiSchemas["WorkflowResource"];
const record = (value: unknown): Row => value !== null && typeof value === "object" ? value as Row : {};
const rows = (value: unknown): Row[] => Array.isArray(value) ? value as Row[] : [];
const FIELDS = ["title", "description", "technical_impact", "business_impact", "remediation", "references", "rationale"] as const;
const LABELS = { title: "Finding title", description: "Evidence-backed description", technical_impact: "Technical impact", business_impact: "Business impact", remediation: "Actionable remediation", references: "Supporting references, one per line", rationale: "Reviewer rationale for this content" };

export function ReportFindingPanel({ assessmentId, token, analytics, onChanged }: { assessmentId: string; token: string; analytics: unknown; onChanged: () => void }) {
  const [findings, setFindings] = useState<Resource[]>([]);
  const [revision, setRevision] = useState<number | null>(null);
  const [editing, setEditing] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [fields, setFields] = useState<Record<string, string>>({});
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const active = useRef(false);
  const observations = rows(record(analytics).ranked_observations);
  const path = `/api/v1/assessments/${encodeURIComponent(assessmentId)}/report-findings`;
  async function reload() {
    const response = await fetch(path, { headers: { Authorization: `Bearer ${token}` }, cache: "no-store" });
    if (!response.ok) throw new Error(`Report content unavailable (${response.status}). Reload before saving.`);
    const body = await response.json() as { revision: number; findings: Resource[] };
    if (active.current) { setFindings(body.findings); setRevision(body.revision); }
  }
  useEffect(() => { active.current = true; void reload().catch(error => { if (active.current) setStatus(String(error)); }); return () => { active.current = false; }; }, [path, token]);
  function edit(id: string) {
    setEditing(id);
    const value = findings.find(item => item.request.finding_id === id)?.request ?? {};
    setSelected(Array.isArray(value.observation_ids) ? value.observation_ids as string[] : []);
    setFields(Object.fromEntries(FIELDS.map(field => [field, field === "references" && Array.isArray(value[field]) ? value[field].join("\n") : String(value[field] ?? "")])));
  }
  async function save(event: FormEvent) {
    event.preventDefault();
    setBusy(true); setStatus("");
    try {
      await mutate("", path, token, { expected_revision: revision, finding_id: editing || null, observation_ids: selected,
        title: fields.title?.trim(), description: fields.description?.trim(), rationale: fields.rationale?.trim(),
        technical_impact: fields.technical_impact?.trim() || null, business_impact: fields.business_impact?.trim() || null,
        remediation: fields.remediation?.trim() || null, references: (fields.references ?? "").split("\n").map(value => value.trim()).filter(Boolean) }, crypto.randomUUID());
      if (!active.current) return;
      await reload(); setEditing(""); setSelected([]); setFields({});
      setStatus("Reviewer report content saved. Freeze a new report containing all selected source revisions to include it. Prior frozen reports remain unchanged; this content does not confirm exploitability."); onChanged();
    } catch (error) { if (active.current) { setStatus(error instanceof Error ? error.message : "Report content was not saved."); await reload().catch(() => setRevision(null)); } }
    finally { if (active.current) setBusy(false); }
  }
  return <section aria-labelledby="report-content-review"><h3 id="report-content-review">Evidence-backed report content</h3>
    <p>A human reviewer can group source observations into a report finding and supply descriptions, impact, remediation and references. Empty optional fields remain unknown. Source severity/CVSS and validation decisions are preserved separately. No generated recommendation is presented as observed evidence.</p>
    <button disabled={busy} onClick={() => void reload().catch(error => setStatus(String(error)))}>Reload report content</button>
    <label>Report finding to edit<select aria-label="Report finding to edit" value={editing} onChange={event => edit(event.target.value)}><option value="">New report finding</option>{findings.map(item => <option key={item.id} value={String(item.request.finding_id)}>{String(item.request.title)} · revision {item.revision}</option>)}</select></label>
    {!observations.length ? <p>Import and normalize source evidence before writing report findings.</p> : <form onSubmit={event => void save(event)}>
      <label>Source observations<select aria-label="Report source observations" multiple value={selected} required onChange={event => setSelected([...event.target.selectedOptions].map(option => option.value))}>{observations.map(item => <option key={String(item.observation_id)} value={String(item.observation_id)}>{String(item.title)} · asset {String(item.asset_id)} · evidence {String(item.evidence_id)}</option>)}</select></label>
      {FIELDS.map(field => <label key={field}>{LABELS[field]}<textarea aria-label={LABELS[field]} required={["title", "description", "rationale"].includes(field)} minLength={field === "rationale" ? 10 : undefined} maxLength={field === "title" ? 500 : field === "rationale" ? 2000 : field === "references" ? 30000 : 4000} value={fields[field] ?? ""} onChange={event => setFields(current => ({ ...current, [field]: event.target.value }))} /></label>)}
      <button disabled={busy || revision === null || !selected.length}>Save reviewed report content</button>
    </form>}
    <p role="status" aria-live="polite">{status}</p>
    <ul>{findings.map(item => <li key={item.id}>{String(item.request.title)} · finding {String(item.request.finding_id)} · content revision {item.revision} · reviewer {String(item.request.recorded_by)} · {String(item.request.recorded_at)}</li>)}</ul>
  </section>;
}

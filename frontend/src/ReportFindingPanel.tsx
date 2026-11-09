import { useEffect, useId, useRef, useState } from "react";
import type { FormEvent } from "react";
import type { ApiSchemas } from "./generated/api";
import { mutate } from "./api-client";
import { EvidenceInspector } from "./EvidenceInspector";
type Row = Record<string, unknown>;
type Resource = ApiSchemas["WorkflowResource"];
type FrameworkReference = { framework: string; status: "applicable" | "not-applicable" | "unknown"; identifier: string | null; supporting_observation_ids: string[]; rationale: string };
type CatalogEntry = { id: string; title: string; source_url?: string };
type CatalogFramework = { key: string; name: string; version: string; role: string; description: string; entries: CatalogEntry[] };
const record = (value: unknown): Row => value !== null && typeof value === "object" ? value as Row : {};
const rows = (value: unknown): Row[] => Array.isArray(value) ? value as Row[] : [];
const FIELDS = ["title", "description", "technical_impact", "technical_impact_basis", "business_impact", "business_impact_basis", "remediation", "remediation_basis", "remediation_owner", "verification_steps", "references", "rationale"] as const;
const LABELS = { title: "Finding title", description: "Evidence-backed description", technical_impact: "Technical impact", technical_impact_basis: "Observed evidence supporting this technical impact", business_impact: "Business impact", business_impact_basis: "Business impact assumptions and basis", remediation: "Actionable remediation", remediation_basis: "Observed technology and evidence supporting this remediation", remediation_owner: "Suggested remediation owner", verification_steps: "Verification or retest steps, one per line", references: "Supporting references, one per line", rationale: "Reviewer rationale for this content" };

export function ReportFindingPanel({ assessmentId, token, analytics, onChanged }: { assessmentId: string; token: string; analytics: unknown; onChanged: () => void }) {
  const [findings, setFindings] = useState<Resource[]>([]);
  const [revision, setRevision] = useState<number | null>(null);
  const [editing, setEditing] = useState("");
  const [planId, setPlanId] = useState("");
  const [disposition, setDisposition] = useState("");
  const [selected, setSelected] = useState<string[]>([]);
  const [fields, setFields] = useState<Record<string, string>>({});
  const [catalog, setCatalog] = useState<CatalogFramework[]>([]);
  const [standardReferences, setStandardReferences] = useState<FrameworkReference[]>([]);
  const [referenceFramework, setReferenceFramework] = useState("owasp-top-10-2025");
  const [referenceStatus, setReferenceStatus] = useState<FrameworkReference["status"]>("applicable");
  const [referenceIdentifier, setReferenceIdentifier] = useState("");
  const [referenceRationale, setReferenceRationale] = useState("");
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const active = useRef(false);
  const formId = useId();
  const observations = rows(record(analytics).ranked_observations);
  const selectedObservations = observations.filter(item => selected.includes(String(item.observation_id)));
  const path = `/api/v1/assessments/${encodeURIComponent(assessmentId)}/report-findings`;
  async function reload() {
    const response = await fetch(path, { headers: { Authorization: `Bearer ${token}` }, cache: "no-store" });
    if (!response.ok) throw new Error(`Report content unavailable (${response.status}). Reload before saving.`);
    const body = await response.json() as { revision: number; findings: Resource[]; reference_catalog?: { frameworks?: CatalogFramework[] } };
    if (active.current) { setFindings(body.findings); setRevision(body.revision); setCatalog(body.reference_catalog?.frameworks ?? []); }
  }
  useEffect(() => { active.current = true; void reload().catch(error => { if (active.current) setStatus(String(error)); }); return () => { active.current = false; }; }, [path, token]);
  function edit(id: string) {
    setEditing(id);
    const value = findings.find(item => item.request.finding_id === id)?.request ?? {};
    const recommendation = record(value.recommendation);
    setPlanId(String(recommendation.plan_id ?? ""));
    setDisposition(String(recommendation.disposition ?? ""));
    setSelected(Array.isArray(value.observation_ids) ? value.observation_ids as string[] : []);
    setStandardReferences(Array.isArray(value.standard_references) ? value.standard_references as FrameworkReference[] : []);
    setFields(Object.fromEntries(FIELDS.map(field => [field, ["references", "verification_steps"].includes(field) && Array.isArray(value[field]) ? value[field].join("\n") : String(value[field] ?? "")])));
  }
  const currentFramework = catalog.find(value => value.key === referenceFramework);
  function addStandardReference() {
    const entry = currentFramework?.entries.find(value => value.id === referenceIdentifier);
    const supportedFramework = ["owasp-top-10-2025", "mitre-attack-enterprise", "nist-csf-2.0"].includes(referenceFramework);
    if (!supportedFramework || selected.length === 0 || referenceRationale.trim().length < 10 || referenceStatus === "applicable" && !entry) return;
    setStandardReferences(values => [...values, {
      framework: referenceFramework,
      status: referenceStatus,
      identifier: referenceStatus === "applicable" ? referenceIdentifier : null,
      supporting_observation_ids: [...selected],
      rationale: referenceRationale.trim(),
    }]);
    setReferenceRationale("");
  }
  async function save(event: FormEvent) {
    event.preventDefault();
    setBusy(true); setStatus("");
    try {
      await mutate("", path, token, { expected_revision: revision, finding_id: editing || null, observation_ids: selected,
        title: fields.title?.trim(), description: fields.description?.trim(), rationale: fields.rationale?.trim(),
        technical_impact: fields.technical_impact?.trim() || null, technical_impact_basis: fields.technical_impact_basis?.trim() || null,
        business_impact: fields.business_impact?.trim() || null,
        business_impact_basis: fields.business_impact_basis?.trim() || null,
        remediation: fields.remediation?.trim() || null, remediation_basis: fields.remediation_basis?.trim() || null,
        remediation_owner: fields.remediation_owner?.trim() || null,
        verification_steps: (fields.verification_steps ?? "").split("\n").map(value => value.trim()).filter(Boolean),
        references: (fields.references ?? "").split("\n").map(value => value.trim()).filter(Boolean),
        standard_references: standardReferences,
        recommendation: planId.trim() ? { plan_id: planId.trim(), disposition } : null }, crypto.randomUUID());
      if (!active.current) return;
      await reload(); setEditing(""); setSelected([]); setFields({}); setStandardReferences([]);
      setPlanId(""); setDisposition("");
      setStatus("Reviewer report content saved. Freeze a new report containing all selected source revisions to include it. Prior frozen reports remain unchanged; this content does not confirm exploitability."); onChanged();
    } catch (error) { if (active.current) { setStatus(error instanceof Error ? error.message : "Report content was not saved."); await reload().catch(() => setRevision(null)); } }
    finally { if (active.current) setBusy(false); }
  }
  return <section aria-labelledby="report-content-review"><h3 id="report-content-review">Evidence-backed report content</h3>
    <p>Group related observations into a finding. Cite the evidence for technical impact, state any business assumptions, and include a verification step for each remediation. Empty fields appear as unknown.</p>
    <button disabled={busy} onClick={() => void reload().catch(error => setStatus(String(error)))}>Reload report content</button>
    <label>Report finding to edit<select aria-label="Report finding to edit" value={editing} onChange={event => edit(event.target.value)}><option value="">New report finding</option>{findings.map(item => <option key={item.id} value={String(item.request.finding_id)}>{String(item.request.title)} · revision {item.revision}</option>)}</select></label>
    {!observations.length ? <p>Import and normalize source evidence before writing report findings.</p> : <>
      <label>Source observations<select form={formId} aria-label="Report source observations" multiple value={selected} required onChange={event => setSelected([...event.target.selectedOptions].map(option => option.value))}>{observations.map(item => <option key={String(item.observation_id)} value={String(item.observation_id)}>{String(item.title)} · asset {String(item.asset_id)} · evidence {String(item.evidence_id)}</option>)}</select></label>
      {selectedObservations.length > 0 && <div className="finding-sources">
        <h4>Selected source evidence</h4>
        <ul>{selectedObservations.map(item => <li key={String(item.observation_id)}>
          <strong>{String(item.title || "Source observation")}</strong>
          {typeof item.evidence_id === "string" && item.evidence_id
            ? <EvidenceInspector assessmentId={assessmentId} token={token} evidenceId={item.evidence_id} observationId={String(item.observation_id)} />
            : <p className="help-text">This observation has no source artifact reference in the current snapshot.</p>}
        </li>)}</ul>
      </div>}
      <form id={formId} onSubmit={event => void save(event)}>
      {FIELDS.map(field => <label key={field}>{LABELS[field]}{["technical_impact_basis", "business_impact_basis", "remediation_basis", "verification_steps"].includes(field) && <span> (required when the corresponding impact or remediation is supplied)</span>}<textarea aria-label={LABELS[field]} required={["title", "description", "rationale"].includes(field) || field === "technical_impact_basis" && Boolean(fields.technical_impact?.trim()) || field === "business_impact_basis" && Boolean(fields.business_impact?.trim()) || ["remediation_basis", "verification_steps"].includes(field) && Boolean(fields.remediation?.trim())} minLength={field === "rationale" ? 10 : undefined} maxLength={field === "title" ? 500 : field === "rationale" ? 2000 : field === "remediation_owner" ? 200 : ["references", "verification_steps"].includes(field) ? 30000 : 4000} value={fields[field] ?? ""} onChange={event => setFields(current => ({ ...current, [field]: event.target.value }))} /></label>)}
      <fieldset className="standards-reference-editor"><legend>Applicable framework references</legend><p>Choose only a mapping supported by the selected observations. CVE, CWE and CVSS values are copied from source observations automatically and stay labeled source-reported. An ATT&amp;CK mapping is a reviewer hypothesis, not proof an adversary action occurred. Formal compliance is never inferred.</p>
        <label>Framework<select aria-label="Framework reference" value={referenceFramework} onChange={event => { setReferenceFramework(event.target.value); setReferenceIdentifier(""); }}>
          {catalog.filter(value => ["owasp-top-10-2025", "mitre-attack-enterprise", "nist-csf-2.0"].includes(value.key)).map(value => <option key={value.key} value={value.key}>{value.name} · {value.version}</option>)}
        </select></label>
        <label>Applicability<select aria-label="Framework applicability" value={referenceStatus} onChange={event => setReferenceStatus(event.target.value as FrameworkReference["status"])}><option value="applicable">Applicable mapping</option><option value="not-applicable">Not applicable</option><option value="unknown">Unknown</option></select></label>
        {referenceStatus === "applicable" && <label>Curated identifier<select aria-label="Curated framework identifier" value={referenceIdentifier} onChange={event => setReferenceIdentifier(event.target.value)} required><option value="">Select a supported identifier</option>{currentFramework?.entries.map(value => <option value={value.id} key={value.id}>{value.id} · {value.title}</option>)}</select></label>}
        <label>Mapping rationale<textarea aria-label="Framework mapping rationale" minLength={10} maxLength={2000} value={referenceRationale} onChange={event => setReferenceRationale(event.target.value)} placeholder="Explain how the selected observation supports this mapping, or why it is unknown/not applicable." /></label>
        <button type="button" className="button-secondary" disabled={!selected.length || referenceRationale.trim().length < 10 || referenceStatus === "applicable" && !referenceIdentifier} onClick={addStandardReference}>Add framework reference</button>
        {standardReferences.length > 0 && <ul aria-label="Framework references to save">{standardReferences.map((value, index) => <li key={`${value.framework}-${value.status}-${value.identifier}-${index}`}><span>{currentFramework?.key === value.framework ? currentFramework.name : catalog.find(item => item.key === value.framework)?.name ?? value.framework} · {value.status}{value.identifier ? ` · ${value.identifier}` : ""} · {value.supporting_observation_ids.length} linked observation(s) — {value.rationale}</span><button type="button" className="button-tertiary" aria-label={`Remove framework reference ${index + 1}`} onClick={() => setStandardReferences(values => values.filter((_, item) => item !== index))}>Remove</button></li>)}</ul>}
      </fieldset>
      <details>
        <summary>Related recommendation</summary>
        <p>Copy a saved plan ID from Scope &amp; plan and select all observations cited by that plan.</p>
        <label>Recommendation plan ID<input value={planId} onChange={event => setPlanId(event.target.value)} maxLength={36} autoComplete="off" /></label>
        {planId.trim() && <label>How did you use this recommendation?<select required value={disposition} onChange={event => setDisposition(event.target.value)}>
          <option value="">Choose a review outcome</option>
          <option value="used">Informed this finding</option>
          <option value="edited">Informed revised wording</option>
          <option value="considered">Considered only</option>
        </select></label>}
      </details>
      <button className="primary-action" disabled={busy || revision === null || !selected.length || Boolean(planId.trim() && !disposition)}>Save reviewed report content</button>
      </form>
    </>}
    <p role="status" aria-live="polite">{status}</p>
    <ul>{findings.map(item => <li key={item.id}>{String(item.request.title)} · finding {String(item.request.finding_id)} · content revision {item.revision} · reviewer {String(item.request.recorded_by)} · {String(item.request.recorded_at)}</li>)}</ul>
  </section>;
}

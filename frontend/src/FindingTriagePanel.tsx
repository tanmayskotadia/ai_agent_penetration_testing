import { useEffect, useRef, useState } from "react";
import { ApiFailure, mutate } from "./api-client";

type Row = Record<string, unknown>;
type Props = { assessmentId: string; token: string; analytics: unknown; onChanged: () => void };
type History = { revision: number; latest_by_observation: Record<string, Row>; reviews: Row[]; history_truncated: boolean };
const rows = (value: unknown): Row[] => Array.isArray(value) ? value as Row[] : [];
const record = (value: unknown): Row => value !== null && typeof value === "object" ? value as Row : {};
const text = (value: unknown) => value == null || value === "" ? "unknown" : String(value);
const confidence = (item: Row) => typeof item.confidence === "number" && item.confidence_method ? "source-reported" : "unknown";
const severeUncertain = (item: Row) => (Number(item.source_cvss_score) >= 7 || ["high", "critical"].includes(String(item.source_severity).toLowerCase())) && (confidence(item) === "unknown" || Number(item.confidence) < 0.5);
const STATES = ["suspected", "confirmed", "false-positive", "contradictory", "unknown"];

export function FindingTriagePanel({ assessmentId, token, analytics, onChanged }: Props) {
  const [history, setHistory] = useState<History | null>(null);
  const [filters, setFilters] = useState<Record<string, string>>({});
  const [states, setStates] = useState<Record<string, string>>({});
  const [reasons, setReasons] = useState<Record<string, string>>({});
  const [references, setReferences] = useState<Record<string, string[]>>({});
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const active = useRef(false);
  const path = `/api/v1/assessments/${encodeURIComponent(assessmentId)}/finding-reviews`;
  const observations = rows(record(analytics).ranked_observations);
  async function reload() {
    const response = await fetch(path, { headers: { Authorization: `Bearer ${token}` } });
    if (!response.ok) throw new Error(`Review history unavailable (${response.status}). Reload before saving.`);
    const body = await response.json() as History;
    if (active.current) setHistory(body);
  }
  useEffect(() => {
    active.current = true;
    void reload().catch(error => { if (active.current) setMessage(String(error)); });
    return () => { active.current = false; };
  }, [path, token]);
  const currentState = (item: Row) => text(history?.latest_by_observation[String(item.observation_id)]?.validation_state ?? item.validation_state);
  const visible = observations.filter(item => (!filters.asset || text(item.asset_id) === filters.asset)
    && (!filters.tool || text(item.source_tool) === filters.tool)
    && (!filters.severity || text(item.source_severity) === filters.severity)
    && (!filters.validation || currentState(item) === filters.validation)
    && (!filters.confidence || confidence(item) === filters.confidence));
  async function save(item: Row) {
    if (!history) return;
    const id = String(item.observation_id);
    const state = states[id] ?? currentState(item);
    setBusy(true); setMessage("");
    try {
      await mutate("", path, token, {
        observation_id: id, expected_revision: history.revision,
        validation_state: state, rationale: reasons[id]?.trim(),
        contradictory_observation_ids: state === "contradictory" ? references[id] ?? [] : [],
      }, crypto.randomUUID());
      if (!active.current) return;
      await reload(); setReasons(current => ({ ...current, [id]: "" }));
      setStates(current => { const next = { ...current }; delete next[id]; return next; });
      setMessage("Reviewer decision saved. Ranking will refresh; create a new report snapshot to include this decision. Existing frozen reports retain their prior review.");
      onChanged();
    } catch (error) {
      if (active.current) {
        if (error instanceof ApiFailure && error.status === 409) {
          setStates({}); setReferences({});
          setMessage("Another reviewer changed the decisions. Current history was reloaded; review the new state before saving again. Your rationale draft is retained.");
          await reload().catch(() => { setHistory(null); });
        } else setMessage(error instanceof Error ? error.message : "Review was not saved.");
      }
    } finally { if (active.current) setBusy(false); }
  }
  return <section aria-labelledby="finding-triage"><h3 id="finding-triage">Finding validation and uncertainty</h3>
    <p>Observed source records and reviewer decisions remain separate. Confidence is source-reported or unknown; no calibrated probability is established. Accepted risk and remediation tracking are deferred and are not marked as remediated.</p>
    <p>{observations.filter(severeUncertain).length} potentially severe observations have low or unknown confidence. They remain in the inventory regardless of review classification.</p>
    <fieldset><legend>Filter source observations</legend>
      {([ ["asset", "Asset", "asset_id"], ["tool", "Tool", "source_tool"], ["severity", "Source severity", "source_severity"] ] as const).map(([key, label, field]) => <label key={key}>{label}<select aria-label={label} value={filters[key] ?? ""} onChange={event => setFilters(current => ({ ...current, [key]: event.target.value }))}><option value="">All</option>{[...new Set(observations.map(item => text(item[field])))].sort().map(value => <option key={value}>{value}</option>)}</select></label>)}
      <label>Validation<select aria-label="Validation" value={filters.validation ?? ""} onChange={event => setFilters(current => ({ ...current, validation: event.target.value }))}><option value="">All</option>{STATES.map(value => <option key={value}>{value}</option>)}</select></label>
      <label>Confidence<select aria-label="Confidence" value={filters.confidence ?? ""} onChange={event => setFilters(current => ({ ...current, confidence: event.target.value }))}><option value="">All</option><option>unknown</option><option>source-reported</option></select></label>
      <button onClick={() => setFilters({})}>Clear finding filters</button>
    </fieldset>
    <p>Showing {visible.length} of {observations.length} observations. {observations.filter(item => severeUncertain(item) && !visible.includes(item)).length} severe uncertain observations are hidden by your filters.</p>
    <button disabled={busy} onClick={() => void reload().then(() => setMessage("Current reviewer history reloaded.")).catch(error => { setHistory(null); setMessage(String(error)); })}>Reload finding reviews</button>
    {visible.map(item => {
      const id = String(item.observation_id), review = history?.latest_by_observation[id];
      const state = states[id] ?? currentState(item);
      return <article className="review-card" key={id} aria-label={`Finding ${id}`}>
        <h4>{text(item.title)}{severeUncertain(item) ? " · Severe uncertain evidence: review required" : ""}</h4>
        <p>Observed evidence · source state {text(item.validation_state)} · {text(item.source_tool)} · asset {text(item.asset_id)}</p>
        <p>Observation {id} · run {text(item.run_id)} · observed {text(item.observed_at)} · source reference {text(item.source_key)} · evidence {text(item.evidence_id)}</p>
        <p>Source severity {text(item.source_severity)} · CVSS {text(item.source_cvss_score)} · version {text(item.source_cvss_version)} · vector {text(item.source_cvss_vector)}</p>
        <p>Source confidence {text(item.confidence)} · method {text(item.confidence_method)} · {confidence(item)} · not calibrated</p>
        <p>Current reviewer state: {review ? text(review.validation_state) : "no reviewer decision"} · rationale {text(review?.rationale)}</p>
        <label>Reviewer state<select aria-label={`Reviewer state ${id}`} value={state} onChange={event => setStates(current => ({ ...current, [id]: event.target.value }))}>{STATES.map(value => <option key={value}>{value}</option>)}</select></label>
        {state === "contradictory" && <label>Contradictory observations<select aria-label={`Contradictory observations ${id}`} multiple value={references[id] ?? []} onChange={event => setReferences(current => ({ ...current, [id]: [...event.target.selectedOptions].map(option => option.value) }))}>{observations.filter(other => other.observation_id !== id).map(other => <option key={String(other.observation_id)} value={String(other.observation_id)}>{text(other.title)} · {text(other.observation_id)} · evidence {text(other.evidence_id)}</option>)}</select></label>}
        <label>Reviewer rationale<textarea aria-label={`Reviewer rationale ${id}`} value={reasons[id] ?? ""} maxLength={2000} onChange={event => setReasons(current => ({ ...current, [id]: event.target.value }))} /></label>
        <button disabled={busy || !history || !reasons[id]?.trim() || (state === "contradictory" && !references[id]?.length)} onClick={() => void save(item)}>Record finding decision</button>
        <details><summary>Decision history for {id}</summary>{history?.history_truncated && <p>History is limited to the latest 100 assessment decisions.</p>}<ol>{history?.reviews.filter(value => record(value.request).observation_id === id).map(value => { const request = record(value.request); return <li key={String(value.id)}>Revision {text(value.revision)} · {text(request.validation_state)} · {text(request.recorded_by)} · {text(request.recorded_at)}<p>{text(request.rationale)}</p><p>Contradiction references: {JSON.stringify(request.contradictory_observation_ids ?? [])}</p></li>; })}</ol></details>
      </article>;
    })}
    {!visible.length && <p>No observations match these filters. Clear filters or import evidence.</p>}
    <p role="status" aria-live="polite">{message}</p>
  </section>;
}

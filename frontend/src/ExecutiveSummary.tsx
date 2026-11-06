type Row = Record<string, unknown>;
const record = (value: unknown): Row => value !== null && typeof value === "object" ? value as Row : {};
const rows = (value: unknown): Row[] => Array.isArray(value) ? value as Row[] : [];
const text = (value: unknown) => value == null ? "unknown" : String(value);

export function ExecutiveSummary({ snapshot, onInspect }: { snapshot: Row | null; onInspect: () => void }) {
  if (!snapshot) return <section aria-label="Executive assessment summary"><h4>Executive assessment summary</h4><p role="status">Assessment summary is loading or unavailable. Refresh reviews to retry; unknown data is not a zero-risk result.</p></section>;
  const analytics = record(snapshot.observation_analytics);
  const observations = rows(analytics.ranked_observations);
  const distribution = new Map<string, number>();
  for (const item of observations) { const label = text(item.source_severity); distribution.set(label, (distribution.get(label) ?? 0) + 1); }
  return <section aria-label="Executive assessment summary"><h4>Executive assessment summary</h4>
    <p>Evidence coverage: {text(snapshot.coverage_state)}. Snapshot completeness: {snapshot.snapshot_complete === true ? "within current row bounds" : "unknown or incomplete"}.</p>
    <p>{text(snapshot.asset_count)} recorded assets · {text(snapshot.source_run_count)} source runs · {text(snapshot.observed_record_count)} source observations. These are source records, not confirmed vulnerabilities.</p>
    <p>Business impact, remediation recommendations and exploitability remain unknown unless supported by reviewed evidence. A severity distribution does not establish business risk or complete assessment coverage.</p>
    <div className="coverage-table" tabIndex={0} role="region" aria-label="Source severity distribution"><table><caption>Source-reported severity; observations in this bounded snapshot</caption><thead><tr><th scope="col">Severity label</th><th scope="col">Observation count</th></tr></thead><tbody>{[...distribution].sort().map(([label, count]) => <tr key={label}><th scope="row">{label}</th><td>{count}</td></tr>)}</tbody></table></div>
    {!observations.length && <p>No source observations are available. This does not establish that the assessment is clean.</p>}
    <h5>Coverage limitations and unavailable capabilities</h5>
    <ul>{(Array.isArray(snapshot.gaps) ? snapshot.gaps : []).map((value, index) => <li key={index}>{text(value)}</li>)}</ul>
    <ul>{rows(snapshot.tool_evidence).map(item => { const capability = record(item.capability); return <li key={text(item.name)}>{text(item.name)}: {text(capability.mode)} · {text(capability.demonstration_label)}</li>; })}</ul>
    <p>Observed evidence, reviewer decisions and AI proposals have separate meanings. Live execution and source authenticity are not implied by this summary.</p>
    <button onClick={onInspect}>Open analyst view and source trace</button>
  </section>;
}

type RecordValue = Record<string, unknown>;
const record = (value: unknown): RecordValue => value !== null && typeof value === "object" && !Array.isArray(value) ? value as RecordValue : {};
const records = (value: unknown): RecordValue[] => Array.isArray(value) ? value.map(record) : [];
const text = (value: unknown): string => value === null || value === undefined ? "unknown" : typeof value === "object" ? JSON.stringify(value) : String(value);
const list = (value: unknown): string => Array.isArray(value) && value.length > 0 ? value.map(text).join(", ") : "none verified";

export function CoveragePanel({ snapshot }: { snapshot: RecordValue }) {
  const coverage = record(snapshot.operation_coverage);
  return <section aria-labelledby="assessment-coverage">
    <h3 id="assessment-coverage">Assessment coverage and integration evidence</h3>
    <p><strong>{text(snapshot.coverage_state)}</strong> · Captured {text(snapshot.captured_at)}</p>
    <p>Snapshot SHA-256: <code>{text(snapshot.snapshot_sha256)}</code>. A report preserves the snapshot taken when it was frozen; current workspace results may be newer.</p>
    {snapshot.snapshot_complete === false && <p role="status">This snapshot reached its row limit. Omitted data prevents complete coverage claims.</p>}
    <ul>{Array.isArray(snapshot.gaps) && snapshot.gaps.map((gap, index) => <li key={index}>{text(gap)}</li>)}</ul>
    <p>Source runs: {text(snapshot.source_run_count)} · Assets: {text(snapshot.asset_count)} · Endpoint catalog: {text(snapshot.endpoint_catalog_count)} · Source observations: {text(snapshot.observed_record_count)}</p>
    <p>Current API credential states: {text(snapshot.api_credential_states)}. Availability is metadata, not proof of authentication. Revocation does not erase historical request outcomes.</p>
    <p>Native job states: {text(snapshot.native_job_states)} · API job states: {text(snapshot.api_job_states)}. Expired running leases are shown as unknown.</p>
    <h4>All seven scanner integrations</h4>
    <p>Imported records do not promote an integration to working status. Guarded candidate formats remain distinct from verified supported formats. API operation checks are a separate execution path.</p>
    <div className="coverage-table"><table><caption>Current scanner capability and assessment evidence</caption>
      <thead><tr><th scope="col">Tool / mode</th><th scope="col">Edition and license</th><th scope="col">Formats</th><th scope="col">Verification</th><th scope="col">Assessment records and gaps</th></tr></thead>
      <tbody>{records(snapshot.tool_evidence).map(tool => {
        const capability = record(tool.capability);
        return <tr key={text(tool.name)}><th scope="row">{text(tool.name)}<br /><strong>{text(capability.mode)}</strong></th>
          <td>Edition: {text(capability.installed_edition)}<br />Version: {text(capability.installed_version)}<br />License: {text(capability.license_status)}</td>
          <td>Verified: {list(capability.supported_formats)}<br />Candidate guards: {list(capability.guarded_containers)}</td>
          <td>{text(capability.demonstration_label)}<br />Last verified: {text(capability.last_verified_at)}<br />Run: {text(capability.last_verified_run_id)}</td>
          <td>Recorded/imported runs: {text(tool.recorded_import_count)}<br />Normalization states: {text(tool.normalization_states)}<br />Job states: {text(tool.job_states)}<br />Limitations: {list(capability.limitations)}</td></tr>;
      })}</tbody></table></div>
    {(["live-request", "disposable-test"] as const).map(mode => {
      const summary = record(coverage[mode]);
      const operations = records(summary.operations);
      return <section key={mode} aria-label={`${mode} endpoint coverage`}><h4>{mode === "live-request" ? "Live worker request outcomes" : "Disposable test outcomes"}</h4>
        <p>{text(summary.coverage_state)} · Declared operations: {text(summary.declared_operation_count)} · Latest attempted: {text(summary.attempted_count)} · Ever attempted: {text(summary.ever_attempted_count)}</p>
        <p>States: {text(summary.state_counts)}. Authentication: {text(summary.authentication_counts)}.</p>
        <p>These counts describe the declared OpenAPI inventory. HTTP success does not establish authenticated identity, a vulnerability, or coverage of hidden endpoints.</p>
        {operations.length > 0 && <div className="coverage-table"><table><caption>Latest outcome per asset, endpoint and method ({mode})</caption><thead><tr><th scope="col">Method / path</th><th scope="col">State</th><th scope="col">Authentication</th><th scope="col">Source</th></tr></thead>
          <tbody>{operations.slice(0, 100).map(operation => <tr key={text(operation.endpoint_id)}><th scope="row">{text(operation.method)} {text(operation.path)}<br />Asset: {text(operation.asset_id)}</th><td>{text(operation.state)}<br />HTTP: {text(operation.status_code)}</td><td>{text(operation.authentication)}</td><td>Check: {text(operation.check_id)}<br />Evidence: {text(operation.source_evidence_id)}</td></tr>)}</tbody></table></div>}
        {operations.length > 100 && <p>Showing 100 of {operations.length} operations. The authenticated coverage API and frozen JSON export retain the full bounded snapshot.</p>}
      </section>;
    })}
  </section>;
}

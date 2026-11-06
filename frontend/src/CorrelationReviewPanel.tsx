import { useEffect, useState } from "react";
import { mutate } from "./api-client";
import { FindingTriagePanel } from "./FindingTriagePanel";

type Row = Record<string, unknown>;
type Props = {
  assessmentId: string;
  token: string;
  analytics: unknown;
  onChanged: () => void;
};
const rows = (value: unknown): Row[] =>
  Array.isArray(value) ? value.filter(item => item !== null && typeof item === "object") as Row[] : [];
const ids = (value: unknown): string[] => Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
const location = (item: Row): string => {
  const endpoint = item.endpoint !== null && typeof item.endpoint === "object" ? item.endpoint as Row : null;
  if (endpoint) return String(endpoint.method ?? "ANY") + " " + String(endpoint.path ?? "path unknown");
  const service = item.service !== null && typeof item.service === "object" ? item.service as Row : null;
  if (service) return String(service.protocol ?? "transport unknown").toUpperCase() + "/" + String(service.port ?? "port unknown") + (service.observed_name ? " · " + String(service.observed_name) : "");
  return "Location unavailable";
};
const parameters = (item: Row): string => ids(item.parameter_names).join(", ") || "none reported";
const occurrence = (item: Row): string => String(item.source_tool ?? "unknown source") + " · " + location(item) + " · parameters: " + parameters(item) + " · asset " + String(item.asset_id ?? "unknown") + " · evidence " + String(item.evidence_id ?? "unavailable") + " · observation " + String(item.observation_id ?? item.id ?? "unavailable");

export function CorrelationReviewPanel({ assessmentId, token, analytics: analyticsValue, onChanged }: Props) {
  const [revision, setRevision] = useState<number | null>(null);
  const [history, setHistory] = useState<Row[]>([]);
  const [rationale, setRationale] = useState("");
  const [selectedSplit, setSelectedSplit] = useState("");
  const [partitionText, setPartitionText] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);
  const path = "/api/v1/assessments/" + encodeURIComponent(assessmentId) + "/correlations/reviews";
  async function refresh() {
    if (!token || !assessmentId) return;
    const response = await fetch(path, { headers: { Authorization: "Bearer " + token } });
    if (!response.ok) throw new Error("Review history could not be loaded (" + response.status + ").");
    const body = await response.json() as { reviews?: Row[]; revision: number };
    setHistory(rows(body.reviews)); setRevision(body.revision);
  }
  useEffect(() => {
    let active = true;
    void fetch(path, { headers: { Authorization: "Bearer " + token } })
      .then(async response => {
        if (!response.ok) throw new Error("Review history could not be loaded (" + response.status + ").");
        return await response.json() as { reviews?: Row[]; revision: number };
      })
      .then(body => { if (active) { setHistory(rows(body.reviews)); setRevision(body.revision); } })
      .catch(error => { if (active) setMessage(error instanceof Error ? error.message : "Review history could not be loaded."); });
    return () => { active = false; };
  }, [assessmentId, token, path]);
  async function submit(payload: Row): Promise<boolean> {
    if (!rationale.trim() && payload.action !== "undo") {
      setMessage("Enter the reviewer rationale before saving this decision.");
      return false;
    }
    if (revision === null) { setMessage("Reload review history before making a decision."); return false; }
    setBusy(true);
    setMessage("");
    try {
      await mutate<Row>("", path, token, { ...payload, expected_revision: revision }, crypto.randomUUID());
      setRationale("");
      await refresh();
      onChanged();
      setMessage("Reviewer decision recorded. Source observations remain unchanged.");
      return true;
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Reviewer decision was not saved.");
      await refresh().catch(() => setRevision(null)); onChanged();
      return false;
    } finally {
      setBusy(false);
    }
  }
  const analytics = analyticsValue !== null && typeof analyticsValue === "object" ? analyticsValue as Row : {};
  const candidates = rows(analytics.cross_tool_candidate_groups);
  const clusters = rows(analytics.reviewed_clusters);
  const splits = rows(analytics.reviewed_splits);
  const latest = history.at(-1);
  return <section aria-labelledby="correlation-review">
    <h3 id="correlation-review">Cross-tool duplicate review</h3>
    <p>Candidate groups are suggestions. Only your explicit review creates a merged group; source observations and their evidence stay intact. Review decisions are auditable and reversible.</p>
    <label>Reviewer rationale<input value={rationale} onChange={event => setRationale(event.target.value)} maxLength={2000} /></label>
    <h4>Unconfirmed candidates</h4>
    {candidates.length === 0 ? <p>No cross-tool candidate groups are currently available.</p> : candidates.map(candidate => {
      const members = rows(candidate.observations);
      const memberIds = ids(candidate.observation_ids);
      return <article className="review-card" key={String(candidate.match_value) + memberIds.join(":")}>
        <h5>{String(candidate.match_basis ?? "Candidate correlation")} · {String(candidate.review_state ?? "review-required")}</h5>
        <p>Assets: {ids(candidate.asset_ids).join(", ") || "unknown"} · Source tools: {ids(candidate.source_tools).join(", ") || "unknown"}</p>
        <ul>{members.map(item => <li key={String(item.observation_id)}>{String(item.title)} · {occurrence(item)}</li>)}</ul>
        {candidate.review_state === "reviewer-split" && <p>Reviewer marked this candidate as distinct: {String(candidate.reviewer_rationale ?? "No rationale")}</p>}
        <button disabled={busy || memberIds.length < 2 || !rationale.trim()} onClick={() => void submit({ action: "merge", observation_ids: memberIds, rationale: rationale.trim() })}>Confirm duplicate and merge</button>
      </article>;
    })}
    <h4>Reviewer-confirmed groups</h4>
    {clusters.length === 0 ? <p>No reviewer-confirmed duplicate groups.</p> : clusters.map(group => <article className="review-card" key={String(group.cluster_id)}>
      <p>Cluster {String(group.cluster_id)} · {String(group.occurrence_count)} source occurrences · assets {ids(group.asset_ids).join(", ")}</p>
      <p>Rationale: {String(group.rationale)}</p>
      <ul>{rows(group.observations).map(item => <li key={String(item.observation_id)}>{String(item.title)} · {occurrence(item)}</li>)}</ul>
      <button disabled={busy || !rationale.trim()} onClick={() => { setSelectedSplit(String(group.cluster_id)); setPartitionText(ids(group.observation_ids).join("\n")); }}>Prepare split</button>
    </article>)}
    {selectedSplit && <div className="review-card">
      <label>One partition per line; list observation IDs separated by commas<textarea value={partitionText} onChange={event => setPartitionText(event.target.value)} rows={5} /></label>
      <button disabled={busy || !rationale.trim()} onClick={() => {
        const partitions = partitionText.split("\n").map(line => line.split(",").map(item => item.trim()).filter(Boolean));
        void submit({ action: "split", cluster_id: selectedSplit, partitions, rationale: rationale.trim() }).then(saved => {
          if (saved) { setSelectedSplit(""); setPartitionText(""); }
        });
      }}>Save split decision</button>
      <button disabled={busy} onClick={() => setSelectedSplit("")}>Cancel split</button>
    </div>}
    {splits.map(group => <article className="review-card" key={String(group.cluster_id)}>
      <p>Reviewer-split candidate · {String(group.rationale)} · partitions: {JSON.stringify(group.partitions)}</p>
    </article>)}
    {latest && <button disabled={busy} onClick={() => void submit({ action: "undo", target_review_id: String(latest.id), rationale: "Undo the latest correlation review" })}>Undo latest review</button>}
    <ol aria-label="Correlation review history">{history.map(review => <li key={String(review.id)}>Revision {String(review.revision)} · {String(rows([review.request])[0]?.action ?? "unknown")} · {String(review.id)}</li>)}</ol>
    <FindingTriagePanel assessmentId={assessmentId} token={token} analytics={analytics} onChanged={onChanged} />
    <p role="status" aria-live="polite">{message}</p>
  </section>;
}

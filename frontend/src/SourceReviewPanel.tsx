import { useMemo, useState } from "react";
import { mutate } from "./api-client";

type Row = Record<string, unknown>;
type Props = {
  assessmentId: string;
  token: string;
  toolEvidence: unknown;
  onChanged: () => void;
};
const rows = (value: unknown): Row[] =>
  Array.isArray(value)
    ? value.filter(item => item !== null && typeof item === "object") as Row[]
    : [];
const record = (value: unknown): Row =>
  value !== null && typeof value === "object" && !Array.isArray(value) ? value as Row : {};

export function SourceReviewPanel({ assessmentId, token, toolEvidence, onChanged }: Props) {
  const [provenance, setProvenance] = useState("test-only");
  const [rationale, setRationale] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState("");
  const sources = useMemo<Row[]>(
    () => rows(toolEvidence).flatMap(tool => rows(tool.source_records).map(source => ({
      ...source,
      tool: tool.name,
    }))),
    [toolEvidence],
  );

  async function review(source: Row, decision: "verify" | "reject") {
    if (!rationale.trim()) {
      setMessage("Enter what you checked and the source's permitted provenance.");
      return;
    }
    const normalizationId = String(source.id ?? "");
    setBusy(normalizationId);
    setMessage("");
    try {
      await mutate<Row>(
        "",
        "/api/v1/assessments/" + encodeURIComponent(assessmentId) + "/source-reviews",
        token,
        {
          normalization_id: normalizationId,
          source_sha256: String(source.source_sha256 ?? ""),
          decision,
          provenance,
          rationale: rationale.trim(),
        },
        crypto.randomUUID(),
      );
      setRationale("");
      setMessage("Source review recorded. Original evidence and normalization are unchanged.");
      onChanged();
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Source review could not be saved.");
    } finally {
      setBusy("");
    }
  }

  return <section aria-labelledby="source-review">
    <h3 id="source-review">Source provenance review</h3>
    <p>Reviewing a source records a human assertion. It does not grant scan authority, change the source file, or turn observations into confirmed vulnerabilities.</p>
    <label>Artifact provenance
      <select value={provenance} onChange={event => setProvenance(event.target.value)}>
        <option value="test-only">Handcrafted or test-only</option>
        <option value="genuine-permitted-capture">Genuine capture with permission already established</option>
      </select>
    </label>
    <label>What did you review?
      <input value={rationale} onChange={event => setRationale(event.target.value)} maxLength={2000} />
    </label>
    {sources.length === 0 ? <p>No normalized source records are available for review.</p> : sources.map(source => {
      const id = String(source.id ?? "");
      const state = String(source.authenticity ?? "not-verified");
      return <article className="review-card" key={id}>
        <h4>{String(source.tool)} · {state}</h4>
        <p>Normalization: <code>{id}</code></p>
        <p>SHA-256: <code>{String(source.source_sha256 ?? "unknown")}</code></p>
        <p>Evidence: {String(source.evidence_id ?? "unknown")} · Run: {String(source.run_id ?? "unknown")} · {String(source.mode ?? "unknown mode")}</p>
        <p>{String(source.source_review_rationale ?? "No reviewer rationale recorded.")}</p>
        <button disabled={Boolean(busy) || !rationale.trim()} onClick={() => void review(source, "verify")}>Record this source review</button>
        <button disabled={Boolean(busy) || !rationale.trim()} onClick={() => void review(source, "reject")}>Reject provenance</button>
      </article>;
    })}
    <p role="status" aria-live="polite">{message}</p>
  </section>;
}

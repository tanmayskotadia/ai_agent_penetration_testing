import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import type { ApiSchemas } from "./generated/api";
import "./style.css";

type Status = { stage: string; live_scans_enabled: boolean; tools: ApiSchemas["Capability"][] };

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
  return <main>
    <header><p className="eyebrow">EVIDENCE. REASONING. HUMAN CONTROL.</p><h1>AegisTrace</h1><p>A clearer path from security evidence to action.</p></header>
    <section aria-labelledby="readiness"><h2 id="readiness">Evidence platform</h2><p>Authenticated assessment, evidence and audit APIs are available. Analyst screens and scanner integrations are being built.</p><p className="notice">Live testing is disabled. Authorized scope and verified execution controls are required before live testing.</p>
      <div role="status" aria-live="polite">{error || (status ? "Connected to the workspace" : "Connecting to the workspace…")}</div>
    </section>
    {status && <section aria-labelledby="coverage"><h2 id="coverage">Integration capabilities</h2><ul>{status.tools.map((tool) => <li key={tool.name}><div><span>{tool.name}</span><small className="capability-description">{tool.demonstration_label}</small><small className="capability-description">{(tool.limitations ?? []).join(". ")}</small></div><span className="badge">{tool.mode ?? "planned"}</span></li>)}</ul><p>Container inspection does not count as a working native integration. Recorded imports remain distinct from live scans.</p></section>}
    <footer>Assessment permission, evidence provenance and human review come first.</footer>
  </main>;
}

const root = document.getElementById("root");
if (!root) throw new Error("Missing application root");
createRoot(root).render(<StrictMode><App /></StrictMode>);

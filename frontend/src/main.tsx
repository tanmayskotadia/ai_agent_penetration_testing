import { StrictMode, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import "./style.css";

type Status = { stage: string; live_scans_enabled: boolean; tools: { name: string; status: string }[] };

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
    <section aria-labelledby="readiness"><h2 id="readiness">Assessment workspace</h2><p>The workspace foundation is ready for development. Security assessment features are being built.</p><p className="notice">Live testing is disabled. Organizer authorization and reviewed assessment controls are required before testing.</p>
      <div role="status" aria-live="polite">{error || (status ? "Connected to the workspace" : "Connecting to the workspace…")}</div>
    </section>
    {status && <section aria-labelledby="coverage"><h2 id="coverage">Integration roadmap</h2><ul>{status.tools.map((tool) => <li key={tool.name}><span>{tool.name}</span><span className="badge">{tool.status}</span></li>)}</ul><p>No scanner results or completed assessments are presented by this foundation.</p></section>}
    <footer>Assessment permission, evidence provenance and human review come first.</footer>
  </main>;
}

const root = document.getElementById("root");
if (!root) throw new Error("Missing application root");
createRoot(root).render(<StrictMode><App /></StrictMode>);

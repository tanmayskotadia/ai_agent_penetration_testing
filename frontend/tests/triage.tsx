import { createRoot } from "react-dom/client";
import { FindingTriagePanel } from "../src/FindingTriagePanel";
const observations = [
  { observation_id: "obs-a", asset_id: "asset-a", source_tool: "OWASP ZAP", source_severity: "high", source_cvss_score: 8, confidence: 0.2, confidence_method: "TEST ONLY quality", validation_state: "suspected", title: "<img src=x onerror=alert(1)> TEST ONLY source", evidence_id: "ev-a", observed_at: "2026-11-07T00:00:00Z" },
  { observation_id: "obs-b", asset_id: "asset-b", source_tool: "Nikto", source_severity: "low", confidence: null, validation_state: "unknown", title: "TEST ONLY second source", evidence_id: "ev-b" },
];
createRoot(document.getElementById("root")!).render(<FindingTriagePanel assessmentId="test-triage" token="test-only-token" analytics={{ ranked_observations: observations }} onChanged={() => {}} />);

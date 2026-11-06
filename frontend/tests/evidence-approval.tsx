import { createRoot } from "react-dom/client";
import { ActionApprovalPanel } from "../src/ActionApprovalPanel";
import { EvidenceInspector } from "../src/EvidenceInspector";
createRoot(document.getElementById("root")!).render(<><EvidenceInspector assessmentId="test-inspector" token="test-only-token" evidenceId="ev-a" observationId="obs-a" /><ActionApprovalPanel assessmentId="test-inspector" token="test-only-token" onChanged={() => {}} /></>);

import { createRoot } from "react-dom/client";
import { AssessmentTimeline } from "../src/AssessmentTimeline";
createRoot(document.getElementById("root")!).render(<AssessmentTimeline assessmentId="test-timeline" token="test-only-token" onChanged={() => {}} />);

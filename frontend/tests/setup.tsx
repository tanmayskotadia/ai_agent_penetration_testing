import { createRoot } from "react-dom/client";
import { AssessmentSetup } from "../src/AssessmentSetup";

createRoot(document.getElementById("root")!).render(<AssessmentSetup assessmentId="test-assessment" token="test-only-token" onChanged={() => {}} />);

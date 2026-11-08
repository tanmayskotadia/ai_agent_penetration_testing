import { createRoot } from "react-dom/client";
import { ReplanPanel } from "../src/ReplanPanel";

createRoot(document.getElementById("root")!).render(
  <ReplanPanel assessmentId="test-assessment" token="test-only-token" coverage={{
    source_reviews: [],
  }} onChanged={() => {}} />,
);

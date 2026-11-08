import assert from "node:assert/strict";
import { mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { chromium } from "@playwright/test";
import { createServer } from "vite";

const server = await createServer({ configFile: false, server: { host: "127.0.0.1", port: 0 } });
await server.listen();
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1100 } });
  page.on("pageerror", error => console.error("Browser error:", error.message));
  const requests = [];
  const reportWrites = [];
  let coverageRequests = 0;
  let importAttempts = 0;
  const coverage = {
    coverage_state: "no-evidence",
    captured_at: "2026-11-08T00:00:00Z",
    source_run_count: 0,
    observed_record_count: 0,
    asset_count: 0,
    endpoint_catalog_count: 0,
    gaps: ["No evidence has been imported in this synthetic walkthrough."],
    tool_evidence: [],
    source_reviews: [],
    observation_analytics: { ranked_observations: [{ observation_id: "obs-test", title: "TEST ONLY missing header", asset_id: "asset-test", evidence_id: "evidence-test", source_tool: "TEST ONLY", priority: { local_priority_index: null, review_attention: "standard-review", state: "unknown", missing_context: [], factors: {} }, source_severity: "unknown", source_cvss_score: null }] },
    prototype_gate: {
      three_verified_network_and_web_imports: { passed: false, evidence: [] },
      authorized_lab_demonstration: { passed: false, evidence: [] },
    },
    operation_coverage: {},
  };
  await page.route("**/api/v1/**", async route => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname;
    requests.push({ method: request.method(), path, search: url.search });
    let data = [], status = 200, contentType = "application/json";
    if (path.endsWith("/system/status")) data = { stage: "ready", live_scans_enabled: false, tools: [{ name: "Nmap", mode: "recorded-import", demonstration_label: "offline import", limitations: ["No live scanner is enabled"] }] };
    else if (path.endsWith("/auth/login") && request.method() === "POST") data = { access_token: "synthetic-session-token" };
    else if (path.endsWith("/assessments") && request.method() === "GET") data = [{ id: "assessment-alpha", name: "Portfolio demo assessment" }, { id: "assessment-beta", name: "Second synthetic assessment" }];
    else if (path.endsWith("/assessments") && request.method() === "POST") data = { id: "assessment-created", name: JSON.parse(request.postData() ?? "{}").name };
    else if (path.endsWith("/coverage")) {
      coverageRequests += 1;
      if (coverageRequests === 1) { data = { message: "TEST ONLY denied" }; status = 403; }
      else data = coverage;
    }
    else if (path.endsWith("/evidence/evidence-test/inspector")) data = {
      id: "evidence-test", sha256: "e".repeat(64), raw_reference: "/test/0", pointer_type: "json-pointer",
      tool: "Nmap", tool_version: "TEST ONLY", run_id: "run-test", captured_at: "TEST ONLY", mode: "recorded-import",
      run_state: "recorded", original_available: false, reviewed_derivative_available: false,
      can_generate_derivative: false, can_review_derivative: false,
    };
    else if (request.method() === "POST" && path.endsWith("/scopes")) data = { id: "scope-test", revision: 1 };
    else if (request.method() === "POST" && path.endsWith("/runs")) data = { id: "run-test" };
    else if (request.method() === "POST" && path.endsWith("/evidence")) data = { id: "evidence-test" };
    else if (request.method() === "POST" && path.endsWith("/imports")) data = { id: "import-test" };
    else if (path.endsWith("/normalize-nmap")) {
      importAttempts += 1;
      data = importAttempts === 1
        ? { state: "quarantined", code: "TEST ONLY parse failure", findings_created: 0 }
        : { state: "normalized", source_sha256: "e".repeat(64), evidence_id: "evidence-test", findings_created: 0 };
      if (importAttempts === 2) {
        coverage.source_run_count = 1;
        coverage.observed_record_count = 1;
      }
    }
    else if (path.endsWith("/report-findings") && request.method() === "POST") {
      reportWrites.push(JSON.parse(request.postData() ?? "{}"));
      data = { id: "report-content-test", revision: 1, request: reportWrites.at(-1) };
      status = 201;
    }
    else if (path.endsWith("/report-findings")) data = { revision: 0, findings: [], reference_catalog: { frameworks: [
      { key: "owasp-top-10-2025", name: "OWASP Top 10", version: "2025", role: "risk-category", description: "TEST ONLY", entries: [{ id: "A02:2025", title: "Security Misconfiguration" }] },
      { key: "mitre-attack-enterprise", name: "MITRE ATT&CK Enterprise", version: "20.1", role: "reviewer-mapped-hypothesis", description: "TEST ONLY", entries: [] },
      { key: "nist-csf-2.0", name: "NIST CSF", version: "2.0", role: "reviewer-mapped-outcome", description: "TEST ONLY", entries: [] },
    ] } };
    else if (path.endsWith("/events")) { data = ""; contentType = "text/event-stream"; }
    else if (path.endsWith("/controls")) data = { stopped: false, epoch: 0, jobs: [] };
    else if (path.endsWith("/finding-reviews")) data = { revision: 0, latest_by_observation: {}, reviews: [], history_truncated: false };
    else if (path.endsWith("/logout")) data = { revoked: true };
    else if (request.method() === "POST") { data = {}; status = 201; }
    await route.fulfill({ status, contentType, body: contentType === "text/event-stream" ? "" : JSON.stringify(data) });
  });

  await page.goto(server.resolvedUrls.local[0]);
  await page.getByRole("heading", { name: "AegisTrace" }).waitFor();
  await page.getByLabel("Username").fill("analyst@example.test");
  await page.getByLabel("Password").fill("synthetic-password-only");
  await page.getByRole("button", { name: "Sign in" }).click();
  await page.getByRole("navigation", { name: "Assessment workflow" }).waitFor();
  const activeAssessment = page.locator(".workflow-context strong");
  await activeAssessment.filter({ hasText: /^Portfolio demo assessment$/ }).waitFor();

  const scopeInput = page.getByLabel("In-scope targets, one per line");
  await page.getByRole("button", { name: "Open scope and plan" }).press("Enter");
  await page.locator("#assessment-setup:focus").waitFor();
  await scopeInput.fill("example.test");
  await page.getByRole("textbox", { name: "Assessment request" }).fill("Review permitted recorded evidence only");
  const stages = page.getByRole("navigation", { name: "Assessment workflow" }).getByRole("button");
  await stages.nth(1).click();
  await page.getByRole("heading", { name: "Import evidence and API definitions" }).waitFor();
  await page.getByRole("alert").filter({ hasText: "You do not have permission" }).waitFor();
  await page.getByRole("button", { name: "Retry coverage" }).click();
  await page.getByText("Evidence import needed").waitFor();
  assert.equal(await stages.nth(1).getAttribute("aria-current"), "step");
  await page.getByRole("button", { name: "Open import form" }).press("Enter");
  await page.locator("#recorded-import:focus").waitFor();
  await page.getByLabel("Targets represented in the input").fill("example.test");
  await page.getByRole("button", { name: "Replan from evidence", exact: true }).press("Enter");
  await page.locator("#evidence-replan:focus").waitFor();
  await page.getByRole("button", { name: "Open audit timeline" }).press("Enter");
  await page.locator("#assessment-timeline:focus").waitFor();
  assert.equal(await page.getByLabel("Targets represented in the input").inputValue(), "example.test");
  await page.getByRole("button", { name: "Tool capabilities" }).press("Enter");
  await page.locator("#integration-capabilities[open] summary:focus").waitFor();
  await stages.nth(0).click();
  assert.equal(await scopeInput.inputValue(), "example.test", "stage navigation preserves scope input");
  assert.equal(await page.getByRole("textbox", { name: "Assessment request" }).inputValue(), "Review permitted recorded evidence only", "stage navigation preserves request text");
  assert.equal(await activeAssessment.textContent(), "Portfolio demo assessment", "selected assessment persists across stages");

  const out = new URL("../../docs/images/issue-107/", import.meta.url);
  await mkdir(fileURLToPath(out), { recursive: true });
  await page.evaluate(() => window.scrollTo(0, 0));
  await page.screenshot({ path: fileURLToPath(new URL("workspace-desktop.png", out)) });
  await page.setViewportSize({ width: 390, height: 844 });
  await stages.nth(1).click();
  await page.evaluate(() => document.querySelector(".workflow-dock").scrollIntoView());
  await page.screenshot({ path: fileURLToPath(new URL("workspace-mobile.png", out)) });
  const dimensions = await page.evaluate(() => ({ viewport: document.documentElement.clientWidth, content: document.documentElement.scrollWidth }));
  assert.ok(dimensions.content <= dimensions.viewport, `mobile layout has no horizontal overflow (${JSON.stringify(dimensions)})`);
  const importForm = page.locator(".intake-form");
  await importForm.locator('input[type="file"]').setInputFiles({ name: "test-only.xml", mimeType: "text/xml", buffer: Buffer.from("<test-only/>") });
  await importForm.getByLabel("Source / authorization reference").fill("TEST ONLY, synthetic acceptance fixture");
  await importForm.getByLabel("Version reported by source").fill("TEST ONLY");
  await importForm.getByLabel("Capture time reported by source").fill("2026-11-08T12:00");
  const normalize = page.getByRole("button", { name: "Store and normalize recorded evidence" });
  await normalize.click();
  await page.getByRole("heading", { name: "Import quarantined" }).waitFor();
  await page.getByText("TEST ONLY parse failure", { exact: true }).waitFor();
  await normalize.click();
  await page.getByRole("heading", { name: "Evidence normalized" }).waitFor();
  await page.getByRole("button", { name: "Open source provenance review", exact: true }).click();
  await page.locator("#source-review:focus").waitFor();
  await stages.nth(2).click();
  await page.getByRole("heading", { name: "Reviewer risk context" }).waitFor();
  await page.getByRole("heading", { name: "Evidence-backed report content" }).waitFor();
  await page.getByLabel("Report source observations").selectOption("obs-test");
  await page.locator(".finding-sources").getByRole("button", { name: "Inspect matching evidence", exact: true }).click();
  await page.getByRole("region", { name: "Evidence evidence-test", exact: true }).getByText("e".repeat(64), { exact: true }).waitFor();
  assert.ok(requests.some(item => item.method === "GET" && item.path.endsWith("/evidence/evidence-test/inspector") && item.search === "?observation_id=obs-test"));
  assert.equal(reportWrites.length, 0, "inspecting a source does not submit the finding form");
  await page.getByLabel("Finding title").fill("TEST ONLY reviewed finding");
  await page.getByLabel("Evidence-backed description").fill("TEST ONLY description linked to the synthetic observation.");
  await page.getByLabel("Reviewer rationale for this content").fill("TEST ONLY rationale; no vulnerability confirmation.");
  await page.getByLabel("Curated framework identifier").selectOption("A02:2025");
  await page.getByLabel("Framework mapping rationale").fill("TEST ONLY selected observation indicates a header configuration review.");
  await page.getByRole("button", { name: "Add framework reference" }).click();
  await page.getByRole("list", { name: "Framework references to save" }).getByText(/A02:2025/).waitFor();
  await page.getByRole("button", { name: "Save reviewed report content" }).click();
  assert.equal(reportWrites.length, 1, "report finding is posted exactly once");
  assert.equal(reportWrites[0].standard_references[0].identifier, "A02:2025", "UI submits the curated framework identifier");
  assert.deepEqual(reportWrites[0].standard_references[0].supporting_observation_ids, ["obs-test"], "mapping is linked to the selected observation");
  await stages.nth(3).click();
  await page.getByRole("heading", { name: "Assessment presentation" }).waitFor();
  await page.getByRole("heading", { name: "Recorded workflow checks" }).waitFor();
  await page.getByRole("heading", { name: "Live execution and lab checks" }).waitFor();
  await page.getByText("Create another assessment").click();
  await page.getByLabel("Assessment name").fill("Third synthetic assessment");
  await page.getByRole("button", { name: "Create assessment" }).click();
  await activeAssessment.filter({ hasText: /^Third synthetic assessment$/ }).waitFor();
  await stages.nth(1).click();
  assert.equal(await page.getByLabel("Targets represented in the input").inputValue(), "", "another assessment does not inherit the previous import targets");
  assert.ok(requests.some(item => item.method === "POST" && item.path.endsWith("/assessments")), "analyst can create another assessment from the workspace");
  assert.ok(requests.some(item => item.path.endsWith("/events")), "audit timeline is one stage away and loads its event stream");
  assert.ok(requests.every(item => !/scan-jobs\/[^/]+\/retry|action-approvals\/[^/]+\/decision/.test(item.path)), "workspace navigation performs no scan or approval action");
  console.log("PASS: authenticated staged journey, selected-assessment context, stage-persistent form state, assessment creation, audit timeline, report stage, keyboard-addressable stage controls, responsive viewport, and no execution calls. Synthetic data only.");
} finally {
  await browser.close();
  await server.close();
}

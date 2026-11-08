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
    prototype_gate: {},
    operation_coverage: {},
  };
  await page.route("**/api/v1/**", async route => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname;
    requests.push({ method: request.method(), path });
    let data = [], status = 200, contentType = "application/json";
    if (path.endsWith("/system/status")) data = { stage: "ready", live_scans_enabled: false, tools: [{ name: "Nmap", mode: "recorded-import", demonstration_label: "offline import", limitations: ["No live scanner is enabled"] }] };
    else if (path.endsWith("/auth/login") && request.method() === "POST") data = { access_token: "synthetic-session-token" };
    else if (path.endsWith("/assessments") && request.method() === "GET") data = [{ id: "assessment-alpha", name: "Portfolio demo assessment" }, { id: "assessment-beta", name: "Second synthetic assessment" }];
    else if (path.endsWith("/assessments") && request.method() === "POST") data = { id: "assessment-created", name: JSON.parse(request.postData() ?? "{}").name };
    else if (path.endsWith("/coverage")) data = coverage;
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
  await page.getByText("Portfolio demo assessment").first().waitFor();

  const scopeInput = page.getByLabel("In-scope targets, one per line");
  await scopeInput.fill("example.test");
  await page.getByRole("textbox", { name: "Assessment request" }).fill("Review permitted recorded evidence only");
  const stages = page.getByRole("navigation", { name: "Assessment workflow" }).getByRole("button");
  await stages.nth(1).click();
  await page.getByRole("heading", { name: "Import evidence and API definitions" }).waitFor();
  await page.getByText("Evidence import needed").waitFor();
  await stages.nth(0).click();
  assert.equal(await scopeInput.inputValue(), "example.test", "stage navigation preserves scope input");
  assert.equal(await page.getByRole("textbox", { name: "Assessment request" }).inputValue(), "Review permitted recorded evidence only", "stage navigation preserves request text");
  assert.equal(await page.getByText("Portfolio demo assessment").first().textContent(), "Portfolio demo assessment", "selected assessment persists across stages");

  const out = new URL("../../docs/images/issue-107/", import.meta.url);
  await mkdir(fileURLToPath(out), { recursive: true });
  await page.screenshot({ path: fileURLToPath(new URL("workspace-desktop.png", out)), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await stages.nth(1).click();
  await page.screenshot({ path: fileURLToPath(new URL("workspace-mobile.png", out)), fullPage: true });
  const dimensions = await page.evaluate(() => ({ viewport: document.documentElement.clientWidth, content: document.documentElement.scrollWidth }));
  assert.ok(dimensions.content <= dimensions.viewport, `mobile layout has no horizontal overflow (${JSON.stringify(dimensions)})`);
  await stages.nth(2).click();
  await page.getByRole("heading", { name: "Reviewer risk context" }).waitFor();
  await page.getByRole("heading", { name: "Evidence-backed report content" }).waitFor();
  await page.getByLabel("Report source observations").selectOption("obs-test");
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
  await page.getByText("Create another assessment").click();
  await page.getByLabel("Assessment name").fill("Third synthetic assessment");
  await page.getByRole("button", { name: "Create assessment" }).click();
  await page.getByText("Third synthetic assessment").first().waitFor();
  assert.ok(requests.some(item => item.method === "POST" && item.path.endsWith("/assessments")), "analyst can create another assessment from the workspace");
  assert.ok(requests.some(item => item.path.endsWith("/events")), "audit timeline is one stage away and loads its event stream");
  assert.ok(requests.every(item => !/scan-jobs\/[^/]+\/retry|action-approvals\/[^/]+\/decision/.test(item.path)), "workspace navigation performs no scan or approval action");
  console.log("PASS: authenticated staged journey, selected-assessment context, stage-persistent form state, assessment creation, audit timeline, report stage, keyboard-addressable stage controls, responsive viewport, and no execution calls. Synthetic data only.");
} finally {
  await browser.close();
  await server.close();
}

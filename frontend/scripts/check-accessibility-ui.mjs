// Full workspace journey with synthetic HTTP fixtures, keyboard-only actions and axe.
import assert from "node:assert/strict";
import { readFile, mkdir } from "node:fs/promises";
import { chromium } from "@playwright/test";
import { createServer } from "vite";
const axe = await readFile(new URL("../node_modules/axe-core/axe.min.js", import.meta.url), "utf8");
const server = await createServer({ configFile: false, server: { host: "127.0.0.1", port: 0 } });
await server.listen();
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  const browserErrors = [];
  page.on("pageerror", error => browserErrors.push(error.message));
  page.on("console", message => { if (message.type() === "error") browserErrors.push(message.text()); });
  let assessment = null;
  const scopes = [], decisions = [];
  const tools = [
    { name: "Nmap", mode: "recorded-import", demonstration_label: "Recorded import only", limitations: ["No native execution verified"] },
    { name: "Metasploit", mode: "unsupported", demonstration_label: "Unavailable; live execution disabled", limitations: ["No license or runtime verified"] },
  ];
  const action = { id: "approval-test", assessment_id: "assessment-test", state: "pending-review", action_digest: "a".repeat(64), parameter_hash: "b".repeat(64), scope_id: "scope-test", scope_revision: 1, profile_current: true, policy_digest: "c".repeat(64), valid_until: "2099-01-01T00:00:00Z", reviewer: null, expired: false, allowed_decisions: ["approve", "deny"], action: { tool: "Nmap", template: "nmap.connect.v1", profile: "discovery", destination_url: "http://192.0.2.10/", parameters: {}, max_runtime_seconds: 20, expected_impact: "TEST ONLY", rollback_instructions: "TEST ONLY", evidence_ids: [], plan_id: "plan-test", plan_revision: 1 } };
  const observation = { observation_id: "obs-test", asset_id: "asset-test", source_tool: "Nmap", title: "TEST ONLY observation", source_severity: "high", source_cvss_score: 8, confidence: null, validation_state: "suspected", evidence_id: "ev-test", priority: { local_priority_index: null, state: "context-insufficient", review_attention: "standard-review", missing_context: ["exposure"], factors: {} } };
  const coverage = { coverage_state: "partial", snapshot_complete: true, source_run_count: 1, asset_count: 1, observed_record_count: 1, endpoint_catalog_count: 0, tool_evidence: tools.map(capability => ({ name: capability.name, capability, source_records: [] })), gaps: ["TEST ONLY incomplete coverage"], prototype_gate: {}, observation_analytics: { ranked_observations: [observation], contextual_risk_ranking: { ranking_method: "TEST ONLY ranking", ranked_observations: [observation] } } };
  await page.route("**/api/v1/**", async route => {
    const request = route.request(), path = new URL(request.url()).pathname;
    let value = [], status = 200;
    if (path.endsWith("/system/status")) value = { tools, live_scans_enabled: false, stage: "test" };
    else if (path.endsWith("/auth/login")) value = { access_token: "test-only-session" };
    else if (path === "/api/v1/assessments") {
      if (request.method() === "POST") { assessment = { id: "assessment-test", name: request.postDataJSON().name }; value = assessment; status = 201; }
      else value = assessment ? [assessment] : [];
    } else if (path.endsWith("/coverage")) value = coverage;
    else if (path.endsWith("/scopes")) {
      if (request.method() === "POST") { scopes.push({ ...request.postDataJSON(), id: "scope-test" }); value = scopes.at(-1); status = 201; } else value = scopes;
    } else if (path.endsWith("/action-approvals")) value = [action];
    else if (path.endsWith("/action-approvals/approval-test")) value = action;
    else if (path.endsWith("/decision")) { decisions.push(request.postDataJSON()); action.state = "denied"; action.allowed_decisions = []; value = action; }
    else if (path.endsWith("/report-findings")) value = { revision: 0, findings: [] };
    else if (path.endsWith("/finding-reviews")) value = { revision: 0, latest_by_observation: {}, reviews: [] };
    else if (path.endsWith("/correlations/reviews")) value = { revision: 0, reviews: [] };
    else if (path.endsWith("/controls")) value = { stopped: false, epoch: 0, jobs: [] };
    else if (path.endsWith("/events")) { await route.fulfill({ contentType: "text/event-stream", body: ": test empty batch\n\n" }); return; }
    else if (path.endsWith("/inspector")) value = { id: "ev-test", sha256: "e".repeat(64), raw_reference: "/host/0", pointer_type: "xml-path", tool: "Nmap", tool_version: "test-only", run_id: "run-test", captured_at: "TEST ONLY", mode: "recorded-import", run_state: "recorded", original_available: false, reviewed_derivative_available: false, can_generate_derivative: false, can_review_derivative: false };
    else if (path.endsWith("/result-revisions")) value = [{ id: "result-test", run_id: "run-test", revision: 1 }];
    else if (path.endsWith("/result-exports")) { value = { id: "export-test" }; status = 201; }
    else if (path.endsWith("/pdf")) { await route.fulfill({ contentType: "application/pdf", body: "%PDF-1.4\nTEST ONLY download fixture" }); return; }
    else if (path.endsWith("/result-exports/export-test")) value = { id: "export-test", sha256: "e".repeat(64), snapshot: { mode: "TEST ONLY" } };
    else if (!["/plans", "/plan-reviews", "/assets", "/asset-contexts", "/scan-jobs"].some(suffix => path.endsWith(suffix))) throw new Error(`Unexpected test endpoint: ${path}`);
    await route.fulfill({ status, json: value });
  });
  async function tabTo(locator) {
    for (let index = 0; index < 300; index++) {
      if (await locator.evaluate(element => element === document.activeElement)) return;
      await page.keyboard.press("Tab");
    }
    throw new Error(`Cannot reach keyboard target: ${await locator.getAttribute("aria-label") ?? await locator.textContent()}`);
  }
  async function activate(locator) { await tabTo(locator); await page.keyboard.press("Enter"); }
  async function audit(label) {
    await page.addScriptTag({ content: axe });
    const result = await page.evaluate(async () => window.axe.run(document, { runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa", "best-practice"] } }));
    assert.deepEqual(result.violations.map(item => ({ id: item.id, nodes: item.nodes.map(node => node.target) })), [], label);
  }
  await page.goto(server.resolvedUrls.local[0]);
  await page.getByText("Workspace connected", { exact: true }).waitFor();
  await audit("Signed-out accessibility");
  await tabTo(page.getByLabel("Username", { exact: true })); await page.keyboard.type("test-reviewer");
  await tabTo(page.getByLabel("Password", { exact: true })); await page.keyboard.type("test-only-password");
  await activate(page.getByRole("button", { name: "Sign in", exact: true }));
  await page.getByLabel("Assessment name", { exact: true }).waitFor();
  await tabTo(page.getByLabel("Assessment name", { exact: true })); await page.keyboard.type("TEST ONLY keyboard assessment");
  await activate(page.getByRole("button", { name: "Create assessment", exact: true }));
  await page.getByRole("heading", { name: "Scope & plan", exact: true }).waitFor();
  assert.equal(assessment.name, "TEST ONLY keyboard assessment");
  // An existing scope is supplied by another authorized setup action for review fixtures.
  await tabTo(page.getByLabel("Assessment request", { exact: true })); await page.keyboard.type("TEST ONLY retained draft");
  scopes.push({ id: "scope-test", revision: 1, targets: ["192.0.2.10"], exclusions: [], mode: "recorded-import" });
  await page.getByRole("button", { name: /Findings & review/ }).click();
  await activate(page.getByRole("button", { name: "Reload action approvals", exact: true }));
  const card = page.getByRole("article", { name: "Action approval-test", exact: true });
  await activate(card.getByRole("button", { name: "Review denial", exact: true }));
  const confirmation = page.getByRole("region", { name: "Confirm exact action decision", exact: true });
  assert.equal(await confirmation.evaluate(element => element === document.activeElement), true);
  await activate(page.getByRole("button", { name: "Confirm denial", exact: true }));
  await page.getByText(/Backend recorded denial/).waitFor();
  assert.equal(decisions[0].decision, "deny");
  assert.equal(await page.getByText(/Backend recorded denial/).evaluate(element => element === document.activeElement), true);
  await activate(page.getByRole("button", { name: "Inspect matching evidence", exact: true }));
  await page.getByRole("region", { name: "Evidence ev-test", exact: true }).getByText("e".repeat(64), { exact: true }).waitFor();
  await audit("Analyst desktop accessibility");
  await page.locator("#workspace-flow").getByRole("button", { name: /Report/ }).click();
  await page.getByRole("heading", { name: "Assessment presentation", exact: true }).waitFor();
  const download = page.waitForEvent("download");
  await activate(page.getByRole("button", { name: "Freeze latest results and download PDF", exact: true }));
  assert.equal((await download).suggestedFilename(), "aegistrace-export-test.pdf");
  const manifest = page.waitForEvent("download");
  await activate(page.getByRole("button", { name: "Download matching JSON", exact: true }));
  assert.equal((await manifest).suggestedFilename(), "aegistrace-export-test.json");
  await activate(page.getByRole("button", { name: "Executive view", exact: true }));
  const summary = page.getByRole("region", { name: "Executive assessment summary", exact: true });
  await summary.waitFor();
  assert.ok((await summary.textContent()).includes("Metasploit: unsupported"));
  assert.ok((await summary.textContent()).includes("not confirmed vulnerabilities"));
  await audit("Executive desktop accessibility");
  await page.setViewportSize({ width: 390, height: 844 });
  await audit("Executive mobile accessibility");
  await mkdir("../tmp", { recursive: true });
  await summary.screenshot({ path: "../tmp/executive-mobile.png" });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true);
  await activate(page.getByRole("button", { name: "Open analyst view and source trace", exact: true }));
  await page.getByText("Analyst view includes source counts, coverage gaps, capability evidence and processing limits.", { exact: true }).waitFor();
  assert.equal(await page.getByLabel("Assessment request", { exact: true }).inputValue(), "TEST ONLY retained draft");
  await audit("Analyst mobile accessibility");
  await page.screenshot({ path: "../tmp/analyst-mobile.png" });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), true);
  assert.deepEqual(browserErrors, []);
  console.log("PASS: keyboard-only sign-in/create assessment/evidence/deny/PDF journey, focus management, executive/analyst capability disclosure, 390px layout and five axe WCAG/best-practice scans. Synthetic fixtures; no independent human usability study claimed.");
} finally { await browser.close(); await server.close(); }

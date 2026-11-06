// Synthetic HTTP evidence/action fixtures. No scanner or external target is contacted.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { chromium } from "@playwright/test";
import { createServer } from "vite";
const server = await createServer({ configFile: false, server: { host: "127.0.0.1", port: 0 } });
await server.listen();
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage();
  let viewer = false, changed = false, denyDownload = true, reviewed = false;
  const mutations = [], requests = [];
  const raw = Buffer.from("TEST ONLY password=private-canary");
  const action = { id: "approval-test", assessment_id: "test-inspector", state: "pending-review", action_digest: "a".repeat(64), parameter_hash: "b".repeat(64), scope_id: "scope-test", scope_revision: 1, profile_current: true, policy_digest: "c".repeat(64), profile_digest: "d".repeat(64), valid_until: "2099-01-01T00:00:00Z", reviewer: null, expired: false, allowed_decisions: ["approve", "deny"], action: { tool: "Nmap", profile: "discovery", template: "nmap.connect.v1", destination_url: "http://192.0.2.10:8080/", parameters: { timeout_seconds: 5 }, expected_impact: "TEST ONLY limited discovery", rollback_instructions: "TEST ONLY no changes", max_runtime_seconds: 20, plan_id: "plan-test", plan_revision: 1, evidence_ids: [] } };
  const metadata = { id: "ev-a", sha256: createHash("sha256").update(raw).digest("hex"), raw_reference: "/alerts/0", pointer_type: "json-pointer", tool: "OWASP ZAP", tool_version: "test-only", run_id: "run-test", mode: "recorded-import", run_state: "recorded", captured_at: "2026-11-07T00:00:00Z", original_available: true, original_access: "assessment and ticket required", reviewed_derivative_available: false, can_generate_derivative: true, can_review_derivative: true };
  await page.route("**/api/v1/assessments/test-inspector/**", async route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname;
    requests.push({ path, method: request.method(), query: url.search });
    if (request.method() === "POST") mutations.push({ path, body: request.postDataJSON() });
    if (path.endsWith("/inspector")) {
      assert.equal(url.searchParams.get("observation_id"), "obs-a");
      await route.fulfill({ json: { ...metadata, reviewed_derivative_available: reviewed, can_generate_derivative: !viewer, can_review_derivative: !viewer } }); return;
    }
    if (path.endsWith("/redaction")) { await route.fulfill({ json: { snippet: "&lt;script&gt;TEST ONLY&lt;/script&gt; password=[REDACTED]", information_kind: "redacted-source-derivative" } }); return; }
    if (path.endsWith("/redaction-review")) { reviewed = true; await route.fulfill({ json: { status: "reviewed" } }); return; }
    if (path.endsWith("/download-ticket")) {
      await route.fulfill(denyDownload ? { status: 403, json: { message: "Original access denied" } } : { json: { ticket: "test-ticket" } }); return;
    }
    if (path.endsWith("/original")) { assert.equal(request.headers()["x-download-ticket"], "test-ticket"); await route.fulfill({ contentType: "application/octet-stream", body: raw }); return; }
    if (path.endsWith("/scopes")) { await route.fulfill({ json: [{ id: "scope-test", revision: 1 }] }); return; }
    const view = { ...action, allowed_decisions: viewer ? [] : action.allowed_decisions, action: { ...action.action, parameters: { timeout_seconds: changed ? 9 : 5 } } };
    if (path.endsWith("/action-approvals")) { await route.fulfill({ json: [view, { ...view, id: "expired-test", expired: true, allowed_decisions: [], valid_until: "2000-01-01T00:00:00Z" }] }); return; }
    if (path.endsWith("/action-approvals/approval-test")) { await route.fulfill({ json: view }); return; }
    if (path.endsWith("/decision")) { action.state = request.postDataJSON().decision === "approve" ? "approved" : "denied"; action.allowed_decisions = []; await route.fulfill({ json: action }); return; }
    throw new Error(`Unexpected endpoint ${path}`);
  });
  await page.goto(server.resolvedUrls.local[0] + "tests/evidence-approval.html");
  const card = page.getByRole("article", { name: "Action approval-test", exact: true });
  await card.waitFor();
  assert.equal(mutations.length, 0);
  assert.ok((await card.textContent()).includes(action.action_digest));
  assert.ok((await card.textContent()).includes("nmap.connect.v1"));
  assert.equal(await page.getByRole("article", { name: "Action expired-test", exact: true }).getByRole("button", { name: "Review approval", exact: true }).isDisabled(), true);
  await page.getByRole("button", { name: "Inspect matching evidence" }).click();
  const inspector = page.getByRole("region", { name: "Evidence ev-a", exact: true });
  await inspector.getByText(metadata.sha256, { exact: true }).waitFor();
  assert.equal(mutations.length, 0);
  await inspector.getByRole("button", { name: "Generate redacted snippet" }).click();
  await inspector.getByText("Unreviewed redacted source derivative", { exact: true }).waitFor();
  assert.ok(!(await inspector.textContent()).includes("private-canary"));
  assert.equal(await inspector.locator("script").count(), 0);
  await inspector.getByRole("button", { name: "Mark derivative reviewed" }).click();
  await inspector.getByText(/Derivative review recorded/).waitFor();
  await inspector.getByRole("button", { name: "Download private original" }).click();
  await inspector.getByText("Original access denied", { exact: true }).waitFor();
  assert.equal(requests.filter(value => value.path.endsWith("/original")).length, 0);
  denyDownload = false;
  const downloaded = page.waitForEvent("download");
  await inspector.getByRole("button", { name: "Download private original" }).click();
  assert.equal((await downloaded).suggestedFilename(), "ev-a.bin");
  await card.getByRole("button", { name: "Review approval", exact: true }).click();
  changed = true;
  await page.getByRole("button", { name: "Confirm approval", exact: true }).click();
  await page.getByText("Action changed since display. Reload and review the exact parameters again.", { exact: true }).waitFor();
  assert.equal(mutations.filter(value => value.path.endsWith("/decision")).length, 0);
  viewer = true;
  await page.getByRole("button", { name: "Reload action approvals" }).click();
  await card.getByText("No decision permitted for this identity or action state.").waitFor();
  assert.equal(await card.getByRole("button", { name: "Review approval", exact: true }).isDisabled(), true);
  viewer = false;
  await page.getByRole("button", { name: "Reload action approvals" }).click();
  await card.getByRole("button", { name: "Review denial", exact: true }).click();
  await page.getByRole("button", { name: "Confirm denial", exact: true }).click();
  await page.getByText(/Backend recorded denial/).waitFor();
  const decision = mutations.find(value => value.path.endsWith("/decision"));
  assert.deepEqual(decision.body, { decision: "deny", action_digest: action.action_digest });
  assert.ok(requests.every(value => !value.path.includes("scan-jobs")));
  console.log("PASS: bound evidence metadata, inert redacted snippet, explicit derivative review, denied/ticketed verified download, expired/viewer restrictions, changed-parameter rejection and exact-digest denial. Synthetic fixtures only.");
} finally { await browser.close(); await server.close(); }

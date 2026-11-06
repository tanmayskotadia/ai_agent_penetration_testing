// Browser interaction tests use synthetic HTTP fixtures, never scanner evidence.
import assert from "node:assert/strict";
import { chromium } from "@playwright/test";
import { createServer } from "vite";

const server = await createServer({ configFile: false, server: { host: "127.0.0.1", port: 0 } });
await server.listen();
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage();
  page.on("pageerror", error => console.error("Browser error:", error.message));
  const scopes = [], plans = [], reviews = [];
  let denyReview = false;
  const requests = [];
  await page.route("**/api/v1/assessments/test-assessment/**", async route => {
    const request = route.request(), path = new URL(request.url()).pathname;
    const body = request.postDataJSON();
    requests.push({ path, method: request.method(), body });
    let data = [], status = 200;
    if (path.endsWith("/scopes")) {
      if (request.method() === "POST") {
        if (body.targets.includes("ambiguous target")) { status = 422; data = { message: "Target must be an explicit host, address or URL" }; }
        else { data = { ...body, id: `scope-${scopes.length + 1}` }; scopes.push(data); status = 201; }
      } else data = scopes;
    } else if (path.endsWith("/plans/intake")) {
      const blocked = body.message.includes("Metasploit");
      data = { id: `plan-${plans.length + 1}`, revision: plans.length + 1, state: blocked ? "blocked" : "draft", mode: "request-only", request: { ...body, review_digest: "a".repeat(64), proposal: { information_kind: "deterministic proposal; not observed evidence or AI inference", request_text: body.message, scope_targets: scopes.at(-1).targets, scope_exclusions: scopes.at(-1).exclusions, clarifications: blocked ? ["Requested tool unavailable"] : [], blockers: blocked ? ["requested-tool-unavailable"] : [], steps: [{ tool: "Nmap", rationale: "Review recorded network evidence", mode: "recorded-import", capability_status: "supported-import", limits: body.constraints, requires: ["Nmap XML"], evidence: ["source artifact SHA-256"] }] } } };
      plans.push(data); status = 201;
    } else if (path.endsWith("/plans")) data = plans;
    else if (path.endsWith("/plan-reviews")) data = reviews;
    else if (path.endsWith("/reviews")) {
      if (denyReview) { status = 403; data = { message: "A human reviewer is required" }; }
      else { data = { id: `review-${reviews.length}`, request: { ...body, plan_id: path.split("/").at(-2) } }; reviews.push(data); status = 201; }
    }
    await route.fulfill({ status, json: data });
  });
  await page.goto(server.resolvedUrls.local[0] + "tests/setup.html");
  await page.getByRole("button", { name: "Create or revise plan" }).waitFor();
  await page.getByRole("button", { name: "Create or revise plan" }).click();
  await page.getByText("Enter at least one explicit target, one per line.", { exact: true }).waitFor();
  assert.equal(requests.filter(r => r.method === "POST").length, 0);
  await page.getByLabel("In-scope targets, one per line").fill("ambiguous target");
  await page.getByLabel("Assessment request", { exact: true }).fill("Review network evidence");
  await page.getByRole("button", { name: "Create or revise plan" }).click();
  await page.getByText("Target must be an explicit host, address or URL", { exact: true }).waitFor();
  await page.getByLabel("In-scope targets, one per line").fill("app.example.test");
  await page.getByLabel("Excluded targets, one per line").fill("admin.example.test");
  await page.getByLabel("Source / authorization reference").fill("TEST ONLY permission reference");
  await page.getByLabel("Constraints, one per line").fill("Offline only");
  await page.getByRole("button", { name: "Create or revise plan" }).click();
  const card = page.getByRole("article", { name: "Plan revision 1", exact: true });
  await card.waitFor();
  assert.ok((await card.textContent()).includes("source artifact SHA-256"));
  assert.equal(plans[0].request.constraints[0], "Offline only");
  await card.getByLabel("Review rationale").fill("TEST ONLY explicit review");
  denyReview = true;
  await card.getByRole("button", { name: "Approve plan proposal" }).click();
  await page.getByText("A human reviewer is required", { exact: true }).waitFor();
  assert.equal(reviews.length, 0);
  denyReview = false;
  await card.getByRole("button", { name: "Reject plan proposal" }).click();
  await card.getByText("Recorded reviewer decision: reject").waitFor();
  assert.equal(reviews[0].request.plan_digest, plans[0].request.review_digest);
  assert.equal(await card.getByRole("button", { name: "Approve plan proposal" }).isDisabled(), true);
  await page.getByLabel("Assessment request", { exact: true }).fill("Review Metasploit evidence");
  await page.getByRole("button", { name: "Create or revise plan" }).click();
  const blocked = page.getByRole("article", { name: "Plan revision 2", exact: true });
  await blocked.getByText("Clarification: Requested tool unavailable").waitFor();
  assert.equal(await blocked.getByRole("button", { name: "Approve plan proposal" }).isDisabled(), true);
  // A scope changed by another tab must disable reviewing old plans after reload.
  scopes.push({ ...scopes[0], id: "scope-new", revision: 2 });
  await page.getByRole("button", { name: "Reload current plans" }).click();
  await blocked.getByText("Scope changed. Create a new plan against the current scope.").waitFor();
  assert.equal(await blocked.getByRole("button", { name: "Reject plan proposal" }).isDisabled(), true);
  await page.reload();
  await page.getByRole("article", { name: "Plan revision 1", exact: true }).waitFor();
  assert.equal(await page.getByLabel("In-scope targets, one per line").inputValue(), "app.example.test");
  assert.equal(requests.some(r => /scan-jobs|action-approvals/.test(r.path)), false);
  console.log("PASS: fresh user, empty/invalid scope, constraints, persisted revision, denied review, rejection, unavailable tool, stale scope and reload. Synthetic HTTP fixtures; no live scan or hosted acceptance claimed.");
} finally { await browser.close(); await server.close(); }

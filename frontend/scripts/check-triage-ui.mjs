// Synthetic reviewer data; browser verifies the actual React workflow.
import assert from "node:assert/strict";
import { chromium } from "@playwright/test";
import { createServer } from "vite";
const server = await createServer({ configFile: false, server: { host: "127.0.0.1", port: 0 } });
await server.listen();
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage();
  let revision = 0, conflict = false;
  const history = [], latest = {};
  await page.route("**/api/v1/assessments/test-triage/finding-reviews", async route => {
    if (route.request().method() === "GET") {
      await route.fulfill({ json: { revision, reviews: history, latest_by_observation: latest, history_truncated: false } }); return;
    }
    const body = route.request().postDataJSON();
    if (conflict || body.expected_revision !== revision) {
      conflict = false; revision++;
      latest[body.observation_id] = { validation_state: "unknown", rationale: "TEST ONLY another reviewer decision" };
      await route.fulfill({ status: 409, json: { message: "Review changed" } }); return;
    }
    revision++;
    const value = { id: `review-${revision}`, revision, request: { ...body, recorded_by: "test-reviewer", recorded_at: "2026-11-07T00:00:00Z" } };
    history.push(value); latest[body.observation_id] = value.request;
    await route.fulfill({ status: 201, json: value });
  });
  await page.goto(server.resolvedUrls.local[0] + "tests/triage.html");
  const card = page.getByRole("article", { name: "Finding obs-a", exact: true });
  await card.waitFor();
  await page.getByRole("button", { name: "Reload finding reviews" }).click();
  assert.equal(await page.locator("img").count(), 0);
  assert.ok((await card.textContent()).includes("ev-a"));
  assert.ok((await card.textContent()).includes("not calibrated"));
  assert.ok((await card.textContent()).includes("Severe uncertain evidence: review required"));
  await page.getByLabel("Asset", { exact: true }).selectOption("asset-b");
  assert.equal(await card.count(), 0);
  assert.ok((await page.locator("body").innerText()).includes("1 severe uncertain observations are hidden by your filters"));
  await page.getByRole("button", { name: "Clear finding filters" }).click();
  for (const [label, option] of [["Tool", "Nikto"], ["Source severity", "low"], ["Validation", "unknown"], ["Confidence", "unknown"]]) {
    await page.getByLabel(label, { exact: true }).selectOption(option);
    assert.equal(await card.count(), 0);
    await page.getByRole("button", { name: "Clear finding filters" }).click();
  }
  await card.getByLabel("Reviewer state obs-a", { exact: true }).selectOption("contradictory");
  assert.equal(await card.getByRole("button", { name: "Record finding decision" }).isDisabled(), true);
  await card.getByLabel("Contradictory observations obs-a", { exact: true }).selectOption(["obs-b"]);
  await card.getByLabel("Reviewer rationale obs-a", { exact: true }).fill("TEST ONLY contradictory source references");
  await card.getByRole("button", { name: "Record finding decision" }).click();
  await page.getByText(/Reviewer decision saved. Ranking will refresh/).waitFor();
  assert.deepEqual(history[0].request.contradictory_observation_ids, ["obs-b"]);
  await card.getByLabel("Reviewer state obs-a", { exact: true }).selectOption("false-positive");
  await card.getByLabel("Reviewer rationale obs-a", { exact: true }).fill("TEST ONLY false alarm reason");
  await card.getByRole("button", { name: "Record finding decision" }).click();
  await page.waitForFunction(() => document.body.textContent.includes("Current reviewer state: false-positive"));
  assert.equal(history.length, 2);
  assert.equal(history[1].request.expected_revision, 1);
  assert.ok((await card.textContent()).includes("Severe uncertain evidence: review required"));
  await card.getByLabel("Reviewer rationale obs-a", { exact: true }).fill("TEST ONLY stale draft retained");
  conflict = true;
  await card.getByRole("button", { name: "Record finding decision" }).click();
  await page.getByText(/Another reviewer changed the decisions/).waitFor();
  assert.equal(await card.getByLabel("Reviewer rationale obs-a", { exact: true }).inputValue(), "TEST ONLY stale draft retained");
  assert.equal(history.length, 2);
  await page.reload();
  await page.waitForFunction(() => document.body.textContent.includes("TEST ONLY another reviewer decision"));
  assert.equal(await page.getByRole("article").count(), 2);
  console.log("PASS: five triage filters, severe uncertainty visibility, safe text, contradiction references, false-positive history, stale-write recovery and reload. Synthetic fixtures only.");
} finally { await browser.close(); await server.close(); }

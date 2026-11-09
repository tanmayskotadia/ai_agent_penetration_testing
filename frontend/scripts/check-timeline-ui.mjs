// Synthetic persisted-event fixtures; no scanner or external target is contacted.
import assert from "node:assert/strict";
import { chromium } from "@playwright/test";
import { createServer } from "vite";

const server = await createServer({ configFile: false, server: { host: "127.0.0.1", port: 0 } });
await server.listen();
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage();
  const browserErrors = [];
  page.on("pageerror", error => browserErrors.push(error.message));
  let offline = false, stopped = false, epoch = 0, denyStop = false;
  const cursors = [], controls = [];
  const job = { id: "job-test", assessment_id: "test-timeline", state: "partial", status: "partial", attempt: 1, created_at: 10, updated_at: 12, heartbeat_stale: false, duration_ms: 2000, events_cursor: 2, diagnostic_code: "collection-failed", diagnostic: "Output collection failed. Review retained evidence." };
  const events = [1, 2].map(sequence => ({ job_id: job.id, assessment_id: job.assessment_id, event_id: `event-${sequence}`, sequence, state: sequence === 1 ? "running" : "partial", kind: sequence === 1 ? "started" : "collection-failed", attempt: 1, created_at: 10 + sequence }));
  await page.route("**/api/v1/assessments/test-timeline/**", async route => {
    const request = route.request(), path = new URL(request.url()).pathname;
    if (offline) { await route.abort("connectionfailed"); return; }
    if (path.endsWith("/scan-jobs")) { await route.fulfill({ json: [job] }); return; }
    if (path.endsWith("/scan-jobs/job-test/events")) {
      cursors.push(Number(request.headers()["last-event-id"] ?? 0));
      // Replay even old entries to exercise the client's deduplication.
      await route.fulfill({ contentType: "text/event-stream", body: events.map(event => `id: ${event.sequence}\ndata: ${JSON.stringify(event)}\n\n`).join("") }); return;
    }
    if (path.endsWith("/events")) {
      const event = { event_id: "audit-1", assessment_id: "test-timeline", created_at: "2026-11-07T00:00:00Z", action: "import.requested", outcome: "requested", actor_kind: "human", resource_id: "evidence-test" };
      await route.fulfill({ contentType: "text/event-stream", body: `id: 1\ndata: ${JSON.stringify(event)}\n\n` }); return;
    }
    if (path.endsWith("/plan-reviews")) { await route.fulfill({ json: [{ id: "decision-test", request: { plan_id: "plan-test", decision: "reject", rationale: "TEST ONLY rejected unsafe action; token=private-value", reviewed_at: "2026-11-07T00:00:00Z" } }] }); return; }
    if (path.endsWith("/finding-reviews")) { await route.fulfill({ json: { reviews: [] } }); return; }
    if (path.endsWith("/controls/stop") || path.endsWith("/controls/resume")) {
      controls.push({ path, key: request.headers()["idempotency-key"] });
      if (denyStop) { await route.fulfill({ status: 403, json: { message: "Human control role required" } }); return; }
      await new Promise(resolve => setTimeout(resolve, 700));
      stopped = path.endsWith("/stop"); epoch++;
      await route.fulfill({ json: { stopped, epoch, running_cancel_requests: 1, unknown_disconnected: 1 } }); return;
    }
    if (path.endsWith("/controls")) { await route.fulfill({ json: { stopped, epoch, jobs: [] } }); return; }
    throw new Error(`Unexpected endpoint ${path}`);
  });
  await page.goto(server.resolvedUrls.local[0] + "tests/timeline.html");
  const jobCard = page.getByRole("article", { name: "Job job-test", exact: true });
  await jobCard.waitFor();
  await page.getByText(/Connected; last reconciled/).waitFor();
  assert.equal(await jobCard.getByRole("listitem").count(), 2);
  assert.ok((await page.locator("body").innerText()).includes("Retry requires review"));
  assert.ok(!(await page.locator("body").innerText()).includes("private-value"));
  assert.ok((await page.locator("body").innerText()).includes("token=[redacted]"));
  offline = true;
  await page.getByRole("button", { name: "Reconnect and reconcile" }).click();
  await page.getByText("Status unknown while disconnected; retained entries are historical.").waitFor();
  assert.ok((await jobCard.textContent()).includes("unknown (connection lost)"));
  offline = false;
  await page.getByRole("button", { name: "Reconnect and reconcile" }).click();
  await page.getByText(/Connected; last reconciled/).waitFor();
  assert.ok(cursors.includes(2));
  assert.equal(await jobCard.getByRole("listitem").count(), 2);
  assert.equal(await page.getByRole("list", { name: "Assessment audit events" }).getByRole("listitem").count(), 1);
  await page.getByRole("button", { name: "Stop assessment", exact: true }).click();
  await page.getByText("stop requested; awaiting backend confirmation.", { exact: true }).waitFor();
  assert.ok(!(await page.locator("body").innerText()).includes("Backend confirmed stop"));
  await page.getByText(/Backend confirmed stop for new work/).waitFor();
  assert.ok((await page.locator("body").innerText()).includes("Worker termination must still be reconciled"));
  await page.reload();
  await page.getByText(/confirmed stopped for new work/).waitFor();
  assert.equal(await jobCard.getByRole("listitem").count(), 2);
  assert.equal(cursors.at(-1), 0);
  await page.getByRole("button", { name: "Resume for new approvals" }).click();
  await page.getByText(/Backend confirmed resume/).waitFor();
  denyStop = true;
  await page.getByRole("button", { name: "Stop assessment", exact: true }).click();
  await page.getByText(/Control outcome unconfirmed/).waitFor();
  assert.equal(stopped, false);
  assert.ok(controls.every(control => !!control.key));
  assert.deepEqual(browserErrors, []);
  console.log("PASS: timeline cursor resume, duplicate replay, partial failure guidance, offline unknown status, backend-confirmed stop/resume, reload, denied control and secret-text redaction. Synthetic fixtures only.");
} finally { await browser.close(); await server.close(); }

import assert from "node:assert/strict";
import { chromium } from "@playwright/test";
import { createServer } from "vite";

const server = await createServer({ configFile: false, server: { host: "127.0.0.1", port: 0 } });
await server.listen();
const browser = await chromium.launch({ headless: true });
try {
  const page = await browser.newPage();
  page.on("pageerror", error => console.error("Browser error:", error.message));
  let scopeRevision = 1;
  let hideEligible = false;
  let redactionReviewed = false;
  const requests = [];
  const evidenceId = "evidence-11111111-1111-4111-8111-111111111111";
  const revisionId = "revision-11111111-1111-4111-8111-111111111111";
  const observationId = "observation-11111111-1111-4111-8111-111111111111";
  const base = "**/api/v1/assessments/test-assessment/**";
  await page.route(base, async route => {
    const request = route.request(), path = new URL(request.url()).pathname;
    const body = request.postDataJSON() ?? {};
    requests.push({ path, method: request.method(), body });
    let data = {}, status = 200;
    if (path.endsWith("/scopes")) {
      data = [{ id: `scope-${scopeRevision}`, revision: scopeRevision, targets: ["127.0.0.1"], exclusions: ["127.0.0.2"] }];
    } else if (path.endsWith("/plans") || path.endsWith("/plan-reviews")) {
      data = [];
    } else if (path.endsWith("/result-revisions")) {
      data = hideEligible ? [] : [
        { id: revisionId, run_id: "run-1", revision: 1, tool: "Nmap", state: "normalized", mode: "recorded-import", captured_at: "2026-11-08T10:00:00Z", evidence_id: evidenceId, source_sha256: "a".repeat(64), normalization_id: "normalization-1", observation_ids: [observationId], scope_id: `scope-${scopeRevision}`, scope_revision: scopeRevision },
        { id: "quarantined-1", run_id: "run-2", revision: 1, tool: "Nikto", state: "quarantined", mode: "recorded-import", captured_at: "2026-11-08T10:01:00Z", evidence_id: evidenceId, source_sha256: "b".repeat(64), normalization_id: "normalization-2", observation_ids: [], scope_id: `scope-${scopeRevision}`, scope_revision: scopeRevision },
        { id: "old-scope-1", run_id: "run-3", revision: 1, tool: "Nmap", state: "normalized", mode: "recorded-import", captured_at: "2026-11-07T10:00:00Z", evidence_id: evidenceId, source_sha256: "c".repeat(64), normalization_id: "normalization-3", observation_ids: [observationId], scope_id: "scope-old", scope_revision: 1 },
      ];
    } else if (path.endsWith(`/evidence/${evidenceId}/inspector`)) {
      data = { id: evidenceId, observation_id: null, sha256: "a".repeat(64), raw_reference: "whole-file", pointer_type: "whole-file", captured_at: "2026-11-08T10:00:00Z", run_id: "run-1", tool: "Nmap", tool_version: "7.94", mode: "recorded-import", run_state: "completed", information_kind: "observed-source-metadata; authenticity is not established", original_available: true, original_access: "assessment access", reviewed_derivative_available: redactionReviewed, can_generate_derivative: true, can_review_derivative: true };
    } else if (path.endsWith(`/evidence/${evidenceId}/redaction`)) {
      redactionReviewed = false;
      data = { snippet: "TEST ONLY: 127.0.0.1 exposes a synthetic HTTP service.", information_kind: "unreviewed-redacted-source-derivative" };
      status = 201;
    } else if (path.endsWith(`/evidence/${evidenceId}/redaction-review`)) {
      redactionReviewed = true;
      data = { state: "reviewed" };
      status = 201;
    } else if (path.endsWith("/reasoning/replan")) {
      if (String(body.request_text).includes("stale scope")) {
        scopeRevision = 2;
        data = { message: "Stale scope revision" };
        status = 409;
      } else if (!body.allow_external_processing || body.data_policy_reference !== "TEST POLICY") {
        data = { id: "plan-policy", assessment_id: "test-assessment", kind: "plans", revision: 1, state: "blocked", mode: "request-only", reason: "external-data-policy-approval-required", request: { ...body, proposal: { information_kind: "unknown", decision: null, blockers: ["external-data-policy-approval-required"], candidates: [], steps: [], execution_enabled: false, provider: { provider_invoked: false, model_called: false } } } };
        status = 201;
      } else if (String(body.request_text).includes("provider failure")) {
        const isRetry = body.retry_failed_attempt === true;
        data = { id: isRetry ? "plan-failure-retry" : "plan-failure", assessment_id: "test-assessment", kind: "plans", revision: isRetry ? 3 : 2, state: "blocked", mode: "request-only", reason: "provider-rate-limited", request: { ...body, proposal: { information_kind: "unknown", decision: null, blockers: ["provider-rate-limited"], candidates: [], steps: [], execution_enabled: false, provider: { provider: "groq", model: "TEST ONLY local model fixture", provider_invoked: true, model_called: false, provider_source: "test-only" } } } };
        status = 201;
      } else if (requests.filter(item => item.path.endsWith("/reasoning/replan") && item.body.request_text === body.request_text && item.body.allow_external_processing === body.allow_external_processing && item.body.data_policy_reference === body.data_policy_reference).length > 1) {
        data = { id: "plan-repeated", assessment_id: "test-assessment", kind: "plans", revision: 4, state: "blocked", mode: "request-only", reason: "unchanged-evidence-or-action", request: { ...body, proposal: { information_kind: "unknown", decision: null, blockers: ["unchanged-evidence-or-action; reuse-prior-plan-instead-of-repeating-model-call"], candidates: [], steps: [], execution_enabled: false, provider: { provider: "groq", model: "TEST ONLY local model fixture", provider_invoked: false, model_called: false } } } };
        status = 201;
      } else {
        data = { id: "plan-test-only", assessment_id: "test-assessment", kind: "plans", revision: 2, state: "draft", mode: "request-only", request: { ...body, context_sha256: "d".repeat(64), proposal: { information_kind: "ai-inference", decision: { decision: "select", selected_candidate_id: "review-sources", rationale: "TEST ONLY: the selected observation supports reviewing the source before proposing more work.", observation_ids: [observationId], expected_information_gain: "TEST ONLY: verify which services are actually represented.", assumptions: ["TEST ONLY synthetic source data"], stop_conditions: ["Stop if scope changes"], rejected_alternatives: [] }, candidates: [{ id: "review-sources", action: "request-review", observation_ids: [observationId] }], steps: [], execution_enabled: false, provider: { provider: "groq", model: "TEST ONLY local model fixture", provider_invoked: true, model_called: false, provider_source: "test-only", response_id_sha256: "e".repeat(64) } } } };
        status = 201;
      }
    }
    await route.fulfill({ status, json: data });
  });

  await page.goto(server.resolvedUrls.local[0] + "tests/replan.html");
  await page.getByRole("heading", { name: "Replan from evidence" }).waitFor();
  await page.getByText("Nmap · result revision 1").waitFor();
  assert.equal(await page.getByText("Nikto · result revision 1").count(), 0, "quarantined revision is hidden");
  assert.equal(await page.getByText(/scope-old/).count(), 0, "old-scope result is hidden");

  hideEligible = true;
  await page.getByRole("button", { name: "Reload scope and evidence" }).click();
  await page.getByText("No normalized evidence revisions match the active scope.").waitFor();
  hideEligible = false;
  await page.getByRole("button", { name: "Reload scope and evidence" }).click();
  await page.getByText("Nmap · result revision 1").waitFor();
  await page.getByRole("checkbox", { name: /Nmap/ }).check();
  await page.getByLabel("What should the model reconsider?").fill("Compare current evidence and choose a safe next step");
  await page.getByLabel(/I explicitly consent/).waitFor();
  await page.getByRole("button", { name: "Replan from selected evidence" }).click();
  assert.equal(requests.at(-1).body.allow_external_processing, false, "consent remains explicit and unchecked by default");
  await page.getByRole("status").filter({ hasText: /consent or policy reference did not match/ }).waitFor();

  await page.getByLabel(/Approved data-processing policy reference/).fill("TEST POLICY");
  await page.getByLabel(/I explicitly consent/).check();
  await page.getByRole("button", { name: "Replan from selected evidence" }).click();
  await page.getByText("TEST ONLY · synthetic response").waitFor();
  await page.getByRole("article", { name: "Saved replanning result" }).getByText(/TEST ONLY: the selected observation supports reviewing/).first().waitFor();
  await page.getByText(observationId).first().waitFor();
  await page.getByRole("link", { name: `${observationId} · inspect source` }).waitFor();
  await page.getByRole("link", { name: "Open saved plan and its separate human review" }).waitFor();
  await page.getByRole("button", { name: "Inspect matching evidence" }).click();
  await page.getByText("A current reviewed redacted derivative is required").waitFor();
  await page.getByRole("button", { name: "Generate redacted snippet" }).click();
  await page.getByRole("button", { name: "Mark derivative reviewed" }).click();
  await page.waitForTimeout(500);
  assert.ok(requests.some(item => item.path.endsWith(`/evidence/${evidenceId}/redaction-review`)), "operator review request reached the API");
  await page.getByText("Human-reviewed derivative available").waitFor({ timeout: 5000 });

  await page.getByRole("button", { name: "Replan from selected evidence" }).click();
  await page.getByText(/selected evidence and available actions match a prior plan/).first().waitFor();
  assert.equal(requests.filter(item => item.path.endsWith("/reasoning/replan") && item.body.request_text === "Compare current evidence and choose a safe next step" && item.body.allow_external_processing === true).length, 2);

  await page.getByLabel("What should the model reconsider?").fill("trigger provider failure");
  await page.getByRole("button", { name: "Replan from selected evidence" }).click();
  await page.getByText(/provider rate-limited this request/).first().waitFor();
  await page.getByRole("button", { name: "Retry failed provider call" }).waitFor();
  await page.getByRole("button", { name: "Retry failed provider call" }).click();
  assert.equal(requests.filter(item => item.path.endsWith("/reasoning/replan") && item.body.retry_failed_attempt).length, 1);

  await page.getByLabel("What should the model reconsider?").fill("stale scope test");
  await page.getByRole("button", { name: "Replan from selected evidence" }).click();
  await page.getByText(/server rejected this stale or over-budget request/).waitFor();
  assert.equal(requests.some(item => /scan-jobs|action-approvals/.test(item.path)), false, "replanning never requests scan or action execution");
  assert.ok(requests.filter(item => item.path.endsWith("/reasoning/replan")).every(item => item.body.scope_id));
  assert.ok(requests.filter(item => item.path.endsWith("/reasoning/replan")).slice(1).every(item => item.body.data_policy_reference === "TEST POLICY"));
  console.log("PASS: current-scope filtering, quarantine exclusion, missing evidence, explicit consent, policy blocker, redaction review, TEST ONLY inference labeling, observation and stored-plan links, provider failure/explicit retry, stale-scope recovery, and no execution requests. Synthetic HTTP fixtures only.");
} finally {
  await browser.close();
  await server.close();
}

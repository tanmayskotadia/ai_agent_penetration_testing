// Render-only coverage UI acceptance. Metadata below is test-only, not scan evidence.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createServer } from "vite";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

const server = await createServer({ configFile: false, server: { middlewareMode: true }, appType: "custom" });
try {
  const { CoveragePanel } = await server.ssrLoadModule("/src/CoveragePanel.tsx");
  const matrix = JSON.parse(await readFile(new URL("../../config/integration-matrix.json", import.meta.url), "utf8"));
  const snapshot = {
    coverage_state: "definition-only-untested", captured_at: "TEST ONLY", snapshot_sha256: "test-only-digest",
    snapshot_complete: false, gaps: ['<img src=x onerror="do-not-execute">'],
    source_run_count: 1, asset_count: 2, endpoint_catalog_count: 2, observed_record_count: 0,
    tool_evidence: matrix.tools.map(capability => ({ name: capability.name, capability,
      recorded_import_count: 0, normalization_states: {}, job_states: {} })),
    operation_coverage: { "live-request": { coverage_state: "definition-only-untested", declared_operation_count: 2,
      attempted_count: 0, ever_attempted_count: 0, state_counts: { untested: 2 }, operations: [] } },
  };
  const html = renderToStaticMarkup(createElement(CoveragePanel, { snapshot }));
  for (const tool of matrix.tools) assert.ok(html.includes(tool.name));
  assert.ok(html.includes("none verified"));
  assert.ok(html.includes("Disposable test outcomes"));
  assert.ok(html.includes("Live worker request outcomes"));
  assert.ok(html.includes("row limit"));
  assert.ok(html.includes("&lt;img"));
  assert.ok(!html.includes("<img"));
  assert.ok(!html.includes("undefined"));
  console.log("Coverage UI acceptance passed: seven tools, separate modes, truncation and escaped source text.");
} finally {
  await server.close();
}

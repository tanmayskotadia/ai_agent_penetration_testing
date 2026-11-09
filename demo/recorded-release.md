# AegisTrace recorded demo

## Demo order

Use the four stages in the analyst workspace. Open with the same review objective in two evidence contexts and explain why the next step changes. Then follow a reviewed finding from the workspace to the PDF and its frozen evidence manifest.

| Time | Screen | Proof to show |
| --- | --- | --- |
| 0:00–0:30 | Scope & plan | Exact scope and exclusions. Show the saved plan and a refusal for an excluded target. |
| 0:30–1:15 | Evidence and replan | Show the recorded source status and hash. Compare the HTTP case with an SSH-only or conflicting case. Open the cited observation, the model or policy outcome, and the plan revision. |
| 1:15–1:55 | Findings & review | Show which source records should stay separate. The reviewed ZAP and Nikto originals represent different targets. Use the explicitly synthetic same-endpoint example for a positive correlation. |
| 1:55–2:20 | Risk and approval | Point out source-reported severity and unresolved confidence. Open the separate action review and show a denial in the disposable walkthrough. |
| 2:20–2:55 | Report | Freeze the PDF, download matching JSON, then follow an Evidence ID link to its manifest entry. Match its ID, hash and pointer in the workspace. |
| 2:55–3:20 | Recovery and status | Show a quarantined import with its reason. Open the seven-tool matrix and explain recorded, planned and unavailable capabilities. |

## Reproduce the engineering checks

Run from a clean checkout with the locked dependencies. The browser and end-to-end fixtures are explicitly synthetic.

```text
uv sync --frozen
uv run pytest -m "not services"
uv run pytest tests/e2e/minimum-prototype -m "not services"
cd frontend
npm ci
npx playwright install chromium
npm run build
npm run check:workspace
npm run check:replan
node scripts/check-accessibility-ui.mjs
```

The [provider evaluation](../docs/reasoning-policy.md) uses a private configuration and a disposable database. Pass `--case http-missing-web-evidence` or `--case ssh-no-web-evidence` to verify one case at a time. Only send the script's synthetic inputs.

## Acceptance record

- [#19](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/19) records hashes and provenance for the reviewed Nmap, ZAP and Nikto originals and the expected correlation gap.
- [#49](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/49) and [#76](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/76) record the fixture-based safety and recovery results.
- [#107](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/107) and [#108](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/108) own the deployed reviewer journey and comparative provider trace. A synthetic browser replay demonstrates interaction and error handling.
- [#68](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/68), [#69](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/69) and [#75](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/75) own human review of the real evidence report, standards references and final PDF QA.
- [#78](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/78) records pass or gap for every judge check. [#17](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/17), [#28](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/28) and [#72](https://github.com/tanmayskotadia/ai_agent_penetration_testing/issues/72) remain separate authorization, live isolation and official acceptance gates.

In the evidence record, retain the deployment revision, scope revision, plan/result IDs, expected outcome and observed outcome. Share synthetic exports and sanitized records. Keep original artifacts and credentials private.

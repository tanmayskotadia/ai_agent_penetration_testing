# Prerequisites and capability inventory - T06

**Reviewed:** 4 November 2026. This is an actual availability assessment and an implementation prerequisite contract, not a claim that seven adapters or a live lab work. Machine identifiers, private paths, keys and raw scan data are not collected.

## Observed development environment

| Item | Observed | Meaning |
|---|---|---|
| Host | Windows; 16 logical processors; about 15.7 GiB RAM | Inventory only; no scanner/model concurrency benchmark |
| Workspace drive free space | About 5.8 GiB at review | Tight for Docker images, feeds, caches, models and retained evidence; choose more space/storage before heavy local setup |
| Python / Node / uv | Host Python 3.12.5, Node 24.14.1, uv 0.12.13 | Native foundation checks passed; CI/image uses its pinned supported Python 3.12 build |
| npm / Git | Available | Exact frontend lock and repository workflow exercised |
| Docker | No executable found on PATH | Full local Compose not executed; clean Linux CI build/start did pass |
| WSL | Executable found on PATH | Distribution, kernel/features, Linux networking and Docker integration not verified |
| Security tools | No listed scanner executable found on PATH | Not proof that a GUI/package is absent elsewhere; no edition/API/license capability verified |
| Model | No endpoint/model configured; processing disabled | No API key, model quality or external privacy guarantee assumed |
| Organizer lab | Participant confirmed no authorization | No live target/security testing allowed; T04 remains open |
| Genuine corpus | Zero captured fixtures and labels | T05 remains open; no measured detection/calibration claim |

[Machine-readable inventory](tool-resource-inventory.json), [runtime pins](../config/runtime-pins.json), [actual T03 CI evidence](verification/T03-ci.json).

## Development profiles

1. **Native smoke:** Python 3.12, uv 0.12.13, Node 24/npm; locked packages; ignored generated `.env`; SQLite smoke migration and API/UI. This is the available local development path, not the canonical PostgreSQL or scanner-isolation deployment.
2. **Full control plane:** supported PostgreSQL/Redis plus API/worker/UI and migrations. Pinned Compose needs Docker Engine/Desktop with Linux containers. API/frontend have a separate workspace ingress network; database/broker/diagnostic worker stay internal. Actual Linux CI verifies fresh services, migrations, queue round trip and container HTTP/proxy startup.
3. **Security lab:** additional genuine organizer scope/actions/rates/credentials, selected tool versions/editions and verified worker-to-target isolation. Not provisioned. Tool installation alone does not grant scan permission.
4. **Model reasoning:** approved local/hosted endpoint, selected model/version, data classifications, timeout/token/step budgets and measured evaluation. Not configured. Evidence-only development continues without it.

Do not run heavy local image/feed/model downloads into the current low-free-space drive without resolving capacity. A planning budget such as 20+ GiB is a starting allocation to evaluate, not a measured universal minimum; actual images, feed sizes, retention and selected local model determine the requirement. No software purchase, disk cleanup or system feature change is performed by this inventory.

## Seven-tool contract and fallback

All integration statuses below are **planned**, because no adapter has yet been verified. Native import is a future fallback, not a presently working capability.

| Tool | Format/control direction | Prerequisites before a truthful working label | Honest fallback |
|---|---|---|---|
| Nmap | Native XML; bounded reviewed CLI profiles | Exact release/license and any Windows packet-capture terms; authorized target/profile/rates | Genuine allowed XML import once parser is implemented/tested |
| Nessus | `.nessus` native export; optional exact-product API | Installed edition, valid entitlement/export/API capabilities, feeds and credentials | Genuine permitted import; otherwise planned/unsupported |
| Greenbone / OpenVAS | Native report; optional GMP via official client | Component/protocol/config versions, feeds, licenses, manager readiness and credentials | Genuine permitted native report import |
| Nikto | Version-supported structured output and reviewed CLI | Code/database/LibWhisker terms separately, installed format support and target permission | Genuine permitted structured export import |
| OWASP ZAP | Native alerts; verified Automation Framework/API | Installed release/add-ons, API authentication, contexts and permitted scan-impact profile | Genuine native alerts/import once tested |
| Burp Suite | Supported issue XML; analyst-assisted handoff; edition-dependent APIs | Actual Community/Professional/DAST edition and matching export/API entitlement | Genuine permitted export or explicit unsupported scenario |
| Metasploit | Narrow approved validation template or genuine import | Organizer permission, exact module/parameters, human approval gate, bounded execution/reset and component terms | Genuine labelled recorded result import; no autonomous console or exploit execution |

No commercial binary, feed or license is bundled. Do not describe an unavailable commercial tool as live, call a generic HTTP endpoint a supported licensed API, or claim a parser works without a genuine supported sample. Network plus web coverage through three working integrations/imports is the later minimum-prototype gate; this inventory is not that gate.

## Required private inputs

- Organizer authorization source/manifest, validity, targets/exclusions, allowed actions/rates, permitted local/remote setup and credential-delivery procedure.
- Tool editions/licenses, feed/update state and exact API/export entitlement where needed. Never publish license keys.
- Genuine captured artifacts plus provenance, redistribution/redaction basis and independent labels. Private originals stay outside source.
- Selected model endpoint and approved data policy; inject credentials locally, never in browser variables, issues or committed files.
- Later final PPT/video Drive destination and reviewed access, outside this milestone's setup scope.

See [lab authorization](lab-authorization.md), [fixture provenance](fixture-provenance.md), [licensing](licensing.md), [model/data policy](model-data-policy.md) and [open questions](open-questions.md).

## Re-run the non-invasive inventory

```powershell
python scripts/check_prerequisites.py
```

It reports tool executable presence and core runtime versions/free space without starting Docker, changing Windows features, launching a scanner, reading credential values or contacting targets. PATH absence and an unqueried daemon are reported honestly. Recheck after any setup change; this snapshot is not a live machine monitor.

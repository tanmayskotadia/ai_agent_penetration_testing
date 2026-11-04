# Untrusted import boundary — T11

Recorded imports remain separate from scanner execution. Users create an owning assessment and scope, record a tool/version/capture source, register a hash/pointer, upload the original privately, then create an import request. `POST /api/v1/assessments/{assessment}/imports/{import}/inspect` takes an explicit source-asset mapping. `GET .../{import}/inspection` retrieves persisted diagnostics. Both enforce identity/ownership; mutations share T10's atomic idempotency receipts. Revised mapping needs a new import request rather than overwriting an inspection.

The evidence hash is rechecked before parsing. Run/tool/scope metadata must agree. An import source ID must map into current targets; exclusions take precedence on both source and mapped identity. Exact host/IP, CIDR and HTTP(S) origin/path-boundary matching perform no DNS lookup or target contact. Explicit recorded aliases are user declarations, not DNS or legal-authorization proof. Dot-segment/credential-bearing/fragment URLs are rejected. Live dispatch still needs M03 scope validation and network controls.

## Bounded parsing and quarantine

- Max original 2 MiB, depth 32, 20,000 structural nodes, 200 assets and 128 XML attributes per node; strings are bounded.
- Parsing runs in a spawned child with a 3-second response deadline. Termination/kill cleanup is bounded. On Linux, child CPU and address-space limits add containment; Windows uses byte/structure/time bounds without claiming a Windows memory quota.
- The child receives bytes/tool/format/version, not application configuration; it clears inherited environment values before inspection. Network entry points are denied in the child. This is defense in depth, not an OS-enforced network sandbox or a substitute for M03 isolation.
- Defused XML forbids entities/external resolution. Bare native `DOCTYPE nmaprun` is permitted; stylesheets are never processed. No XSLT, HTML renderer, subprocess command from a file, `eval`, external schema fetch or content-selected filesystem path is used.
- JSON rejects duplicate keys, NaN/Infinity, excessive nesting and unsafe control characters. Banners/HTML/prompt-like strings remain untrusted data; inspection returns only bounded asset IDs/counts/diagnostic codes, never executes or prompts with them.
- Archives/compressed containers are unsupported and never extracted. This rejects zip traversal and decompression bombs without expanding them. HTML/SQL/arbitrary binaries and unrecognized versions remain unsupported/quarantined.

An invalid file stays encrypted as the original with its original hash. Diagnostics retain partial parsed counts/assets when available and contain safe codes rather than exception text/raw secrets. An out-of-scope asset quarantines the whole import; no valid subset is silently published. Zero findings are created by this boundary.

## Container support is not a working adapter

Initial guard recognizers cover Nmap 7.x XML with matching tool version and XML-output version 1.03/1.04/1.05, ZAP 2.x alerts API JSON (`{"alerts": [...]}`), and Nikto 2.6.x JSON report arrays with host-level vulnerability arrays. Nmap requires a successful finish marker; incomplete captures remain partial/quarantined. Candidate recorded ZAP and Nikto normalizers store scoped endpoint and source observations, but neither is a verified native adapter: genuine version-matched fixtures, source behavior review and permitted demonstration evidence remain required. Other exports, including other ZAP report layouts and older Nikto JSON/XML reports, remain unsupported rather than guessed.

`container-validated` is explicitly accompanied by `normalizer_enabled: false`, `findings_created: 0`, and recorded-import mode. The candidate ZAP normalization endpoint is a separate operation and also creates zero findings; neither it nor Nmap normalization upgrades registry status to import-only/live. Genuine source verification and authorized demonstration remain required. The project's minimum three network/web imports gate is still later work; no handcrafted or malformed-output fixture counts toward it.

Primary format references: [Nmap native XML](https://nmap.org/book/output-formats-xml-output.html), [ZAP API](https://www.zaproxy.org/docs/api/), [Nikto format/version changes](https://github.com/sullo/nikto/releases), [defusedxml](https://github.com/tiran/defusedxml).

## Verification and requirement trace

`tests/test_ingestion.py` labels every native-shaped/adversarial input handcrafted and exercises bare DTD, XXE/external resources, truncation, deep XML/JSON, duplicate JSON keys, invalid numbers/control characters, unsupported versions/HTML, oversized bytes, compressed traversal/bomb rejection, process deadline, exclusion precedence and URL boundaries. An integrated authenticated API round trip preserves exact original bytes, stores diagnostics, quarantines out-of-scope/partial input and leaves findings empty. Hosted CI repeats the round trip on PostgreSQL; it does not scan any target.

R05/R08/R09: tool/source separation and no invented normalization. R31/R32: bounded private ingestion and scope mapping. R34: explicit limits and preserved evidence. Genuine-parser accuracy remains pending on M01 fixtures and later native adapters; T11 verifies the hostile-file boundary independently.

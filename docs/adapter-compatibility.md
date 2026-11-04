# M06 adapter compatibility and evidence status

This is a parser contract, not proof of installed scanners or successful live integrations. Capability remains `planned` until a genuine, version-matched, redaction-reviewed, rights-cleared artifact and the applicable acceptance checks are reviewed. Uploaded version labels are participant-supplied and do not authenticate a source.

| Tool | Candidate offline format | Fields retained in normalized source record | Live/API state and limits |
|---|---|---|---|
| Nessus | `.nessus` XML rooted at `NessusClientData_v2` | Host identity, plugin ID/name, port/protocol/service, source severity, CVE, available CVSS base score/vector/version, source pointer; repeated plugin occurrences remain distinct | Planned. No Tenable product API, license/edition entitlement, feed check or live scanner path is enabled. Truncated XML is quarantined with an explicit incomplete marker. |
| Greenbone / OpenVAS | GMP XML report rooted at `report`, `get_reports_response` or `gmp` | Host, port/protocol, NVT OID/name, CVE, source severity, CVSS base when supplied, QoD value/type and source pointer | Planned. No GMP connection, manager health/version negotiation, task/configuration selection or feed check is enabled. QoD is not treated as probability. |
| Burp Suite | Burp issue XML rooted at `issues` | Issue serial/type/name, host/path, severity, CWE classification and source pointer | Planned. Base64 request/response elements are not decoded into normalized records; they remain in the private encrypted original. No universal REST API or edition entitlement is assumed. |
| Metasploit | No normalized scanner import format enabled | N/A | Planned and execution-disabled. The application does not expose arbitrary console/module execution, payloads, callbacks, persistence or lateral movement. A future narrow adapter needs organizer-authorized lab scope, module allowlisting, approval-bound parameters, isolated networking, safe stop and cleanup proof. |

## Shared import boundary

The import API checks assessment access, scope revision, declared source tool and format, then stores original bytes through the encrypted evidence store. Parsers run in the isolated, network-denied worker with byte, structure, string and time limits. Extracted assets are checked against the active scope and exclusions before normalization. Out-of-scope imports are quarantined. Normalization creates source-linked observations, not confirmed findings. No target request is generated.

## Evidence still required to promote capability

- Genuine permitted exports for each format, including exact product version/edition, rights basis, capture time, authorization reference and redaction review.
- Parser contract outcomes on those files and an independent source review. Handcrafted fixtures are parser tests only.
- For any live API/runner claim: actual entitlement, installed edition/version, health and protocol checks, a completed authorized run, runtime gate evidence and a linked artifact digest.
- For M06 cross-tool acceptance: a reviewable network/web/infrastructure path with mixed available and unavailable integrations, source-linked evidence, explicit failures and a safe active-validation boundary.

## Sources

- [Tenable Nessus file format](https://docs.tenable.com/quick-reference/nessus-file-format/Nessus-File-Format.pdf)
- [Greenbone GMP API reference](https://docs.greenbone.net/API/GMP/gmp-22.6.html)
- [PortSwigger Burp XML issue export](https://portswigger.net/burp/documentation/desktop/running-scans/reporting/report-settings)
- [Metasploit RPC module API](https://docs.metasploit.com/api/Msf/RPC/RPC_Module.html)

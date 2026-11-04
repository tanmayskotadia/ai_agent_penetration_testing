# M06 implementation status

M06 is not accepted yet. The code paths below are offline candidates and all seven capability entries remain `planned`; version-declared parser tests do not authenticate a scanner, license, entitlement, feed, or artifact.

| Issue | Available implementation | Still required for acceptance |
|---|---|---|
| T31 #40 Nessus | Bounded `.nessus` XML parser; retains host/plugin/service occurrences, CVE and source CVSS when available; truncation is quarantined as incomplete; encrypted original is retained | Genuine permitted exports across relevant versions, redaction review, duplicate/missing-CVSS/truncated test on real source files, exact edition/API entitlement review. No Tenable API or live runner is implemented. |
| T32 #41 Greenbone | Bounded report XML parser; retains host/NVT/port/CVE/severity and QoD as source metadata | Genuine permitted exports and format/version review. No GMP client, health/version negotiation, feed/task/config verification or live scan control. |
| T33 #33 Burp | Bounded Burp issue XML parser; host/path/severity/CWE retained; request/response messages are never decoded into normalized records and stay in encrypted original evidence | Genuine edition-matched export, redaction review and analyst handoff validation. No universal desktop API or live runner is assumed. |
| T34 #42 Metasploit | Existing controlled-validation template is explicitly disabled at approval and claim boundaries; no arbitrary console or module execution path is exposed | The authorized sandbox, module allowlist, isolated execution, stop/timeout and cleanup proof are absent. Do not enable without organizer authorization and a concrete reviewed design. |
| T35 #47 Compatibility | [Adapter compatibility matrix](adapter-compatibility.md), truthful capability registry and generated matrix list candidate formats, limitations, and unverified editions/licenses | Genuine versioned fixtures, redaction/rights review and capability contract evidence per tool. Status must remain planned until those checks pass. |
| T36 #50 Cross-tool flow | The shared evidence/import pipeline can retain source-linked offline observations in one assessment; coverage UI can show source-specific records and candidate correlation | An integrated workflow with genuine permitted network/web/infrastructure captures, partial commercial availability and reviewer-confirmed results has not been run. No scanner is run by this import flow. |

## Parser verification

`tests/test_scanner_imports.py` contains only handcrafted parser fixtures. It checks multi-host Nessus occurrences and CVSS fields, Greenbone QoD treatment, Burp internal DTD/base64 handling, malformed/truncated input rejection and isolated parser execution. It is not genuine-source acceptance evidence.

The authenticated import API stores originals through the encrypted evidence service, checks the active scope revision and exclusions before adding observations, links normalized rows to evidence/run IDs, and creates no confirmed finding. Burp request/response bytes and query values are omitted from normalized output. Import capability remains clearly recorded/offline.

## Manual evidence needed

No local scanner installation is required to exercise the upload routes later. Supply genuine Nessus `.nessus`, Greenbone XML and Burp issue XML exports with the source version/edition, capture time, allowed-use basis, target scope and reviewed redactions. Do not put credentials or public/customer scan data in Git. A real Metasploit live demo additionally requires organizer-authorized lab scope and explicit action-bound approval; without that, it stays disabled and M06 stays open.

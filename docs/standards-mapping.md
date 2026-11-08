# Standards references in frozen reports

Report references are versioned, linked to specific finding observations, and kept separate from scanner text, reviewer decisions, and inferred claims. The frozen JSON stores the catalogue revision, framework register, per-finding mappings, source record IDs, source URL, rationale, and validation/provenance label. The PDF prints the same information.

## Supported catalogue

The pinned catalogue revision is `aegistrace-standards-2026-11-08.1` in [`schemas/standards-catalog.json`](../schemas/standards-catalog.json). The versions and sources recorded in that catalogue are:

| Reference family | Pinned edition/version | How the report uses it |
| --- | --- | --- |
| NIST SP 800-115 | 2008 | Methodology citation. It does not claim every procedure was performed or that a recorded import was a live test. |
| OWASP Top 10 | 2025 | Reviewer mapping to one of the curated A01–A10 categories, with rationale and linked observation IDs. |
| CVE | CVE Program; individual record version not pinned | Only source-observation CVE fields are copied. External existence, details and freshness are not checked. |
| CVSS | Source-reported version; current reference is CVSS 4.0 | Exact source score, version and vector are included only as a complete tuple. The app does not calculate or change a score. |
| CWE | CWE List 5.0 | Only CWE values on selected source observations are copied; they are not validated as a correct weakness mapping. |
| MITRE ATT&CK Enterprise | 20.1, dated 2026-11-05 | Curated technique IDs may be added as reviewer hypotheses, with rationale and observation links. They do not assert an attack occurred. |
| NIST CSF | 2.0, dated 2024-02-26 | Curated outcomes may be reviewer-mapped with rationale and observation links. They do not establish control effectiveness, conformance, or certification. |

Official catalog sources: [NIST SP 800-115](https://doi.org/10.6028/NIST.SP.800-115), [OWASP Top 10:2025](https://top10.owasp.org/2025/), [CVE Program](https://www.cve.org/), [FIRST CVSS v4.0 specification](https://www.first.org/cvss/v4-0/specification-document), [CWE list](https://cwe.mitre.org/data/), [MITRE ATT&CK release history](https://attack.mitre.org/resources/updates/), and [NIST CSF 2.0](https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20).

## Applicability and trust rules

- A reviewer can choose a curated OWASP category, ATT&CK Enterprise technique, or CSF 2.0 subcategory only for the report finding's selected observations. A rationale is required and the API rejects IDs outside the pinned catalogue. The catalogue establishes that an ID exists in the pinned vocabulary, not that the mapping fits the evidence.
- The editor also permits explicit `unknown` and `not applicable` decisions with a rationale and supporting observation IDs. Findings do not need a label from every framework.
- CVE, CWE, and CVSS values cannot be typed into the standards mapping editor. The report derives them from exact selected source fields. CVE/CWE stay `source-reported; not independently validated`. CVSS requires score, version, and vector together and is never recalculated. Unsupported or incomplete values remain unknown in the framework register and original evidence trace.
- Generic free-text supporting references reject common standards identifier formats; structured entries are the only way to place taxonomy identifiers in the standards section.
- ATT&CK categories/techniques are not evidence of adversary behavior. A weakness, scanner category, or open port is not proof of an attack technique.
- NIST CSF outcome mappings do not establish that an organization implements or complies with the framework. The report makes no formal compliance or certification claim.
- Frozen report snapshots retain their original catalogue revision. Updating the catalogue requires a deliberate new revision and a new frozen report; older exports do not change.

## Verification

Run from the repository root:

```powershell
.venv\Scripts\python scripts\export_standards_catalog.py --check
.venv\Scripts\python scripts\export_api_contracts.py --check
.venv\Scripts\python scripts\export_standards_catalog.py --check
.venv\Scripts\pytest tests/test_standards.py tests/test_report_findings.py -q
```

Tests use synthetic `TEST ONLY` observations and establish no scanner accuracy, vulnerability validity, business impact, compliance status, or real mapping suitability.

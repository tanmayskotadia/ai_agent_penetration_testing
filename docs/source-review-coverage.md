# Source review coverage and interpretation record

Reviewed for T01 on 4 November 2026. Source identity and digest are in [the source register](sources/source-register.json). The register captures requirements and interpretations; it is not an assertion of completed product behavior.

| PDF page | Sections / material | Register prefixes | Review outcome |
|---:|---|---|---|
| 1 | 1 Background; 2 Problem Statement | CTX, AI | Lifecycle and reasoning objectives captured; background distinguished from mandatory functionality |
| 2 | Security boundary; 3 workflow and additional UX requirements; start of 4 | SAFE, WF, UX | Authorized lab and active-action approval separated; eight workflow steps and four UX obligations captured |
| 3 | 4 seven-tool table and integration requirements; 5.1; start of 5.2 | INT, SCOPE | All seven roles, allowed modes, transparency/licensing and scope registration captured |
| 4 | 5.2-5.8 | AI, ORCH, DATA, EVID, RISK, SAFE, REPORT | Adaptive inputs; execution/timeout/error status; dedupe; seven evidence fields; five risk factors; no fabrication; approval/outcome; reporting captured |
| 5 | 6 minimum-versus-bonus table and integration transparency; 7.1; start of 7.2 | MIN, ADV, INT, REPORT | Mandatory minimum and bonus features kept distinct; four capability status values captured; downloadable PDF required |
| 6 | 7.2-7.6 report sections; 8 first four references | REPORT, STD | All report fields retained, with conditional CVSS/CVE/CWE; methodology and impact not omitted |
| 7 | 8 remaining references and compliance note; 9.1-9.6 | STD, DEL, ARCH, REPO | Seven frameworks plus no-formal-compliance qualification; all architecture/repository deliverable fields captured |
| 8 | 9.6 matrix details; 10 all seven demo checks; start of 11 | INT, DEMO | Limitations/assumptions/unsupported scenarios and seven independently inspectable demonstrations captured |
| 9 | 11 eight weighted criteria; 12 first five quality characteristics | JUDGE, QUAL | Weights transcribed as 15/20/15/15/10/10/10/5 (100); quality aspirations not presented as guaranteed scores |
| 10 | 12 remaining characteristics; 13 ethics/integrity; success criterion | QUAL, SAFE, SUCCESS | Full traceability, scope, approval, uncertainty, recovery and professional accuracy captured; no fabricated/public testing; data protection; reduced analyst effort with human control |

The supplied PDF text was re-read in full against the earlier ten-page extraction. The table layouts for tools, prototype/bonus and judging weights were inspected during the initial review; the row distinctions are preserved here.

| Official page material | Register prefixes | Review outcome |
|---|---|---|
| Submission instructions | WEB | Three distinct artifact/link gates, access checks and missing-artifact consequence captured |
| Lab boundary | WEB, SAFE | Event-wide lab and human-control rule aligns with PDF boundary |
| Participation / dates / Discord | EVENT | Kept separate from engineering estimates; user preference for quality does not waive event rules |
| Themes and innovation expectations | THEME | Contextual decisions, meaningful outcomes and practical secure scalability mapped as objectives, not new invented mandatory features |
| Other attachments/social links/private coordination | Exclusions in source register | Not fetched or assumed applicable to this selected problem statement |

## Interpretations recorded for review

- The minimum is three working integrations **or supported imports**, with network and web coverage. It is not seven compulsory live scanners for minimum acceptance.
- All seven tools still need truthful status disclosure; the complete target addresses their expected roles. Full legal live/API support is explicitly advanced.
- Scanner execution approval and active exploitation/offensive-validation approval are related but distinct. A target allowlist alone is not sufficient consent to all actions.
- Native imports and genuine recorded output remain labelled as such. Handcrafted parser data is test-only and cannot stand in for scanner proof.
- CVSS is conditional on supported evidence; CVE/CWE applies where relevant. Unknown fields must not be filled by the model.
- Applicable framework mappings do not establish formal compliance. A mapped ATT&CK technique does not establish that exploitation happened.
- A failed/partial scanner does not demonstrate complete coverage. A missing retest cannot establish resolution.
- Quality targets and extra features in the implementation plan are proposed engineering goals, not organizer scoring guarantees.

## Remaining assurance limits

This review is a requirements analysis by the implementing assistant, ready for participant review. It is not independent organizer approval, a legal/license review, a verified lab manifest, or a product acceptance run. Private announcements and later source changes remain unverified. Every product acceptance proof remains to be collected in later issues.

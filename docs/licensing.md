# Licensing and availability assumptions - T06

**Scope:** record upstream sources and assumptions before promising capabilities. No scanner binary/feed, licensed key, vendor source copy or genuine raw scan corpus is included in this repository. No license agreement or purchase is accepted by this work.

## Scanner/component review

| Tool | Reviewed source and observation | Distribution / capability decision |
|---|---|---|
| Nmap | [Official NPSL page](https://nmap.org/npsl/) identifies Nmap Public Source License and release-dependent terms | Review the exact installed LICENSE/COPYING and any Npcap terms. Do not infer unrestricted embedding/redistribution from free download availability. No Nmap/Npcap binary is bundled. |
| Nikto | [Current upstream COPYING](https://github.com/sullo/nikto/blob/main/COPYING) distinguishes GPLv3 code, separate database restrictions and LibWhisker terms | Do not label the entire code/database bundle with one permissive license or extract/repackage databases. Review exact release and upstream commercial-use policy before integration/distribution. |
| ZAP | [Upstream LICENSE](https://github.com/zaproxy/zaproxy/blob/main/LICENSE) is identified as Apache-2.0 | Keep release/add-on dependencies and notices separate; this does not prove installation, authentication, API add-ons or target permission. |
| Greenbone/OpenVAS | [gvmd COPYING](https://github.com/greenbone/gvmd/blob/main/COPYING) is identified AGPL-3.0; [scanner COPYING](https://github.com/greenbone/openvas-scanner/blob/main/COPYING) GPL-2.0 | Stack components and feeds have separate terms/version/readiness. No single blanket license, feed entitlement or functioning deployment is assumed. |
| Metasploit Framework | [Combined upstream LICENSE](https://github.com/rapid7/metasploit-framework/blob/master/LICENSE) describes BSD-3-clause framework material plus separately listed third-party components | Do not apply the framework label to all bundled payload/data/dependency files. No exploit/payload binary is redistributed by this repository. |
| Nessus | [Official product/edition information](https://www.tenable.com/products/nessus) | Actual edition, subscription/export/API entitlement and installed agreement are unverified. No scanner/license/feed is bundled; import/API plans remain conditional. |
| Burp Suite | [Official product editions](https://portswigger.net/burp) distinguish manual/toolkit/scanning offerings | Verify the installed edition and its exact export/API entitlement; no universal desktop REST API or commercial scanner access is promised. No proprietary software or key is bundled. |

Sources were reviewed on 4 November 2026. GitHub's automatic license identifier returned `NOASSERTION` for Nikto and the Metasploit combined file; that is not treated as absence of license terms. The exact files were inspected for the distinctions above. Upstream default branches can change; review and record the installed release before implementation/distribution. These observations are not a formal legal opinion or certification of all downstream usage.

## Application dependencies and project licensing

`uv.lock` and `frontend/package-lock.json` pin packages for reproducibility, not automatic license approval. [Python distribution metadata](sources/runtime-dependency-licenses.json) records the installed top-level dependency versions/license labels. Transitive packages, JavaScript packages and image operating-system components retain their own terms/notices. Preserve required notices when actually distributing packaged applications or images; do not assume one top-level identifier covers everything.

No project-wide redistribution license is invented for the participant's original code. The owner must choose one before making an affirmative licensing grant; public repository visibility alone is not such a grant. `NOTICE` records these boundaries without overwriting third-party rights or selecting an unsolicited project license.

## Fixture and model rights

Tool access does not automatically grant redistribution rights in customer/organizer scan data. Record capture permission, ownership, redaction review and allowed sharing separately. Keep raw private originals outside Git; public fixture paths require a documented redistribution basis. Model-provider terms, retention, location and use of sensitive assessment data remain unselected/unapproved, so external processing is disabled.

## Acceptance for this inventory issue

T06 is complete when the installed/unavailable/unknown states and prerequisites are truthfully documented, no unlicensed component is bundled and private-data/model assumptions are explicit. It does not require purchasing all commercial tools or pretending their capabilities exist. Actual adapter verification remains T20/T25-T35; organizer permission and genuine data remain T04/T05; model evaluation remains T42.

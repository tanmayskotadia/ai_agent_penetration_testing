# Cross-tool correlation and reviewer decisions (T43)

## Candidate generation

Correlation is deterministic and review-only. A candidate requires an exact source CVE, or an exact CWE plus normalized title, and the same assessment asset and location. The strongest location identity is the endpoint, followed by a service identity; only when neither exists does the normalized title serve as a conservative fallback. Web parameter names are included in the candidate key; values are never stored in the normalized observation. Candidates with missing asset/location identity are not grouped. Similar banners, scanner-specific wording without a common explicit identifier, and observations from only one tool do not become cross-tool candidate groups.

Candidate membership never creates or confirms a vulnerability. Every result keeps its original observation ID, evidence ID, source tool, asset, service, endpoint, parameter names, source severity/CVSS, confidence and validation state. A CVE found on two assets or endpoints is displayed as distinct candidate occurrences rather than one collapsed result.

## Reviewer operations

Authenticated human reviewers and administrators can use:

- GET /api/v1/assessments/{assessment_id}/correlations/reviews to inspect the immutable decision history, current merged clusters and reviewer-split candidates.
- POST /api/v1/assessments/{assessment_id}/correlations/reviews with action=merge and the exact observation IDs to confirm a duplicate group.
- action=split with a current cluster ID and a complete, non-overlapping partition of its observations to mark observations as distinct. Singleton partitions are allowed and remove those items from merged groups.
- action=undo with the latest review ID to restore the previous cluster state.

Every decision requires a rationale, is recorded as an append-only assessment resource, and creates an audit event. A new decision snapshots the prior and resulting state. Undo is limited to the most recent non-undo operation so concurrent or stale review history cannot silently overwrite later decisions. Observations, endpoint records and encrypted evidence remain unchanged.

The workspace UI exposes candidate merge, reviewed-group split and latest-decision undo controls. The PDF freezes reviewer-confirmed groups and reviewer-split candidates alongside the exact observation IDs, asset/source list and rationale. A report omits a review cluster if the selected immutable source revisions do not contain every observation in it.

## Verification limits

Handcrafted tests verify deterministic matching, asset/endpoint/parameter separation, preserved occurrences, and the immutable review-state transition helpers. They do not establish correlation precision/recall. That requires genuine permitted captures and independent labels. No model-generated score or synthetic fixture is represented as measured accuracy.


## Reviewer-visible occurrence context

Candidate and reviewer-confirmed source occurrences include the safe endpoint method/path or network service protocol/port, parameter names only, assessment asset ID, source tool, immutable observation ID, and evidence ID. Query strings and parameter values remain confined to encrypted original evidence. Cross-tool candidates require an exact reported identifier plus the same assessment asset, canonical endpoint/service identity, and exact parameter-name set; each source observation remains a separate occurrence. Same identifiers on a different asset, endpoint, or parameter set remain separate. The reviewer UI shows this context before a merge and after confirmation.

The end-to-end synthetic integration check imports source-labeled ZAP and Nikto records through the normal intake and coverage APIs, demonstrates one exact shared candidate plus separate endpoint/parameter/asset observations, verifies the reviewer merge retains both evidence links, and confirms source observations remain unchanged. These fixtures are test-only and do not measure correlation precision/recall or prove genuine scanner execution.


The frozen VAPT PDF also renders each reviewer-confirmed occurrence with its source, safe endpoint or service location, parameter names, asset, observation ID, and evidence ID. The end-to-end synthetic verification asserts those occurrence details survive normalization, reviewer merge, and export.

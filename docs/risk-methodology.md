# Contextual priority methodology

The review API retains source CVSS as received. A separate `aegistrace-context-priority-v1` index is computed only from factors with explicit provenance: source CVSS and version (weight 0.40), exposure (0.20), exploitability state (0.20), analyst-recorded asset criticality 1–5 (0.15), and method-disclosed source confidence (0.05). The index renormalizes over available factors only when at least one contextual factor is present. It is not CVSS, calibrated risk, or exploitability probability.

Exposure, exploitability and asset criticality are unknown unless supplied with a provenance reference. Missing factors are listed. Unknown-only input receives no numeric local priority; source CVSS remains a secondary ordering signal. Severe CVSS combined with disclosed low source confidence receives a high-review-attention flag so uncertainty does not silently hide a potentially serious report.

Snapshots show `context-insufficient` until provenance-backed context is collected. The ranking is deterministic and versioned but not calibrated; independent outcome labels are needed before any accuracy claim.

Reviewer/admin users can record context with `POST /api/v1/assessments/{assessment_id}/asset-contexts`. The target asset must exist in the assessment, and each non-unknown context field requires a provenance reference plus reviewer rationale. Revisions are append-only API records with an audit event and the prior revision link; `GET .../asset-contexts` returns the latest revision per asset. References are participant/reviewer supplied and are not independently authenticated. A regular analyst can view coverage and priority results but cannot write risk context.

## Policy v2 (#57)

The active policy is `aegistrace-context-priority-v2`; v1 above describes the retained baseline weights. Only finite CVSS 0-10 with a supported version and confidence 0-1 with a nonblank method contribute. Booleans, invalid versions, infinities and NaN are unknown. Original CVSS vectors, source severity and provenance are preserved. No CVSS calculation is performed or claimed; therefore a CVSS calculation library is unnecessary.

For reproducibility, `weighted_sum` / `available_weight`, rounded to one decimal, gives the local index when at least one contextual factor is documented. Scales: CVSS x10; restricted/internal/internet-facing exposure 30/60/100; suspected/confirmed exploitability 50/100; criticality (value - 1) x25; source confidence x100. Missing factors contribute neither weight nor score. Comparing different available-factor sets requires analyst judgment; rounding is a display convention, not empirical precision.

Contradictory reviewer decisions suppress the exploitability contribution and flag contradictory-evidence-review in current coverage, frozen report ranking and UI details. Severe low-confidence and contradictory observations receive elevated review attention; no decision removes source observations. Source confidence remains uncalibrated, and no conflicting source is averaged away. Ties use observation ID. Old frozen reports retain their policy version.

Inputs are normalized source observations, optional documented asset context and optional human decisions. Synthetic policy tests and the integrated review/coverage check verify unknown values, reproducibility, monotonic exposure and contradiction handling. They do not establish scanner accuracy or genuine evidence provenance. No new credentials or cloud configuration are required.

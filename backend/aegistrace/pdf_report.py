"""Small dependency-free PDF renderer for frozen, source-linked result snapshots."""

from typing import Any

PAGE_WIDTH = 595
PAGE_HEIGHT = 842
LEFT = 48
BODY_HEIGHT_PER_PAGE = 650


def _plain(value: Any) -> str:
    """Keep untrusted source text printable in the built-in PDF fonts."""
    ascii_text = str(value).encode("ascii", "replace").decode("ascii")
    return "".join(character if " " <= character <= "~" else " " for character in ascii_text)


def _escape(value: str) -> bytes:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)").encode("ascii")


def _wrap(value: Any, width: int = 74) -> list[str]:
    text = _plain(value).strip()
    if not text:
        return [""]
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        while len(word) > width:
            if current:
                lines.append(current)
                current = ""
            lines.append(word[:width])
            word = word[width:]
        candidate = f"{current} {word}".strip()
        if len(candidate) > width and current:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    return lines


def _display(value: Any) -> str:
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) if value else "none"
    if value is None:
        return "unknown"
    return str(value)


def _content_stream(lines: list[tuple[str, int]], page_number: int, page_count: int) -> bytes:
    commands: list[bytes] = []

    def draw(text: str, y: int, size: int, bold: bool = False, color: str = "0 0 0") -> None:
        font = "F2" if bold else "F1"
        commands.extend(
            [
                b"BT",
                f"/{font} {size} Tf {color} rg {LEFT} {y} Td ".encode("ascii")
                + b"("
                + _escape(text)
                + b") Tj",
                b"ET",
            ]
        )

    draw("AegisTrace - Vulnerability Assessment Review Report", 788, 14, True, "0.08 0.20 0.32")
    draw(
        "Reviewer export | Source records only | Not a complete VAPT report",
        769,
        9,
        False,
        "0.30 0.34 0.38",
    )
    y = 738
    for text, level in lines:
        if level == 0:
            y -= 4
            draw(text, y, 13, True, "0.08 0.20 0.32")
            y -= 18
        elif level == 1:
            draw(text, y, 10, True)
            y -= 15
        else:
            draw(text, y, 9)
            y -= 13
    draw(
        f"AegisTrace | Page {page_number} of {page_count} | Coverage is not established by imports",
        28,
        8,
        False,
        "0.35 0.38 0.42",
    )
    return b"\n".join(commands)


def render_evidence_report(
    snapshot: dict[str, Any],
    observations: list[dict[str, Any]],
    assets: dict[str, str],
) -> bytes:
    """Render an immutable export with explicit limits and source provenance."""
    revisions = snapshot.get("result_revisions", [])
    lines: list[tuple[str, int]] = []
    lines.extend(
        [
            ("Assessment and export", 0),
            (f"Assessment ID: {snapshot.get('assessment_id', 'unknown')}", 2),
            (f"Frozen export ID: {snapshot.get('id', 'see response metadata')}", 2),
            (f"Created at: {snapshot.get('created_at', 'unknown')}", 2),
            (f"Source digest (SHA-256): {snapshot.get('sha256', 'see response metadata')}", 2),
            ("", 2),
            ("Interpretation and coverage", 0),
            ("This report summarizes recorded/imported evidence included in the frozen export.", 2),
            (
                "It does not claim that a live scan ran, that the supplied source is authentic, or that every asset or endpoint was tested.",
                2,
            ),
            (
                "Observations remain suspected source evidence until a human reviewer validates them.",
                2,
            ),
            ("Coverage status: NOT ESTABLISHED", 1),
            ("", 2),
            (f"Included source-result revisions: {len(revisions)}", 2),
            (
                f"Source observations referenced: {snapshot.get('content', {}).get('summary_counts', {}).get('source_observation_count', len(observations))}",
                2,
            ),
        ]
    )
    content = snapshot.get("content")
    if isinstance(content, dict):
        lines.append(("Executive summary", 0))
        lines.extend((part, 2) for part in _wrap(content.get("executive_summary", "Unknown")))
        lines.append(("Assessment scope and rules of engagement", 0))
        scope = content.get("scope", {})
        for label, value in [
            ("Scope revision", scope.get("revision", "unknown")),
            ("Targets", scope.get("targets", [])),
            ("Exclusions", scope.get("exclusions", [])),
            ("Authorization", scope.get("authorization_status", "unknown")),
            ("Authorization reference", scope.get("authorization_reference") or "not supplied"),
            ("Validity", scope.get("valid_until") or "not supplied"),
        ]:
            lines.extend((part, 2) for part in _wrap(f"{label}: {_display(value)}"))
        methodology = content.get("methodology", {})
        lines.append(("Methodology", 0))
        for label, value in [
            ("Selected source tools", methodology.get("tools_with_selected_sources", [])),
            ("Processing", methodology.get("processing", "unknown")),
            ("Correlation", methodology.get("correlation", "unknown")),
            ("Priority policy", methodology.get("priority_policy", "unknown")),
            (
                "Live testing",
                "not claimed"
                if not methodology.get("live_scanning_claimed")
                else "see source record",
            ),
            ("Rules of engagement", methodology.get("rules_of_engagement", "unknown")),
        ]:
            lines.extend((part, 2) for part in _wrap(f"{label}: {_display(value)}"))
        lines.append(("Asset inventory", 0))
        if not content.get("assets"):
            lines.append(("No in-scope assets were linked to the selected source revisions.", 2))
        for asset in content.get("assets", []):
            lines.extend(
                (part, 2)
                for part in _wrap(
                    f"{asset.get('identifier', 'unknown asset')} | {asset.get('kind', 'unknown')} | asset ID {asset.get('id', 'unknown')}"
                )
            )
        lines.append(("Tool execution summary", 0))
        if not content.get("tool_runs"):
            lines.append(("No source tool runs were linked to the selected revisions.", 2))
        for run in content.get("tool_runs", []):
            lines.extend(
                (part, 2)
                for part in _wrap(
                    f"{run.get('tool', 'unknown')} {run.get('tool_version', 'unknown version')} | "
                    f"{run.get('mode', 'unknown mode')} | {run.get('state', 'unknown state')} | "
                    f"run {run.get('id', 'unknown')} | captured {run.get('captured_at', 'unknown')}"
                )
            )
        lines.append(("Severity distribution (source-reported)", 0))
        severity = content.get("source_severity_distribution", {})
        if not severity:
            lines.append(("No source severity values were supplied.", 2))
        for label, count in severity.items():
            lines.extend((part, 2) for part in _wrap(f"{label}: {count} source observations"))
        if severity:
            lines.append(
                ("Source-reported severity counts (each # represents one item, capped at 40)", 1)
            )
            for label, count in severity.items():
                bar = "#" * min(int(count), 40)
                suffix = " (bar capped)" if int(count) > 40 else ""
                lines.extend((part, 2) for part in _wrap(f"{label}: |{bar}| {count}{suffix}"))
        lines.append(("Prioritized observations and reviewer findings", 0))
        lines.extend(
            (part, 2)
            for part in _wrap(
                f"Source observations: {content.get('summary_counts', {}).get('source_observation_count', sum(content.get('source_severity_distribution', {}).values()))}; "
                f"ranked entries: {len(content.get('prioritized_observations', []))}; "
                f"reviewer report findings: {content.get('summary_counts', {}).get('reviewer_finding_count', 0)}; "
                f"reviewer-recorded findings: {len(content.get('reviewed_findings', []))}; "
                f"distinct occurrences: {content.get('occurrence_count', 0)}."
            )
        )
        for item in content.get("prioritized_observations", []):
            priority = item.get("priority", {})
            lines.extend(
                (part, 2)
                for part in _wrap(
                    f"Observation {item.get('observation_id', 'unknown')}: {item.get('title', 'untitled')} | "
                    f"source CVSS {item.get('source_cvss_score', 'unknown')} | local index "
                    f"{priority.get('local_priority_index', 'unknown')} ({priority.get('state', 'unknown')}) | "
                    f"evidence {item.get('evidence_id', 'unknown')} | review {priority.get('review_attention', 'standard-review')}"
                )
            )
        lines.append(("Reviewer correlation decisions", 0))
        reviewed_correlations = content.get("reviewed_correlations", [])
        if not reviewed_correlations:
            lines.append(
                ("No cross-tool duplicate groups have an explicit reviewer merge decision.", 2)
            )
        for group in reviewed_correlations:
            lines.extend(
                (part, 2)
                for part in _wrap(
                    f"Reviewer-merged cluster {group.get('cluster_id', 'unknown')}: "
                    f"{group.get('occurrence_count', 0)} preserved source occurrences; "
                    f"assets {group.get('asset_ids', [])}; tools {group.get('source_tools', [])}."
                )
            )
            lines.extend(
                (part, 2)
                for part in _wrap(
                    f"Rationale: {group.get('rationale', 'not supplied')}; "
                    f"source observation IDs: {group.get('observation_ids', [])}."
                )
            )
            for occurrence in group.get("observations", []):
                endpoint = occurrence.get("endpoint") or {}
                service = occurrence.get("service") or {}
                location = (
                    f"{endpoint.get('method', 'ANY')} {endpoint.get('path', 'path unavailable')}"
                    if endpoint
                    else f"{service.get('protocol', 'transport unknown')}/"
                    f"{service.get('port', 'port unknown')}"
                )
                lines.extend(
                    (part, 2)
                    for part in _wrap(
                        f"Source occurrence {occurrence.get('observation_id', 'unknown')}: "
                        f"{occurrence.get('source_tool', 'unknown source')} at {location}; "
                        f"parameters {occurrence.get('parameter_names', [])}; "
                        f"asset {occurrence.get('asset_id', 'unknown')}; "
                        f"evidence {occurrence.get('evidence_id', 'unknown')}."
                    )
                )
        for group in content.get("reviewed_splits", []):
            lines.extend(
                (part, 2)
                for part in _wrap(
                    f"Reviewer-split candidate {group.get('cluster_id', 'unknown')}: "
                    f"partitions {group.get('partitions', [])}; rationale: "
                    f"{group.get('rationale', 'not supplied')}."
                )
            )
        lines.append(("Detailed findings and source observations", 0))
        counts = content.get("summary_counts", {})
        lines.extend((part, 2) for part in _wrap(f"Counts (separate units): {counts}"))
        if not content.get("detailed_findings"):
            lines.append(
                (
                    "No detailed findings or observations in the selected revisions; this does not establish a clean assessment.",
                    2,
                )
            )
        for finding in content.get("detailed_findings", []):
            lines.extend((part, 1) for part in _wrap(f"{finding['id']}: {finding['title']}"))
            for label, value in [
                ("Record type", finding["record_kind"]),
                ("Information kind", finding["information_kind"]),
                ("Validation", finding["validation_state"]),
                ("Description", finding["description"]),
                ("Assets", finding["asset_ids"]),
                ("Observation occurrences", finding["occurrence_count"]),
                ("Technical impact", finding["technical_impact"]),
                ("Business impact", finding["business_impact"]),
                ("Remediation", finding["remediation"]),
                ("References", finding["references"]),
                ("Content provenance", finding["content_provenance"]),
            ]:
                lines.extend((part, 2) for part in _wrap(f"{label}: {value}"))
            for observed in finding["source_records"]:
                lines.extend(
                    (part, 2)
                    for part in _wrap(
                        f"Source observation {observed.get('id', 'unknown')} | tool {observed.get('source_tool', 'unknown')} | "
                        f"asset {observed.get('asset_id', 'unknown')} | evidence {observed.get('evidence_id', 'unknown')} | "
                        f"observed {observed.get('observed_at', 'unknown')} | source reference {observed.get('source_key', 'unknown')} | "
                        f"severity {observed.get('source_severity') or 'unknown'} | CVSS {observed.get('cvss_score') if observed.get('cvss_score') is not None else 'unknown'} "
                        f"version {observed.get('cvss_version') or 'unknown'} vector {observed.get('cvss_vector') or 'unknown'} | "
                        f"CVE {observed.get('cve') or 'not supplied'} CWE {observed.get('cwe') or 'not supplied'} | "
                        f"confidence {observed.get('confidence') if observed.get('confidence') is not None else 'unknown'} method {observed.get('confidence_method') or 'unknown'}"
                    )
                )
        lines.append(("Selected source processing outcomes", 0))
        for outcome in content.get("execution_summary", []):
            lines.extend((part, 2) for part in _wrap(str(outcome)))
        for reference in content.get("evidence_manifest", []):
            lines.extend(
                (part, 2)
                for part in _wrap(
                    f"Evidence source {reference.get('id')}: SHA-256 {reference.get('sha256')} | {reference.get('pointer_type')} {reference.get('pointer')} | captured {reference.get('captured_at')}"
                )
            )
        for approval in content.get("approvals_and_decisions", {}).get("action_approvals", []):
            lines.extend(
                (part, 2)
                for part in _wrap(
                    f"Action approval {approval.get('id')}: {approval.get('state', 'unknown')} | digest {approval.get('action_digest', 'unknown')} | reviewer {approval.get('reviewer') or 'not supplied'}"
                )
            )
        impact = content.get("impact_and_remediation", {})
        lines.append(("Business impact, recommendations and references", 0))
        lines.extend((part, 2) for part in _wrap(f"Status: {impact.get('status', 'unknown')}"))
        lines.extend(
            (part, 2)
            for part in _wrap(f"Business impact: {impact.get('business_impact', 'unknown')}")
        )
        lines.extend(
            (part, 2) for part in _wrap(f"Remediation: {impact.get('remediation', 'unknown')}")
        )
        lines.extend((part, 2) for part in _wrap(f"References: {impact.get('references', [])}"))
        decision_data = content.get("approvals_and_decisions", {})
        lines.append(("Human approvals and decisions", 0))
        lines.extend(
            (part, 2)
            for part in _wrap(
                f"Recorded approvals: {len(decision_data.get('approvals', []))}; "
                f"decisions: {len(decision_data.get('decisions', []))}. Full frozen records are available in the JSON manifest."
            )
        )
        lines.append(("Assumptions, scan failures and limitations", 0))
        if not content.get("limitations"):
            lines.append(("No limitations were supplied.", 2))
        for limitation in content.get("limitations", []):
            lines.extend((part, 2) for part in _wrap(limitation))
        if content.get("grounded_claims"):
            lines.append(("Structured claim checks", 0))
            for claim in content["grounded_claims"]:
                lines.extend(
                    (part, 2)
                    for part in _wrap(
                        f"{claim.get('claim_type')}: {claim.get('value') if claim.get('state') == 'source-supported' else 'unknown'} | "
                        f"state {claim.get('state')} | source-reported only; not independently verified | "
                        f"asset {claim.get('asset_id')} | evidence {claim.get('evidence_id')} | "
                        f"observation {claim.get('observation_id')} | reasons {claim.get('reasons', [])}."
                    )
                )
        lines.append(("Evidence manifest", 0))
        lines.extend(
            (part, 2)
            for part in _wrap(
                "Use the frozen JSON export and its SHA-256 digest to inspect revision IDs, evidence IDs, source hashes, parser revisions, and source observation references."
            )
        )
    if not isinstance(content, dict):
        for limitation in snapshot.get("limitations", []):
            for wrapped in _wrap(f"Limitation: {limitation}"):
                lines.append((wrapped, 2))

    coverage = snapshot.get("coverage_snapshot")
    if isinstance(coverage, dict):
        lines.append(("Coverage and capabilities at export time", 0))
        for text in [
            f"Captured: {coverage.get('captured_at', 'unknown')}",
            f"Coverage digest: {coverage.get('snapshot_sha256', 'unknown')}",
            f"Coverage state: {coverage.get('coverage_state', 'unknown')}",
        ]:
            lines.extend((part, 2) for part in _wrap(text))
        for mode in ("live-request", "disposable-test"):
            counts = coverage.get("operation_coverage", {}).get(mode, {})
            lines.append(
                (
                    f"{mode}: {counts.get('attempted_count', 0)} attempted / {counts.get('declared_operation_count', 0)} declared operations",
                    2,
                )
            )
            lines.extend((part, 2) for part in _wrap(f"States: {counts.get('state_counts', {})}"))
        for text in [
            f"Credential states at export: {coverage.get('api_credential_states', {})}",
            f"Native jobs: {coverage.get('native_job_states', {})}; API jobs: {coverage.get('api_job_states', {})}",
        ]:
            lines.extend((part, 2) for part in _wrap(text))
        for capability in coverage.get("capabilities", []):
            text = (
                f"{capability.get('name')}: {capability.get('mode')} | license: {capability.get('license_status')} | "
                f"edition: {capability.get('installed_edition') or 'unknown'} | last verification: {capability.get('last_verified_at') or 'none'}"
            )
            lines.extend((part, 2) for part in _wrap(text))
            for detail in [
                f"Verified formats: {capability.get('supported_formats') or 'none'}; candidate guards: {capability.get('guarded_containers') or 'none'}",
                f"Verification run: {capability.get('last_verified_run_id') or 'none'}",
                f"Limitations: {capability.get('limitations') or 'not supplied'}",
            ]:
                lines.extend((part, 2) for part in _wrap(detail))
        for gap in coverage.get("gaps", []):
            lines.extend((part, 2) for part in _wrap(f"Gap: {gap}"))

    lines.append(("Frozen source runs", 0))
    if not revisions:
        lines.append(("No source-result revisions were included in this export.", 2))
    for index, revision in enumerate(revisions, start=1):
        lines.append(
            (
                f"Source {index}: {revision.get('parser_code', 'unknown source')} - {revision.get('state', 'unknown')}",
                1,
            )
        )
        for label, key in [
            ("Tool", "tool"),
            ("Tool version", "tool_version"),
            ("Run ID", "run_id"),
            ("Revision ID", "id"),
            ("Captured at", "captured_at"),
            ("Mode", "mode"),
            ("Evidence ID", "evidence_id"),
            ("Source SHA-256", "source_sha256"),
            ("Parser revision", "parser_revision"),
            ("Source observations", "observation_ids"),
        ]:
            value = revision.get(key, "unknown")
            if key == "observation_ids":
                value = len(value) if isinstance(value, list) else 0
            for wrapped in _wrap(f"{label}: {value}"):
                lines.append((wrapped, 2))
        for warning in revision.get("warnings", []):
            for wrapped in _wrap(f"Source limitation: {warning}"):
                lines.append((wrapped, 2))

    if not isinstance(content, dict) or "detailed_findings" not in content:
        lines.append(("Source observations", 0))
        if not observations:
            lines.append(("No normalized observations were present in the selected revisions.", 2))
        for index, observation in enumerate(observations, start=1):
            asset = assets.get(str(observation.get("asset_id")), "unmapped asset")
            title = observation.get("title", "Untitled source observation")
            for line_number, wrapped in enumerate(_wrap(f"Observation {index}: {title}")):
                lines.append((wrapped, 1 if line_number == 0 else 2))
            for label, value in [
                ("Source tool", observation.get("source_tool", "unknown")),
                ("Asset", asset),
                ("Observed at", observation.get("observed_at", "unknown")),
                ("Source key", observation.get("source_key", "unknown")),
                ("Source severity", observation.get("source_severity") or "not supplied"),
                (
                    "CVSS",
                    observation.get("cvss_score")
                    if observation.get("cvss_score") is not None
                    else "not supplied",
                ),
                ("CVSS vector", observation.get("cvss_vector") or "not supplied"),
                ("CVSS version", observation.get("cvss_version") or "not supplied"),
                ("CVE", observation.get("cve") or "not supplied"),
                ("CWE", observation.get("cwe") or "not supplied"),
                (
                    "Source confidence",
                    observation.get("confidence")
                    if observation.get("confidence") is not None
                    else "not supplied",
                ),
                ("Confidence method", observation.get("confidence_method") or "not supplied"),
                ("Validation", observation.get("validation_state", "unknown")),
                ("Evidence ID", observation.get("evidence_id", "unknown")),
            ]:
                for wrapped in _wrap(f"{label}: {value}"):
                    lines.append((wrapped, 2))

    lines.append(("Reviewer triage decisions", 0))
    triage = snapshot.get("finding_reviews", [])
    if not triage:
        lines.append(
            (
                "No reviewer triage decisions are recorded; confidence and validation remain unknown or source-reported.",
                2,
            )
        )
    for decision in triage:
        for label, value in [
            ("Observation", decision.get("observation_id", "unknown")),
            ("Reviewer state", decision.get("validation_state", "unknown")),
            ("Information kind", decision.get("information_kind", "reviewer-decision")),
            (
                "Confidence",
                decision.get("confidence") if decision.get("confidence") is not None else "unknown",
            ),
            ("Confidence method", decision.get("confidence_method") or "not supplied"),
            ("Calibration", decision.get("calibration_status", "not-calibrated")),
            ("Contradictory observations", decision.get("contradictory_observation_ids", [])),
            ("Reviewer rationale", decision.get("rationale", "not supplied")),
            ("Recorded at", decision.get("recorded_at", "unknown")),
        ]:
            for wrapped in _wrap(f"{label}: {value}"):
                lines.append((wrapped, 2))

    total_observations = int(snapshot.get("observation_reference_count", len(observations)))
    if total_observations > len(observations):
        lines.append(
            (
                f"Display limit: {len(observations)} of {total_observations} observations are listed; consult the JSON export for the frozen source snapshot.",
                2,
            )
        )

    blocks: list[list[tuple[str, int]]] = []
    index = 0
    while index < len(lines):
        block = [lines[index]]
        starts_section = lines[index][1] == 0
        index += 1
        while index < len(lines) and lines[index][1] not in {0, 1}:
            block.append(lines[index])
            index += 1
        if starts_section and index < len(lines) and lines[index][1] == 1:
            block.append(lines[index])
            index += 1
            while index < len(lines) and lines[index][1] == 2:
                block.append(lines[index])
                index += 1
        blocks.append(block)

    pages: list[list[tuple[str, int]]] = []
    current_page: list[tuple[str, int]] = []
    current_height = 0
    for block in blocks:
        block_height = sum(22 if level == 0 else 15 if level == 1 else 13 for _, level in block)
        if current_page and (
            block_height <= BODY_HEIGHT_PER_PAGE
            and current_height + block_height > BODY_HEIGHT_PER_PAGE
            or block_height > BODY_HEIGHT_PER_PAGE
            and current_height + 50 > BODY_HEIGHT_PER_PAGE
        ):
            pages.append(current_page)
            current_page = []
            current_height = 0
        if block_height <= BODY_HEIGHT_PER_PAGE:
            current_page.extend(block)
            current_height += block_height
        else:
            # Long capability/limitation sections must split across pages rather
            # than overflow beneath the footer as one indivisible block.
            for line in block:
                height = 22 if line[1] == 0 else 15 if line[1] == 1 else 13
                if current_page and current_height + height > BODY_HEIGHT_PER_PAGE:
                    pages.append(current_page)
                    current_page = []
                    current_height = 0
                current_page.append(line)
                current_height += height
    if current_page:
        pages.append(current_page)
    if not pages:
        pages = [[]]
    objects: list[bytes] = [b""]

    def add_object(value: bytes) -> int:
        objects.append(value)
        return len(objects) - 1

    catalog_id = add_object(b"")
    pages_id = add_object(b"")
    regular_font_id = add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    bold_font_id = add_object(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
    page_ids: list[int] = []
    for page_number, page_lines in enumerate(pages, start=1):
        content = _content_stream(page_lines, page_number, len(pages))
        stream_id = add_object(
            b"<< /Length "
            + str(len(content)).encode("ascii")
            + b" >>\nstream\n"
            + content
            + b"\nendstream"
        )
        page_id = add_object(
            f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {PAGE_WIDTH} {PAGE_HEIGHT}] "
            f"/Resources << /Font << /F1 {regular_font_id} 0 R /F2 {bold_font_id} 0 R >> >> "
            f"/Contents {stream_id} 0 R >>".encode("ascii")
        )
        page_ids.append(page_id)
    objects[catalog_id] = f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode("ascii")
    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects[pages_id] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("ascii")

    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for object_id, value in enumerate(objects[1:], start=1):
        offsets.append(len(output))
        output.extend(f"{object_id} 0 obj\n".encode("ascii"))
        output.extend(value)
        output.extend(b"\nendobj\n")
    xref_offset = len(output)
    output.extend(f"xref\n0 {len(objects)}\n".encode("ascii"))
    output.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        output.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    output.extend(
        f"trailer\n<< /Size {len(objects)} /Root {catalog_id} 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode(
            "ascii"
        )
    )
    return bytes(output)

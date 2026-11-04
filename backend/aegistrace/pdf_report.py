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

    draw("AegisTrace - Recorded Evidence Report", 788, 16, True, "0.08 0.20 0.32")
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
                f"Source observations referenced: {snapshot.get('observation_reference_count', sum(len(value.get('observation_ids', [])) for value in revisions))}",
                2,
            ),
        ]
    )
    for limitation in snapshot.get("limitations", []):
        for wrapped in _wrap(f"Limitation: {limitation}"):
            lines.append((wrapped, 2))

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

    lines.append(("Source observations", 0))
    if not observations:
        lines.append(("No normalized observations were present in the selected revisions.", 2))
    for index, observation in enumerate(observations, start=1):
        asset = assets.get(str(observation.get("asset_id")), "unmapped asset")
        title = observation.get("title", "Untitled source observation")
        for line_number, wrapped in enumerate(_wrap(f"Observation {index}: {title}")):
            lines.append((wrapped, 1 if line_number == 0 else 2))
        for label, value in [
            ("Asset", asset),
            ("Source key", observation.get("source_key", "unknown")),
            ("Source severity", observation.get("source_severity") or "not supplied"),
            (
                "CVSS",
                observation.get("cvss_score")
                if observation.get("cvss_score") is not None
                else "not supplied",
            ),
            ("CVE", observation.get("cve") or "not supplied"),
            ("CWE", observation.get("cwe") or "not supplied"),
            ("Validation", observation.get("validation_state", "unknown")),
            ("Evidence ID", observation.get("evidence_id", "unknown")),
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
        if current_page and current_height + block_height > BODY_HEIGHT_PER_PAGE:
            pages.append(current_page)
            current_page = []
            current_height = 0
        current_page.extend(block)
        current_height += block_height
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

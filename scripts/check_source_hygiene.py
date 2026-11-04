"""Check tracked public source for excluded runtime data and recognizable credentials."""

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    result = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True)
    paths = [name for name in result.stdout.decode().split("\0") if name]
    findings: list[str] = []
    patterns = [
        re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
        re.compile(r"AKIA[A-Z0-9]{16}"),
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ]
    for relative in paths:
        if (
            relative == ".env"
            or relative.startswith((".venv/", "data/", "evidence/", "planning/", "tmp/"))
            or "/node_modules/" in relative
        ):
            findings.append(relative + ": runtime/private/generated path is tracked")
            continue
        text = (ROOT / relative).read_text(encoding="utf-8-sig", errors="replace")
        if any(pattern.search(text) for pattern in patterns):
            findings.append(relative + ": recognizable credential material (value not printed)")
    if findings:
        raise SystemExit("\n".join(findings))
    print(
        f"PASS: {len(paths)} tracked paths; no excluded runtime data or recognized credential patterns. This is not an exhaustive secret audit."
    )


if __name__ == "__main__":
    main()

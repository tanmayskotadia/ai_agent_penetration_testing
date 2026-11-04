"""Non-invasive development prerequisite inventory; never starts scanners or reads keys."""

import argparse
import json
import os
import platform
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = {
    "Nmap": ["nmap"],
    "Nessus": ["nessuscli"],
    "Greenbone": ["gvm-cli", "openvas", "gvmd"],
    "Nikto": ["nikto"],
    "OWASP ZAP": ["zaproxy", "zap.sh", "zap.bat"],
    "Burp Suite": ["burpsuite", "burp"],
    "Metasploit": ["msfconsole", "msfrpcd"],
}


def version(command: str) -> str:
    executable = shutil.which(command)
    if executable is None:
        return "not-on-PATH"
    try:
        result = subprocess.run(
            [executable, "--version"], capture_output=True, text=True, timeout=10
        )
        return (
            (result.stdout or result.stderr).strip().splitlines()[0]
            if result.returncode == 0
            else "version-unverified"
        )
    except (OSError, subprocess.TimeoutExpired, IndexError):
        return "version-unverified"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    free = round(shutil.disk_usage(ROOT).free / 1024**3, 1)
    result = {
        "status": "inventory-collected-not-a-capability-certification",
        "platform": platform.system(),
        "python": platform.python_version(),
        "logical_processors": os.cpu_count(),
        "workspace_drive_free_gib": free,
        "core_versions": {name: version(name) for name in ["uv", "node", "npm", "git"]},
        "docker_executable_on_path": bool(shutil.which("docker")),
        "docker_daemon_checked": False,
        "scanner_executable_on_path": {
            name: any(shutil.which(candidate) for candidate in candidates)
            for name, candidates in TOOLS.items()
        },
        "secret_values_read": False,
        "target_traffic_sent": False,
        "notes": [
            "PATH absence does not establish machine-wide absence or license entitlement.",
            "Organizer authorization is separately required for live testing.",
            "Low free space should be resolved before heavy image/feed/model downloads."
            if free < 20
            else "Verify workload-specific storage/retention needs before heavy setup.",
        ],
    }
    if args.output:
        path = args.output.resolve()
        if not path.is_relative_to(ROOT):
            raise SystemExit("Output must remain inside the workspace")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

"""Explicit live-provider acceptance over synthetic normalized fixtures, never real targets.

Run with dev dependencies. Reads a private env file at runtime; never prints secrets,
prompts, provider raw responses, or source artifacts. Uses a disposable SQLite database.
"""

import argparse
import hashlib
import json
import secrets
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "backend"), str(ROOT / "workers"), str(ROOT / "tests")]

from aegistrace.api import create_app  # noqa: E402
from aegistrace.capabilities import DEFAULT_REGISTRY  # noqa: E402
from aegistrace.model_provider import SYSTEM_PROMPT  # noqa: E402
from aegistrace.schema_v1 import metadata  # noqa: E402
from aegistrace.settings import Settings  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from test_adaptive_planner import prepare_case  # noqa: E402
from test_nmap import XML  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--approve-synthetic-data", action="store_true")
    parser.add_argument("--interval-seconds", type=int, default=0)
    args = parser.parse_args()
    if not args.approve_synthetic_data:
        parser.error("Explicit --approve-synthetic-data is required for external Groq calls")
    if not 0 <= args.interval_seconds <= 60:
        parser.error("interval must be between 0 and 60 seconds")
    if not args.env_file.is_file():
        parser.error(
            "Private env file not present; do not paste credentials into command arguments"
        )
    results = []
    with tempfile.TemporaryDirectory(prefix="aegistrace-test-only-groq-") as temporary:
        config = Settings(
            _env_file=args.env_file,
            app_secret=secrets.token_hex(32),
            evidence_key=secrets.token_hex(32),
            database_url=f"sqlite:///{Path(temporary) / 'test.db'}",
            environment="test",
            adaptive_planner_enabled=True,
            model_data_policy_reference="TEST-ONLY-policy",
            allow_operator_tokens=True,
        )
        if not config.groq_api_key or not config.groq_model:
            parser.error("GROQ_API_KEY and GROQ_MODEL must be configured privately")
        app = create_app(config)
        metadata.create_all(app.state.engine)
        try:
            with TestClient(app) as client:
                for name, raw, expected in [
                    ("http-missing-web-evidence", XML, "select"),
                    (
                        "ssh-no-web-evidence",
                        XML.replace(b'name="http"', b'name="ssh"'),
                        "request-review",
                    ),
                    (
                        "conflicting-port-states",
                        XML.replace(b'portid="81"', b'portid="80"'),
                        "request-review",
                    ),
                    ("unavailable-web-imports", XML, "request-review"),
                ]:
                    if results and args.interval_seconds:
                        time.sleep(args.interval_seconds)
                    if name == "unavailable-web-imports":
                        DEFAULT_REGISTRY.revoke(
                            "OWASP ZAP", "TEST ONLY isolated acceptance scenario"
                        )
                        DEFAULT_REGISTRY.revoke("Nikto", "TEST ONLY isolated acceptance scenario")
                    _, _, base, headers, body = prepare_case((client, config), raw=raw)
                    response = client.post(base + "/reasoning/replan", json=body, headers=headers())
                    if response.status_code != 201:
                        results.append(
                            {"case": name, "passed": False, "http_status": response.status_code}
                        )
                        continue
                    plan = response.json()
                    proposal = plan["request"]["proposal"]
                    decision = proposal["decision"]
                    trace = proposal["provider"]
                    duplicate = (
                        client.post(
                            base + "/reasoning/replan",
                            json=body | {"conversation_id": str(uuid4())},
                            headers=headers(),
                        )
                        if decision
                        else None
                    )
                    suppressed = bool(
                        duplicate is not None
                        and duplicate.status_code == 201
                        and "unchanged-evidence" in duplicate.json().get("reason", "")
                    )
                    passed = bool(
                        decision
                        and (
                            decision["decision"] == expected
                            or expected == "request-review"
                            and decision["decision"] == "stop"
                        )
                        and trace["model_called"]
                        and trace.get("provider_source") == "live-provider"
                        and suppressed
                    )
                    results.append(
                        {
                            "case": name,
                            "passed": passed,
                            "expected": expected,
                            "decision": decision,
                            "provider": trace,
                            "plan_id": plan["id"],
                            "context_sha256": plan["request"]["context_sha256"],
                            "context": plan["request"]["context"],
                            "validated_plan_steps": proposal["steps"],
                            "synthetic_artifact_sha256": hashlib.sha256(raw).hexdigest(),
                            "blockers": proposal["blockers"],
                            "duplicate_suppressed": suppressed,
                            "label": "synthetic fixture; provider trace reports actual model status; no scanner or target contacted",
                        }
                    )
        finally:
            app.state.engine.dispose()
    report = {
        "schema_version": "1.0",
        "issue": 52,
        "executed_at": datetime.now(UTC).isoformat(),
        "prompt_sha256": hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest(),
        "source_sha256": {
            name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
            for name in [
                "backend/aegistrace/adaptive_planner.py",
                "backend/aegistrace/model_provider.py",
            ]
        },
        "acceptance": "passed" if results and all(row["passed"] for row in results) else "failed",
        "cases": results,
        "limitations": [
            "Synthetic inputs are not genuine scanner evidence or T30 acceptance.",
            "Human rationale review remains required; schema and policy checks do not prove reasoning quality.",
        ],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(
        json.dumps(
            {"acceptance": report["acceptance"], "cases": len(results), "output": str(args.output)}
        )
    )
    if report["acceptance"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()

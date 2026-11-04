"""Export the same truthful capability registry and worker contracts consumed by the app."""

import argparse
import json
from pathlib import Path

from aegistrace.capabilities import capability_snapshot
from aegistrace_workers.adapters.base import (
    AdapterPlan,
    CollectedArtifact,
    ExecutionGrant,
    HealthResult,
    PlanValidation,
    RunStatus,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    snapshot = capability_snapshot()
    outputs = {
        root / "config/integration-matrix.json": json.dumps(
            {
                "schema_version": "1.0",
                "verified_working_integrations": sum(
                    tool["mode"] in {"live", "import-only"} for tool in snapshot
                ),
                "tools": snapshot,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    }
    for contract in [
        AdapterPlan,
        CollectedArtifact,
        ExecutionGrant,
        HealthResult,
        PlanValidation,
        RunStatus,
    ]:
        outputs[root / "schemas/adapters" / (contract.__name__ + ".json")] = (
            json.dumps(contract.model_json_schema(), indent=2, sort_keys=True) + "\n"
        )
    for path, value in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        if args.check:
            if not path.is_file() or path.read_text(encoding="utf-8") != value:
                raise SystemExit(f"Capability contract drift: {path.name}")
        else:
            path.write_text(value, encoding="utf-8")


if __name__ == "__main__":
    main()

"""Unit checks for fixed, bounded scanner plans; no scanner or target is run here."""

import hashlib
import json

import pytest
from aegistrace.policy import Destination, PolicyError
from aegistrace_workers.adapters.web_scanners import (
    PinnedBinary,
    execute_json_artifact,
    nikto_arguments,
    serialize_zap_plan,
    validate_har_input,
    validate_json_artifact,
    zap_automation_plan,
)
from aegistrace_workers.process_control import ProcessOutcome


@pytest.fixture
def pinned_binary(tmp_path):
    path = tmp_path / "scanner"
    path.write_bytes(b"test launcher identity")
    return PinnedBinary(path, hashlib.sha256(path.read_bytes()).hexdigest())


@pytest.fixture
def destination():
    return Destination(
        protocol="https",
        host="app.example.test",
        port=443,
        path="/app",
        pinned_addresses=("203.0.113.10",),
    )


def test_nikto_arguments_are_fixed_and_bounded(pinned_binary, destination, tmp_path):
    output = tmp_path / "nikto.json"
    argv = nikto_arguments(
        pinned_binary,
        destination,
        output,
        "http://127.0.0.1:19001",
        runtime_seconds=60,
        requests_per_second=2,
    )
    assert argv[0] == str(pinned_binary.path)
    assert argv[argv.index("-host") + 1] == "https://app.example.test/app"
    assert argv[argv.index("-useproxy") + 1] == "http://127.0.0.1:19001"
    assert argv[argv.index("-maxtime") + 1] == "60s"
    assert argv[argv.index("-Pause") + 1] == "0.5"
    assert argv[argv.index("-Tuning") + 1] == "123b"
    assert "-followredirects" not in argv
    assert argv[-1] == str(output)


@pytest.mark.parametrize("kwargs", [{"excluded_paths": ("/admin",)}, {"runtime_seconds": 301}])
def test_nikto_refuses_unenforceable_scope_and_unbounded_runtime(
    pinned_binary, destination, tmp_path, kwargs
):
    options = {"runtime_seconds": 60, "requests_per_second": 1}
    options.update(kwargs)
    with pytest.raises(PolicyError):
        nikto_arguments(
            pinned_binary,
            destination,
            tmp_path / "nikto.json",
            "http://127.0.0.1:19001",
            **options,
        )


def test_passive_zap_never_replays_imported_har(destination, tmp_path):
    plan = zap_automation_plan(
        destination,
        "passive-web",
        report_directory=tmp_path,
        included_paths=("/app",),
        excluded_paths=("/app/private",),
        runtime_seconds=60,
        requests_per_second=1,
        har_filename="capture.har",
    )
    assert plan["jobs"][0]["type"] == "import"
    assert plan["jobs"][0]["parameters"]["sendRequests"] is False
    assert plan["env"]["configs"]["pscans.scanOnlyInScope"] == "true"
    assert plan["env"]["contexts"][0]["excludePaths"]


def test_passive_har_requires_exact_approved_origin_and_paths(destination):
    har = json.dumps(
        {
            "log": {
                "entries": [
                    {"request": {"url": "https://app.example.test/app/home"}},
                    {"request": {"url": "https://app.example.test/app/public/item"}},
                ]
            }
        }
    ).encode()
    validate_har_input(har, destination, ("/app",), ("/app/private",))
    for rejected in (
        b'{"log":{"entries":[{"request":{"url":"https://evil.example/app/"}}]}}',
        b'{"log":{"entries":[{"request":{"url":"https://app.example.test/app/private/"}}]}}',
        b'{"log":{"entries":[{"request":{"url":"https://app.example.test/app/../admin"}}]}}',
    ):
        with pytest.raises(PolicyError):
            validate_har_input(rejected, destination, ("/app",), ("/app/private",))


def test_active_zap_requires_loopback_proxy_and_action_scope(destination, tmp_path):
    with pytest.raises(PolicyError, match="proxy"):
        zap_automation_plan(
            destination,
            "active-web",
            report_directory=tmp_path,
            included_paths=("/app",),
            excluded_paths=(),
            runtime_seconds=60,
            requests_per_second=1,
        )
    plan = zap_automation_plan(
        destination,
        "active-web",
        report_directory=tmp_path,
        included_paths=("/app",),
        excluded_paths=("/app/admin",),
        runtime_seconds=60,
        requests_per_second=2,
        proxy_url="http://127.0.0.1:19001",
    )
    scan = plan["jobs"][0]["parameters"]
    assert scan["threadPerHost"] == 1
    assert scan["delayInMs"] == 500
    assert scan["defaultStrength"] == "Low"
    assert scan["url"] == "https://app.example.test/app"
    assert plan["env"]["proxy"] == {"hostname": "127.0.0.1", "port": 19001}


def test_zap_plan_serialization_and_artifact_size_are_bounded(destination, tmp_path):
    plan = zap_automation_plan(
        destination,
        "passive-web",
        report_directory=tmp_path,
        included_paths=("/app",),
        excluded_paths=(),
        runtime_seconds=60,
        requests_per_second=1,
        har_filename="capture.har",
    )
    path = tmp_path / "plan.yaml"
    serialize_zap_plan(plan, path)
    assert "sendRequests: false" in path.read_text(encoding="utf-8")
    validate_json_artifact(b'{"alerts": []}')
    with pytest.raises(PolicyError):
        validate_json_artifact(b"not json")
    with pytest.raises(PolicyError):
        validate_json_artifact(b"".join([b" "] * (2 * 1024 * 1024 + 1)))


def test_executor_collects_only_valid_artifact_after_success(tmp_path):
    artifact = tmp_path / "nikto.json"

    def executor(argv, runtime, cancelled):
        assert argv == ("pinned-scanner", "--fixed")
        assert runtime == 20 and cancelled() is False
        artifact.write_text(json.dumps([]), encoding="utf-8")
        return ProcessOutcome("finished", "finished", 0.1, 0, True)

    raw, outcome = execute_json_artifact(
        ("pinned-scanner", "--fixed"), artifact, 20, lambda: False, executor=executor
    )
    assert raw == b"[]"
    assert outcome.exit_code == 0


def test_executor_rejects_nonzero_or_missing_artifact(tmp_path):
    artifact = tmp_path / "zap.json"

    def failed(*_):
        return ProcessOutcome("finished", "finished", 0.1, 2, True)

    with pytest.raises(PolicyError):
        execute_json_artifact(("pinned-scanner",), artifact, 20, lambda: False, executor=failed)

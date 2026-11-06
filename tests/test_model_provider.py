"""Transport contract doubles: no credentials or network requests leave these tests."""

import io
import json
import secrets

import pytest
from aegistrace import model_provider
from aegistrace.model_provider import GroqProvider, ProviderFailure
from aegistrace.settings import Settings
from pydantic import SecretStr


def config():
    return Settings(
        _env_file=None,
        app_secret=secrets.token_hex(32),
        database_url="sqlite:///:memory:",
        groq_api_key=SecretStr("TEST_ONLY_GROQ_CREDENTIAL"),
        groq_model="test-only-model",
    )


@pytest.mark.parametrize(
    "mode",
    [
        "success",
        "redirect",
        "rate-limit",
        "oversize",
        "truncated",
        "tool-call",
        "timeout",
        "mismatched-model",
    ],
)
def test_groq_transport_is_fixed_bounded_text_only_and_failure_safe(monkeypatch, mode):
    requests = []
    closed = []
    envelope = {
        "id": "test-only-provider-id",
        "model": "test-only-model",
        "choices": [{"finish_reason": "stop", "message": {"content": '{"decision":"stop"}'}}],
        "usage": {"total_tokens": 10},
    }
    if mode == "oversize":
        envelope["choices"][0]["message"]["content"] = "x" * 70000
    if mode == "truncated":
        envelope["choices"][0]["finish_reason"] = "length"
    if mode == "tool-call":
        envelope["choices"][0]["message"]["tool_calls"] = [{"function": "shell"}]
    if mode == "mismatched-model":
        envelope["model"] = "other-model"

    class Response(io.BytesIO):
        status = 302 if mode == "redirect" else 429 if mode == "rate-limit" else 200

    class Connection:
        sock = None

        def __init__(self, host, **kwargs):
            assert host == "api.groq.com" and kwargs["timeout"] <= 60
            assert kwargs["context"].check_hostname

        def request(self, method, path, body, headers):
            if mode == "timeout":
                raise TimeoutError("TEST_ONLY_GROQ_CREDENTIAL must not escape")
            requests.append(json.loads(body))
            assert method == "POST" and path == "/openai/v1/chat/completions"

        def getresponse(self):
            return Response(json.dumps(envelope).encode())

        def close(self):
            closed.append(True)

    monkeypatch.setattr(model_provider.http.client, "HTTPSConnection", Connection)
    if mode == "success":
        reply = GroqProvider(config()).generate({"observations": []}, {})
        assert reply.content == '{"decision":"stop"}'
        assert len(reply.response_id) == 64 and reply.source == "live-provider"
    else:
        with pytest.raises(ProviderFailure) as error:
            GroqProvider(config()).generate({"observations": []}, {})
        assert "TEST_ONLY_GROQ_CREDENTIAL" not in str(error.value)
    assert closed == [True] and len(requests) <= 1
    if requests:
        assert "tools" not in requests[0] and requests[0]["stream"] is False


def test_compound_models_are_rejected_without_invocation():
    with pytest.raises(ValueError, match="text-only"):
        config().model_validate(config().model_dump() | {"groq_model": "groq/compound"})

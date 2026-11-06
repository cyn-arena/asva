"""Light coverage for llm/llm_client.py — a thin wrapper around the endpoint's
OpenAI-compatible chat API (streamed by default). Only the request shape, stream assembly,
retries and error handling are asserted here; no real LLM endpoint is called."""

from __future__ import annotations

import json
import json as _json

import httpx
import pytest

from llm import llm_client

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _no_reasoning_overrides(monkeypatch):
    """A developer's .env may set these; the request-shape tests assume they are unset.
    Retries happen without waiting so retried errors don't slow the suite down."""
    monkeypatch.delenv("ASVA_LLM_REASONING_EFFORT", raising=False)
    monkeypatch.delenv("ASVA_LLM_EXTRA_BODY", raising=False)
    monkeypatch.delenv("OLLAMA_STREAM", raising=False)
    monkeypatch.setenv("OLLAMA_RETRY_DELAY", "0")


def _sse(*deltas: dict, finish_reason: str | None = "stop", done: bool = True) -> httpx.Response:
    """A streamed chat-completions reply: one `data:` event per delta, as the gateway sends."""
    events = [{"choices": [{"delta": delta, "finish_reason": None}]} for delta in deltas]
    if finish_reason:
        events.append({"choices": [{"delta": {}, "finish_reason": finish_reason}]})
    body = "".join(f"data: {json.dumps(event)}\n\n" for event in events) + ("data: [DONE]\n\n" if done else "")
    return httpx.Response(200, text=body, headers={"content-type": "text/event-stream"})


def _use_fake_backend(monkeypatch, handler):
    """Route both the shared client (non-streamed) and httpx.stream (streamed) to `handler`."""
    fake = httpx.Client(base_url="http://llm.test", transport=httpx.MockTransport(handler))
    monkeypatch.setattr(llm_client, "client", fake)
    monkeypatch.setattr(llm_client.httpx, "stream",
                        lambda method, url, **kwargs: fake.stream(method, url, **kwargs))


def test_call_llm_sends_expected_request_shape_and_returns_response_text(monkeypatch):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["path"] = request.url.path
        captured["body"] = json.loads(request.content)
        return _sse({"role": "assistant", "content": ""}, {"content": "the generated"}, {"content": " fix"})

    _use_fake_backend(monkeypatch, handler)
    monkeypatch.setenv("OLLAMA_MODEL", "test-model-x")
    monkeypatch.delenv("ASVA_LLM_NUM_PREDICT", raising=False)

    result = llm_client.call_llm("fix this file please")

    assert result == "the generated fix"
    assert captured == {
        "path": "/v1/chat/completions",
        "body": {
            "model": "test-model-x",
            "messages": [{"role": "user", "content": "fix this file please"}],
            "stream": True,
            "stream_options": {"include_usage": True},
        },
    }


def test_call_llm_sends_the_configured_token_limit(monkeypatch):
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        return _sse({"content": "ok"})

    _use_fake_backend(monkeypatch, handler)
    monkeypatch.setenv("ASVA_LLM_NUM_PREDICT", "8192")

    llm_client.call_llm("anything")

    assert captured["max_tokens"] == 8192


def test_call_llm_flags_an_answer_cut_off_at_the_token_limit(monkeypatch):
    # agent_loop discards a cut-off single-file reply (half a file can still parse, e.g.
    # YAML) and keeps only the complete files of a cut-off multi-file reply.
    _use_fake_backend(monkeypatch, lambda request: _sse({"content": "services:\n  web:\n"}, finish_reason="length"))

    llm_client.call_llm("anything")
    assert llm_client.last_call["finish_reason"] == "length"


def test_call_llm_ignores_the_models_streamed_reasoning(monkeypatch):
    _use_fake_backend(monkeypatch, lambda request: _sse(
        {"content": "", "reasoning": "The user wants a fix..."}, {"content": "fixed"}, {"content": "", "reasoning": "done"}))

    assert llm_client.call_llm("anything") == "fixed"


@pytest.mark.parametrize("status", [400, 401, 404, 429, 503])
def test_call_llm_raises_llm_unavailable_on_http_errors(monkeypatch, status):
    _use_fake_backend(monkeypatch, lambda request: httpx.Response(status, json={"detail": "nope"}))

    with pytest.raises(llm_client.LLMUnavailableError, match="Ollama call failed"):
        llm_client.call_llm("anything")


@pytest.mark.parametrize("body", [
    {"error": {"message": "input exceeds context limit", "type": "invalid_request"}},
    {"detail": "input exceeds context limit"},
    {"message": "input exceeds context limit"},
])
def test_call_llm_reports_gateway_error_without_echoing_payload(monkeypatch, body):
    body["request"] = {"messages": "private source"}
    _use_fake_backend(monkeypatch, lambda request: httpx.Response(400, json=body))

    with pytest.raises(llm_client.LLMUnavailableError) as error:
        llm_client.call_llm("private source")

    assert "HTTP 400: input exceeds context limit" in str(error.value)
    assert "private source" not in str(error.value)
    assert "invalid_request" not in str(error.value)


def test_call_llm_redacts_credentials_and_echoed_prompt(monkeypatch):
    monkeypatch.setenv("OLLAMA_API_KEY", "private-api-key")
    _use_fake_backend(monkeypatch, lambda request: httpx.Response(400, json={
        "error": {"message": "Rejected private-api-key Bearer other-secret; fix\\nsource"}
    }))

    with pytest.raises(llm_client.LLMUnavailableError) as error:
        llm_client.call_llm("fix\nsource")

    message = str(error.value)
    assert "private-api-key" not in message
    assert "other-secret" not in message
    assert "source" not in message
    assert "[redacted]" in message


def test_call_llm_bounds_plain_text_error_and_keeps_it_on_one_line(monkeypatch):
    _use_fake_backend(monkeypatch, lambda request: httpx.Response(
        400, text="request too large\n" + "x" * 20000))

    with pytest.raises(llm_client.LLMUnavailableError) as error:
        llm_client.call_llm("anything")

    message = str(error.value)
    assert "request too large" in message
    assert "[truncated]" in message
    assert "\n" not in message
    assert len(message) < 600


def test_call_llm_preserves_http_error_if_response_body_fails(monkeypatch):
    class BrokenBody(httpx.SyncByteStream):
        def __iter__(self):
            raise httpx.ReadError("body unavailable")

    _use_fake_backend(monkeypatch, lambda request: httpx.Response(400, stream=BrokenBody()))

    with pytest.raises(llm_client.LLMUnavailableError, match="HTTP 400: Error response could not be read"):
        llm_client.call_llm("anything")


def test_call_llm_raises_llm_unavailable_on_connection_failure(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused")

    _use_fake_backend(monkeypatch, handler)

    with pytest.raises(llm_client.LLMUnavailableError, match="Ollama call failed"):
        llm_client.call_llm("anything")


def test_call_llm_treats_a_cut_off_stream_as_a_failure_not_a_short_file(monkeypatch):
    _use_fake_backend(monkeypatch, lambda request: _sse({"content": "half a fi"}, finish_reason=None, done=False))

    with pytest.raises(llm_client.LLMUnavailableError, match="ended before the model finished"):
        llm_client.call_llm("anything")


def test_call_llm_returns_empty_string_when_the_model_sends_no_content(monkeypatch):
    _use_fake_backend(monkeypatch, lambda request: _sse({"role": "assistant", "content": None}))

    assert llm_client.call_llm("anything") == ""

def test_call_llm_sends_expected_request_shape_without_streaming(monkeypatch):
    captured = {}

    def fake_post(url, json):
        captured["url"] = url
        captured["json"] = json
        return httpx.Response(200, json={"choices": [{"message": {"content": "the generated fix"}}]})

    monkeypatch.setattr(llm_client.client, "post", fake_post)
    monkeypatch.setenv("OLLAMA_STREAM", "0")
    monkeypatch.setenv("OLLAMA_MODEL", "test-model-x")
    monkeypatch.delenv("ASVA_LLM_NUM_PREDICT", raising=False)

    result = llm_client.call_llm("fix this file please")

    assert result == "the generated fix"
    assert captured == {
        "url": "/v1/chat/completions",
        "json": {
            "model": "test-model-x",
            "messages": [{"role": "user", "content": "fix this file please"}],
            "stream": False,
        },
    }


def test_call_llm_passes_num_predict_as_max_tokens(monkeypatch):
    captured = {}

    def fake_post(url, json):
        captured["json"] = json
        return httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})

    monkeypatch.setattr(llm_client.client, "post", fake_post)
    monkeypatch.setenv("OLLAMA_STREAM", "0")
    monkeypatch.setenv("ASVA_LLM_NUM_PREDICT", "8192")

    llm_client.call_llm("hi")

    assert captured["json"]["max_tokens"] == 8192


def test_call_llm_raises_llm_unavailable_on_http_error(monkeypatch):
    def fake_post(url, json):
        return httpx.Response(401, json={"detail": "Missing API key"})

    monkeypatch.setattr(llm_client.client, "post", fake_post)
    monkeypatch.setenv("OLLAMA_STREAM", "0")

    with pytest.raises(llm_client.LLMUnavailableError, match=r"HTTP 401: Missing API key"):
        llm_client.call_llm("hi")


# --------------------------------------------------------------------------------------
# Streamed replies (the default)
# --------------------------------------------------------------------------------------


class _FakeStream:
    """Stands in for httpx.stream(...)'s response context manager."""

    def __init__(self, status=200, events=None, json_body=None, text=""):
        self.status_code = status
        self._events = events
        self._json = json_body
        self.text = text
        ctype = "text/event-stream" if events is not None else "application/json"
        self.headers = {"content-type": ctype}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self):
        return _json.dumps(self._json).encode() if self._json is not None else self.text.encode()

    def iter_lines(self):
        for e in self._events:
            yield e if isinstance(e, str) else "data: " + _json.dumps(e)
            yield ""


def _delta(text=None, finish=None):
    choice = {"delta": {"content": text} if text else {}}
    if finish:
        choice["finish_reason"] = finish
    return {"choices": [choice]}


def _stream_of(*texts, finish="stop"):
    return [_delta(t) for t in texts] + [_delta(finish=finish), "data: [DONE]"]


@pytest.fixture
def openai_env(monkeypatch):
    monkeypatch.delenv("ASVA_LLM_NUM_PREDICT", raising=False)
    monkeypatch.setenv("OLLAMA_HOST", "https://llm.example.test/")
    monkeypatch.setenv("OLLAMA_API_KEY", "secret-key")
    monkeypatch.setenv("OLLAMA_MODEL", "glm-test")
    monkeypatch.setenv("OLLAMA_RETRY_DELAY", "0")
    monkeypatch.setenv("OLLAMA_RETRIES", "3")


def _serve(monkeypatch, *responses):
    """Each call to httpx.stream returns the next response (or raises it)."""
    calls = []
    queue = list(responses)

    def fake_stream(method, url, headers, json, timeout):
        calls.append({"method": method, "url": url, "headers": headers, "json": json})
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(llm_client.httpx, "stream", fake_stream)
    return calls


def test_streams_chat_completion_and_assembles_the_reply(openai_env, monkeypatch):
    calls = _serve(monkeypatch, _FakeStream(events=_stream_of("the generated ", "fix")))

    assert llm_client.call_llm("fix this file please") == "the generated fix"
    assert calls[0]["url"] == "https://llm.example.test/v1/chat/completions"
    assert calls[0]["headers"]["Authorization"] == "Bearer secret-key"
    assert calls[0]["json"] == {
        "model": "glm-test",
        "messages": [{"role": "user", "content": "fix this file please"}],
        "stream": True,
        "stream_options": {"include_usage": True},
    }
    assert llm_client.last_call["finish_reason"] == "stop"


def test_plain_json_reply_is_accepted_too(openai_env, monkeypatch):
    body = {"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": 12, "completion_tokens": 1}}
    _serve(monkeypatch, _FakeStream(json_body=body))
    assert llm_client.call_llm("p") == "ok"
    assert llm_client.last_call == {"finish_reason": "stop", "prompt_tokens": 12,
                                    "completion_tokens": 1, "reasoning_chars": 0,
                                    "answer_chars": 2}


def test_records_a_cut_off_reply(openai_env, monkeypatch):
    _serve(monkeypatch, _FakeStream(events=_stream_of("partial", finish="length")))
    llm_client.call_llm("long prompt")
    assert llm_client.last_call["finish_reason"] == "length"


def test_strips_inline_thinking(openai_env, monkeypatch):
    _serve(monkeypatch, _FakeStream(events=_stream_of("<think>\nlet me reason\n</think>\n", "const x = 1;")))
    assert llm_client.call_llm("p") == "const x = 1;"


CLOUDFLARE_524 = ("<!DOCTYPE html><html><head><title>gateway.test | 524: A timeout occurred"
                  "</title></head><body>...</body></html>")


def test_gateway_timeout_is_retried_then_succeeds(openai_env, monkeypatch, capsys):
    calls = _serve(monkeypatch,
                   _FakeStream(status=524, text=CLOUDFLARE_524),
                   _FakeStream(events=_stream_of("fixed")))
    assert llm_client.call_llm("p") == "fixed"
    assert len(calls) == 2
    assert "HTTP 524: gateway.test | 524: A timeout occurred" in capsys.readouterr().out


def test_stream_that_ends_early_is_retried(openai_env, monkeypatch):
    calls = _serve(monkeypatch,
                   _FakeStream(events=[_delta("half a fi")]),          # no finish, no [DONE]
                   _FakeStream(events=_stream_of("whole fix")))
    assert llm_client.call_llm("p") == "whole fix"
    assert len(calls) == 2


def test_persistent_gateway_timeout_gives_up_with_a_short_message(openai_env, monkeypatch):
    calls = _serve(monkeypatch, *[_FakeStream(status=524, text=CLOUDFLARE_524)] * 3)
    with pytest.raises(llm_client.LLMUnavailableError) as err:
        llm_client.call_llm("p")
    assert len(calls) == 3
    assert "524: A timeout occurred" in str(err.value) and "<html" not in str(err.value)
    assert "after 3 attempts" in str(err.value)


def test_not_found_is_not_retried(openai_env, monkeypatch):
    calls = _serve(monkeypatch, _FakeStream(status=404, text='{"detail":"Not Found"}'))
    with pytest.raises(llm_client.LLMUnavailableError) as err:
        llm_client.call_llm("p")
    assert len(calls) == 1 and "404" in str(err.value)


def test_connection_errors_are_retried(openai_env, monkeypatch):
    calls = _serve(monkeypatch, httpx.ConnectError("refused"), httpx.ConnectError("refused"),
                   _FakeStream(events=_stream_of("ok")))
    assert llm_client.call_llm("p") == "ok"
    assert len(calls) == 3


# --------------------------------------------------------------------------------------
# Non-streamed (OLLAMA_STREAM=0): cut-off detection and retries
# --------------------------------------------------------------------------------------


@pytest.fixture
def post_env(monkeypatch):
    monkeypatch.setenv("OLLAMA_STREAM", "0")
    monkeypatch.delenv("ASVA_LLM_NUM_PREDICT", raising=False)
    monkeypatch.setenv("OLLAMA_RETRY_DELAY", "0")
    monkeypatch.setenv("OLLAMA_RETRIES", "3")


def _post_queue(monkeypatch, *responses):
    calls = []
    queue = list(responses)

    def fake_post(url, json):
        calls.append(json)
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(llm_client.client, "post", fake_post)
    return calls


def _ok(content, finish="stop", usage=None):
    body = {"choices": [{"message": {"content": content}, "finish_reason": finish}]}
    if usage:
        body["usage"] = usage
    return httpx.Response(200, json=body)


def test_records_finish_reason_and_usage(post_env, monkeypatch):
    _post_queue(monkeypatch, _ok("ok", usage={"prompt_tokens": 12, "completion_tokens": 1}))
    assert llm_client.call_llm("p") == "ok"
    assert llm_client.last_call == {"finish_reason": "stop", "prompt_tokens": 12,
                                    "completion_tokens": 1, "reasoning_chars": 0,
                                    "answer_chars": 2}


def test_records_a_cut_off_non_streamed_reply(post_env, monkeypatch):
    _post_queue(monkeypatch, _ok("partial", finish="length"))
    llm_client.call_llm("p")
    assert llm_client.last_call["finish_reason"] == "length"


def test_non_streamed_gateway_error_is_retried(post_env, monkeypatch):
    calls = _post_queue(monkeypatch, httpx.Response(524, text=CLOUDFLARE_524), _ok("fixed"))
    assert llm_client.call_llm("p") == "fixed"
    assert len(calls) == 2


def test_non_streamed_strips_inline_thinking(post_env, monkeypatch):
    _post_queue(monkeypatch, _ok("<think>hmm</think>\nconst y = 2;"))
    assert llm_client.call_llm("p") == "const y = 2;"


def test_context_window_reads_env(monkeypatch):
    monkeypatch.setenv("OLLAMA_NUM_CTX", "32768")
    assert llm_client.context_window() == 32768
    monkeypatch.setenv("OLLAMA_NUM_CTX", "")
    assert llm_client.context_window() is None


# --------------------------------------------------------------------------------------
# Reasoning ("thinking") models
# --------------------------------------------------------------------------------------


def test_hidden_reasoning_is_measured_when_streamed(openai_env, monkeypatch):
    events = [{"choices": [{"delta": {"reasoning_content": "x" * 500}}]},
              {"choices": [{"delta": {"reasoning": "y" * 100}}]},
              _delta(finish="length"), "data: [DONE]"]
    _serve(monkeypatch, _FakeStream(events=events))
    assert llm_client.call_llm("p") == ""
    assert llm_client.last_call["reasoning_chars"] == 600
    assert llm_client.last_call["answer_chars"] == 0
    assert llm_client.last_call["finish_reason"] == "length"


def test_hidden_reasoning_is_measured_without_streaming(post_env, monkeypatch):
    body = {"choices": [{"message": {"content": "", "reasoning": "z" * 40}, "finish_reason": "length"}]}
    _post_queue(monkeypatch, httpx.Response(200, json=body))
    llm_client.call_llm("p")
    assert llm_client.last_call["reasoning_chars"] == 40


def test_reasoning_effort_and_extra_body_reach_the_request(post_env, monkeypatch):
    calls = _post_queue(monkeypatch, _ok("ok"))
    monkeypatch.setenv("ASVA_LLM_REASONING_EFFORT", "none")
    monkeypatch.setenv("ASVA_LLM_EXTRA_BODY", '{"think": false}')
    llm_client.call_llm("p")
    assert calls[0]["reasoning_effort"] == "none"
    assert calls[0]["think"] is False


def test_bad_extra_body_is_reported(post_env, monkeypatch):
    monkeypatch.setenv("ASVA_LLM_EXTRA_BODY", "{not json")
    with pytest.raises(llm_client.LLMUnavailableError, match="ASVA_LLM_EXTRA_BODY"):
        llm_client.call_llm("p")

import json
import os
import re
import time

import httpx
from dotenv import load_dotenv

load_dotenv()

# OpenAI-compatible chat endpoint. The team's gateway (OLLAMA_HOST) serves
# only this one; a stock Ollama server serves it too, so OLLAMA_HOST can point at either.
CHAT_COMPLETIONS_PATH = "/v1/chat/completions"
TIMEOUT_SECONDS = 600  # a whole-file fix can take minutes
ERROR_BODY_LIMIT = 8192
ERROR_MESSAGE_LIMIT = 500

client = httpx.Client(
    base_url=os.environ["OLLAMA_HOST"].rstrip("/"),
    headers={"Authorization": f"Bearer {os.environ['OLLAMA_API_KEY']}"},
    timeout=TIMEOUT_SECONDS,
)

# Details of the most recent call (finish reason, token usage), so callers can tell when a
# reply was cut off (ITP2 3.6: a multi-file reply that hits the token limit). Empty until
# the first call.
last_call: dict = {}

_THINK_RE = re.compile(r"^\s*<think>.*?</think>\s*", re.DOTALL)


class LLMUnavailableError(RuntimeError):
    """The LLM backend didn't respond (network failure, auth failure, rate limit,
    exhausted quota, etc.). An outage or exhausted quota fails every subsequent call
    the same way, so callers should treat this as fatal for the whole run rather than
    skipping the one file and moving on."""


def context_window() -> int | None:
    """OLLAMA_NUM_CTX, if set: the context window (tokens) the server uses for the model.
    The OpenAI-compatible endpoint cannot set it per call, so it should match the server's
    setting; the agent uses it to warn when a prompt plus its reply may not fit."""
    value = os.environ.get("OLLAMA_NUM_CTX", "").strip()
    return int(value) if value else None


def _streaming() -> bool:
    """Replies are streamed unless OLLAMA_STREAM=0. The gateway's proxy drops a response
    that stays silent for ~100 s (Cloudflare 524), which a reasoning model can exceed on a
    whole-file fix; a streamed reply keeps data flowing."""
    return os.environ.get("OLLAMA_STREAM", "1").strip().lower() not in {"0", "false", "no"}


# Gateway/server errors worth retrying: rate limit, overload, and Cloudflare's origin
# errors (524 = the server took longer than Cloudflare's ~100s limit to start answering).
_RETRY_STATUS = {429, 500, 502, 503, 504, 520, 521, 522, 523, 524}
_TITLE_RE = re.compile(r"<title>(.*?)</title>", re.IGNORECASE | re.DOTALL)


class _HTTPFailure(Exception):
    """An HTTP error reply. `body` is the first ERROR_BODY_LIMIT characters of the error
    body, or None when it could not be read; call_llm turns it into a redacted summary."""

    def __init__(self, status: int, body: str | None):
        self.status = status
        self.body = body
        super().__init__(f"HTTP {status}")


def _error_detail(body: str | None, prompt: str) -> str:
    """A short, one-line, redacted diagnostic from an error body: the <title> of an HTML
    error page (e.g. Cloudflare's), the message of a JSON error, otherwise the text."""
    if body is None:
        return "Error response could not be read"
    try:
        detail = body
        title = _TITLE_RE.search(detail)
        if title:
            detail = title.group(1)
        else:
            try:
                data = json.loads(detail)
            except ValueError:
                data = None
                if detail.lstrip().startswith(("{", "[")):
                    return "Error response contained unreadable or oversized JSON"
            if isinstance(data, dict):
                detail = data.get("error") or data.get("detail") or data.get("message")
                if isinstance(detail, dict):
                    detail = detail.get("message")
                if not isinstance(detail, str):
                    detail = "No error message provided"
        # Do not log echoed prompts, request payloads or configured credentials.
        for value in (prompt, os.environ.get("OLLAMA_API_KEY"),
                      client.headers.get("Authorization")):
            if value:
                detail = detail.replace(value, "[redacted]")
                detail = detail.replace(json.dumps(value)[1:-1], "[redacted]")
        detail = re.sub(r"(?i)bearer\s+[^\s\"<>]+", "Bearer [redacted]", detail)
        detail = " ".join(detail.split())
        if len(detail) > ERROR_MESSAGE_LIMIT:
            return detail[:ERROR_MESSAGE_LIMIT] + "... [truncated]"
        return detail or "Empty error response"
    except Exception:
        return "Error response could not be read"


def _retries() -> tuple[int, float]:
    return (max(1, int(os.environ.get("OLLAMA_RETRIES", "3"))),
            float(os.environ.get("OLLAMA_RETRY_DELAY", "15")))


def _payload(prompt: str, stream: bool) -> dict:
    payload = {
        "model": os.environ["OLLAMA_MODEL"],
        "messages": [{"role": "user", "content": prompt}],
        "stream": stream,
    }
    if os.environ.get("ASVA_LLM_NUM_PREDICT"):
        payload["max_tokens"] = int(os.environ["ASVA_LLM_NUM_PREDICT"])
    # Reasoning ("thinking") models spend reply tokens on hidden reasoning before the
    # answer, which can use up max_tokens before any code is written. These let the
    # endpoint be told to think less or not at all, whatever knob it understands:
    #   ASVA_LLM_REASONING_EFFORT=none|low|medium|high   -> "reasoning_effort"
    #   ASVA_LLM_EXTRA_BODY='{"think": false}'            -> merged into the request body
    effort = os.environ.get("ASVA_LLM_REASONING_EFFORT", "").strip()
    if effort:
        payload["reasoning_effort"] = effort
    extra = os.environ.get("ASVA_LLM_EXTRA_BODY", "").strip()
    if extra:
        try:
            payload.update(json.loads(extra))
        except ValueError as e:
            raise LLMUnavailableError(f"ASVA_LLM_EXTRA_BODY is not valid JSON: {e}") from e
    if stream:
        payload.setdefault("stream_options", {"include_usage": True})   # token counts
    return payload


def _reasoning_text(part: dict) -> str:
    """Hidden reasoning in a message or stream delta (field name differs by server)."""
    return part.get("reasoning_content") or part.get("reasoning") or part.get("thinking") or ""


def _post_completion(payload: dict) -> tuple[str, str | None, dict, int]:
    response = client.post(CHAT_COMPLETIONS_PATH, json=payload)
    if response.status_code >= 400:
        raise _HTTPFailure(response.status_code, response.text[:ERROR_BODY_LIMIT])
    data = response.json()
    choice = data["choices"][0]
    message = choice.get("message") or {}
    return (message.get("content") or "", choice.get("finish_reason"),
            data.get("usage") or {}, len(_reasoning_text(message)))


def _stream_completion(payload: dict) -> tuple[str, str | None, dict, int]:
    """POST with stream=True and assemble the server-sent events. A server that answers
    with plain JSON instead of a stream is handled too."""
    url = os.environ["OLLAMA_HOST"].rstrip("/") + CHAT_COMPLETIONS_PATH
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {os.environ['OLLAMA_API_KEY']}",
    }
    timeout = httpx.Timeout(float(os.environ.get("OLLAMA_TIMEOUT", "900")), connect=30.0)
    with httpx.stream("POST", url, headers=headers, json=payload, timeout=timeout) as r:
        if r.status_code >= 400:
            try:
                r.read()
                body = r.text[:ERROR_BODY_LIMIT]
            except Exception:
                body = None
            raise _HTTPFailure(r.status_code, body)
        if "text/event-stream" not in r.headers.get("content-type", ""):
            data = json.loads(r.read())
            choice = data["choices"][0]
            message = choice.get("message") or {}
            return (message.get("content") or "", choice.get("finish_reason"),
                    data.get("usage") or {}, len(_reasoning_text(message)))
        parts: list[str] = []
        reasoning = 0
        finish, usage, done = None, {}, False
        for line in r.iter_lines():
            if not line.startswith("data:"):
                continue
            chunk_text = line[5:].strip()
            if chunk_text == "[DONE]":
                done = True
                break
            chunk = json.loads(chunk_text)
            if chunk.get("error"):
                raise _HTTPFailure(500, json.dumps(chunk["error"]))
            for choice in chunk.get("choices") or []:
                delta = choice.get("delta") or {}
                content = delta.get("content")
                if content:
                    parts.append(content)
                reasoning += len(_reasoning_text(delta))
                if choice.get("finish_reason"):
                    finish = choice["finish_reason"]
            if chunk.get("usage"):
                usage = chunk["usage"]
        if not done and finish is None:
            # The connection closed mid-reply: the text is incomplete, so try again
            raise _HTTPFailure(502, "stream ended before the model finished")
        return "".join(parts), finish, usage, reasoning


def call_llm(prompt: str) -> str:
    stream = _streaming()
    payload = _payload(prompt, stream)
    attempts, delay = _retries()
    for attempt in range(1, attempts + 1):
        try:
            content, finish, usage, reasoning_chars = (
                _stream_completion if stream else _post_completion)(payload)
            break
        except _HTTPFailure as e:
            retryable, error = e.status in _RETRY_STATUS, e
            reason = f"HTTP {e.status}: {_error_detail(e.body, prompt)}"
        except (httpx.TransportError, json.JSONDecodeError) as e:
            retryable, reason, error = True, f"{type(e).__name__}: {e}", e
        except Exception as e:
            raise LLMUnavailableError(f"Ollama call failed: {e}") from e
        if not retryable or attempt == attempts:
            raise LLMUnavailableError(
                f"Ollama call failed: {reason}"
                + (f" (after {attempt} attempts)" if attempt > 1 else "")
            ) from error
        wait = delay * attempt
        print(f"    [WARN] LLM call failed ({reason}); retrying in {wait:.0f}s "
              f"(attempt {attempt + 1} of {attempts})")
        time.sleep(wait)
    last_call.clear()
    last_call.update({
        "finish_reason": finish,
        "prompt_tokens": usage.get("prompt_tokens"),
        "completion_tokens": usage.get("completion_tokens"),
        "reasoning_chars": reasoning_chars,   # hidden reasoning the model produced
        "answer_chars": len(content),
    })
    # Some reasoning models put their thinking inline; it must never reach a fixed file.
    return _THINK_RE.sub("", content)


# quick test
if __name__ == "__main__":
    result = call_llm("hi there, introduce yourself.")
    print(result)

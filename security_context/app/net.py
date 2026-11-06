"""HTTP helpers for online sources: one shared client, retries with backoff, rate limits.

Online sources fail softly: a lookup that still fails after its retries raises
LookupFailed, which callers turn into a warning instead of an error.
"""

import threading
import time
from collections import deque

import httpx

from app import config

RETRY_STATUSES = {429, 500, 502, 503, 504}


class LookupFailed(RuntimeError):
    """An online source didn't answer usefully after retries."""


class RateLimiter:
    """At most `max_calls` per `period` seconds, shared across threads."""

    def __init__(self, max_calls: int, period: float):
        self.max_calls, self.period = max_calls, period
        self._calls: deque[float] = deque()
        self._lock = threading.Lock()

    def wait(self) -> None:
        while True:
            with self._lock:
                now = time.monotonic()
                while self._calls and now - self._calls[0] >= self.period:
                    self._calls.popleft()
                if len(self._calls) < self.max_calls:
                    self._calls.append(now)
                    return
                delay = self.period - (now - self._calls[0])
            time.sleep(max(delay, 0.05))


def make_client(timeout: float = config.HTTP_TIMEOUT, transport: httpx.BaseTransport | None = None) -> httpx.Client:
    return httpx.Client(timeout=timeout, follow_redirects=True, transport=transport,
                        headers={"User-Agent": config.USER_AGENT})


def request(client: httpx.Client, method: str, url: str, *, limiter: RateLimiter | None = None,
            retries: int = 3, backoff: float = 2.0, ok_statuses: tuple[int, ...] = (), **kwargs) -> httpx.Response:
    """Send with retries on timeouts, 429 and 5xx. `ok_statuses` (e.g. 404) are returned, not raised."""
    last_error = None
    for attempt in range(retries + 1):
        if limiter:
            limiter.wait()
        try:
            response = client.request(method, url, **kwargs)
        except httpx.TransportError as error:  # timeouts, connection errors
            last_error = f"{type(error).__name__}: {error}"
        else:
            if response.is_success or response.status_code in ok_statuses:
                return response
            last_error = f"HTTP {response.status_code}"
            if response.status_code not in RETRY_STATUSES:
                break
            retry_after = response.headers.get("Retry-After")
            if retry_after and retry_after.isdigit() and attempt < retries:
                time.sleep(min(int(retry_after), 30))
                continue
        if attempt < retries:
            time.sleep(backoff * (2 ** attempt))
    raise LookupFailed(f"{method} {url}: {last_error}")

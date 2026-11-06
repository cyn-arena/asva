"""Background source syncs triggered over HTTP (POST /admin/sync), e.g. by a Kubernetes CronJob.

One sync at a time; the service keeps answering requests while it runs, and picks up new
OWASP passages when it finishes.
"""

import hmac
import threading
from typing import Callable

from app import store


def token_ok(expected: str, authorization: str | None) -> bool:
    if not expected or not authorization or not authorization.startswith("Bearer "):
        return False
    return hmac.compare_digest(authorization[len("Bearer "):].encode(), expected.encode())


class SyncRunner:
    def __init__(self, run_sync: Callable[[list[str] | None, bool], list[str]], on_done: Callable[[], None]):
        self._run_sync = run_sync
        self._on_done = on_done
        self._lock = threading.Lock()
        self.status: dict = {"state": "idle", "started_at": None, "finished_at": None, "sources": None, "results": []}

    @property
    def running(self) -> bool:
        return self.status["state"] == "running"

    def start(self, sources: list[str] | None, force: bool) -> bool:
        """Start a sync in the background; False if one is already running."""
        with self._lock:
            if self.running:
                return False
            self.status = {"state": "running", "started_at": store.now_iso(), "finished_at": None,
                           "sources": sources, "results": []}
        threading.Thread(target=self._work, args=(sources, force), daemon=True).start()
        return True

    def _work(self, sources: list[str] | None, force: bool) -> None:
        try:
            results = self._run_sync(sources, force)
            self._on_done()
            state = "failed" if any("FAILED" in r for r in results) else "done"
        except Exception as error:  # report, never crash the service
            results, state = [f"sync crashed: {type(error).__name__}: {error}"], "failed"
        self.status.update({"state": state, "finished_at": store.now_iso(), "results": results})

"""Shared httpx helpers for the request-level e2e tier."""

from __future__ import annotations

import httpx
import pytest

from tests.expectations import State


def login_client(base_url: str, username: str, password: str) -> httpx.Client:
    """A logged-in httpx.Client carrying the resulting session cookie, via the real
    login form (not a raw session hack) -- CSRF is disabled in this app (server.js),
    so no token dance is needed here."""
    client = httpx.Client(base_url=base_url, follow_redirects=False)
    resp = client.post("/login", data={"userName": username, "password": password})
    assert resp.status_code == 302, f"login failed for {username!r}: got {resp.status_code}"
    return client


def assert_case(state: State, vulnerable_behavior_observed: bool, detail: str) -> None:
    """Check an observed boolean ("did the vulnerable behavior happen?") against this
    target's expected state for the case. UNKNOWN skips instead of asserting either way --
    see the State enum in tests/expectations.py for why."""
    if state == State.VULNERABLE:
        assert vulnerable_behavior_observed, f"expected vulnerable behavior, but it was blocked: {detail}"
    elif state == State.FIXED:
        assert not vulnerable_behavior_observed, f"expected this to be fixed, but it still works: {detail}"
    else:
        pytest.skip("remediation status not confirmed for this target -- see tests/expectations.py")

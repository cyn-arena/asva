# tests/e2e/api/

Request-level misuse-case checks, `@pytest.mark.api`. `httpx` + a session-cookie
login helper; status codes / redirect `Location` / response bodies against `BASE_URL`
(dvng1=blue, dvng2=green, or a local NodeGoat — see `tests/e2e/browser/README.md`).
Expectations come from `tests/expectations.py`, never a global "vuln present" flag —
a case whose fix isn't confirmed on the target being tested skips instead of asserting
either way.

- `_helpers.py` — `login_client(base_url, username, password)` returns an httpx.Client
  already carrying the session cookie from a real `/login` POST (this app has CSRF
  protection disabled, so no token handling is needed); `assert_case(state, observed,
  detail)` checks an observed boolean against the target's expected state, skipping on
  `UNKNOWN`.
- `conftest.py` — `user1_client` / `user2_client` fixtures, logged in as the two
  non-admin seed users.
- `test_misuse_cases.py` — the five A-case checks: IDOR on `/allocations/:userId`,
  missing access control on `/benefits`, open redirect on `/learn?url=`, SSJI via
  `eval()` on `/contributions`, and a baseline validation check around the ReDoS-prone
  regex on `/profile`'s `bankRouting` field. The ReDoS check is validation-only and does
  not send timing payloads.

Set `TARGET=blue` or `TARGET=green` alongside `BASE_URL` so the suite knows which side
of `tests/expectations.py` to check against; defaults to `blue`.

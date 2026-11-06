# tests/e2e/browser/

Playwright, DOM/session-only cases. Prefer `tests/e2e/api/` for anything request-level —
reserve this tier for what actually needs a browser.

Requires `BASE_URL` (a running NodeGoat — see below) and Playwright's chromium browser
installed (`python -m playwright install chromium`). Skips cleanly (via the `target_base_url`
fixture in `tests/conftest.py`) when `BASE_URL` isn't set, so `-m unit` never needs a browser.

- `_helpers.py` — shared `login(page, base_url, username, password)`, used by the `logged_in_page`
  fixture in this directory's `conftest.py` and directly by anything that wants to assert on the
  login flow itself.
- `test_smoke.py` (`@pytest.mark.smoke`) — the pre-merge happy-path suite: login redirects to
  `/dashboard`, the dashboard renders, a normal contribution submits successfully, the profile
  page renders, and the Learning Resources link still reaches its off-site destination. Meant
  to run against green (`dvng2`) before a fix PR merges. Attaching the result to the PR is a
  separate CI/reporting concern, not done here.
  - The Learning Resources check keeps the legitimate Khan Academy redirect working after
    open-redirect fixes.
- Misuse cases that only manifest in rendered UI (not yet written) belong here too, alongside
  the login flow they'll also reuse via `logged_in_page`.

## Running against a local NodeGoat instead of dvng1/dvng2

To run locally:

1. Ensure `target-apps/NodeGoat/config/env/` contains the environment files required by your
   local NodeGoat setup.
2. Use the local `docker-compose.override.yml` to run MongoDB 3.2 and set `PORT=4000`.
3. Run `docker compose up -d --build` from `target-apps/NodeGoat/`, then
   `BASE_URL=http://localhost:4000 pytest -m smoke`.

Seed accounts (from `artifacts/db-reset.js`, auto-run on container start): `admin`/`Admin_123`,
`user1`/`User1_123`, `user2`/`User2_123`.

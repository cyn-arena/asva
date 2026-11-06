# tests/rescan/

Before/after Snyk SARIF diff, `@pytest.mark.rescan`. Triggers real Snyk scans against two
NodeGoat source checkouts and asserts on the diff — matched by the normaliser's dedup key,
never by count.

- `_snyk_rescan.py` — scan invocation (`run_sast_scan` / `run_sca_scan`, wrapping
  `snyk code test` / `snyk test`), `is_authenticated()` (`snyk whoami` — true for either
  `snyk auth`'s local CLI-config token or a CI `SNYK_TOKEN` env var), `load_findings`
  (normalise + dedupe, keeping `dedup_key` — `normaliser.build_ranked_unified` strips it for
  the downstream pipeline, but this is exactly what the diff needs), `diff_findings` (splits
  into `remediated` / `persisted` / `introduced` buckets), and `assert_fully_remediated`
  (asserts specific rule_ids are gone in "after", with a guard against a vacuous pass if the
  rule_id never appeared in "before" at all). Unit-tested in `tests/unit/test_snyk_rescan.py`
  with mocked `subprocess` and synthetic finding dicts — no real Snyk call needed for that.
- `test_rescan.py` — three tests, two different claims:
  - `test_sast_rescan_no_new_findings` — a *regression* check ("nothing new broke"), asserted
    strictly. On its own this says nothing about whether anything was actually fixed.
  - `test_sast_rescan_confirms_known_fixes_remediated` — the *remediation* check: asserts the
    SAST rule_ids behind the two `tests/expectations.py` cases marked `green=FIXED`
    (`a1_ssji_eval` → `javascript/CodeInjection`, `a1_redos_bankrouting` →
    `javascript/reDOSPolynomial`) are actually gone in "after", proving the fix agent's work
    held up under a real independent scanner, not just the misuse-case suite.
  - `test_sca_rescan_no_new_findings` — `xfail(strict=False)`, documented reason.

**Env needed:** `snyk auth` (local dev) or `SNYK_TOKEN` (CI), optionally `SNYK_ORG`, and a
patched NodeGoat checkout in `RESCAN_AFTER_DIR`. `RESCAN_BEFORE_DIR` defaults to this repo's
`target-apps/NodeGoat`. The suite skips cleanly when Snyk is not authenticated or
`RESCAN_AFTER_DIR` is unset.

**SAST and SCA results:** SAST differences are enforced strictly. SCA is
`xfail(strict=False)` because its live vulnerability database can report a newly published CVE
between scans without a code regression. Container/image scans would need the same treatment.

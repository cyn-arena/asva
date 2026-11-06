"""Run before/after Snyk scans against RESCAN_BEFORE_DIR and RESCAN_AFTER_DIR.

Findings are matched by dedup_key. The suite checks both new SAST findings and known SAST
remediations; SCA is an informational xfail because its vulnerability data can change.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from tests.rescan._snyk_rescan import (
    SnykScanError,
    assert_fully_remediated,
    diff_findings,
    is_authenticated,
    load_findings,
    run_sast_scan,
    run_sca_scan,
)

# rule_ids Snyk Code emits for the two misuse cases tests/expectations.py marks
# green=State.FIXED -- confirmed by inspecting a real before/after scan (2026-07-06).
EXPECTED_REMEDIATED_SAST_RULE_IDS = {
    "javascript/CodeInjection",    # a1_ssji_eval -- eval() on /contributions
    "javascript/reDOSPolynomial",  # a1_redos_bankrouting -- bankRouting regex in profile.js
}

pytestmark = pytest.mark.rescan

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture(autouse=True)
def _require_snyk_setup():
    if not is_authenticated():
        pytest.skip(
            "snyk CLI not authenticated -- run `snyk auth` once, or set SNYK_TOKEN for CI"
        )
    if not os.environ.get("RESCAN_AFTER_DIR"):
        pytest.skip(
            "RESCAN_AFTER_DIR not set -- point it at a patched NodeGoat checkout "
            "(e.g. a worktree with fix branches applied) to compare against RESCAN_BEFORE_DIR"
        )


@pytest.fixture
def before_dir() -> Path:
    path = Path(os.environ.get("RESCAN_BEFORE_DIR") or REPO_ROOT / "target-apps" / "NodeGoat")
    if not path.exists():
        pytest.skip(f"RESCAN_BEFORE_DIR not found: {path}")
    return path


@pytest.fixture
def after_dir() -> Path:
    path = Path(os.environ["RESCAN_AFTER_DIR"])
    if not path.exists():
        pytest.skip(f"RESCAN_AFTER_DIR not found: {path}")
    return path


def test_sast_rescan_no_new_findings(tmp_path, before_dir, after_dir):
    try:
        before_sarif = run_sast_scan(before_dir, tmp_path / "before-sast.sarif.json")
        after_sarif = run_sast_scan(after_dir, tmp_path / "after-sast.sarif.json")
    except SnykScanError as e:
        pytest.fail(str(e))

    diff = diff_findings(load_findings([before_sarif]), load_findings([after_sarif]))

    new_sast = diff.introduced_of_type("sast")
    assert new_sast == [], (
        f"{len(new_sast)} new SAST finding(s) appeared after that weren't present before: "
        f"{[f['dedup_key'] for f in new_sast]}"
    )


def test_sast_rescan_confirms_known_fixes_remediated(tmp_path, before_dir, after_dir):
    try:
        before_sarif = run_sast_scan(before_dir, tmp_path / "before-sast.sarif.json")
        after_sarif = run_sast_scan(after_dir, tmp_path / "after-sast.sarif.json")
    except SnykScanError as e:
        pytest.fail(str(e))

    before = load_findings([before_sarif])
    diff = diff_findings(before, load_findings([after_sarif]))

    assert_fully_remediated(before, diff, EXPECTED_REMEDIATED_SAST_RULE_IDS)


@pytest.mark.xfail(
    reason=(
        "SCA data comes from a live vulnerability database, so a newly published CVE can "
        "appear between scans without a code regression."
    ),
    strict=False,
)
def test_sca_rescan_no_new_findings(tmp_path, before_dir, after_dir):
    before_sarif = run_sca_scan(before_dir, tmp_path / "before-sca.sarif.json")
    after_sarif = run_sca_scan(after_dir, tmp_path / "after-sca.sarif.json")

    diff = diff_findings(load_findings([before_sarif]), load_findings([after_sarif]))

    new_sca = diff.introduced_of_type("sca")
    assert new_sca == [], f"new SCA finding(s): {[f['dedup_key'] for f in new_sca]}"

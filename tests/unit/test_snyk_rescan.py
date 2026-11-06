"""Unit tests for tests/rescan/_snyk_rescan.py -- scan invocation (mocked subprocess) and
the before/after diff logic (synthetic finding dicts, no real SARIF needed for that part)."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from tests.rescan import _snyk_rescan
from tests.rescan._snyk_rescan import (
    SnykScanError,
    assert_fully_remediated,
    diff_findings,
    is_authenticated,
    load_findings,
    run_sast_scan,
    run_sca_scan,
)

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _no_local_snyk_config(monkeypatch):
    """These tests assert on the exact command built, so pin SNYK_BINARY/SNYK_ORG to their
    defaults regardless of what a local .env sets them to (same convention as
    test_regression_gate.py's _no_fix_path_prefix) -- otherwise they'd only pass by
    accident of environment."""
    monkeypatch.setattr(_snyk_rescan, "SNYK_BINARY", "snyk")
    monkeypatch.setattr(_snyk_rescan, "SNYK_ORG", "")


@dataclass
class FakeCompletedProcess:
    returncode: int
    stdout: str = ""
    stderr: str = ""


def _finding(
    dedup_key: str, finding_type: str = "sast", severity: str = "high", rule_id: str = "some/Rule"
) -> dict:
    return {
        "dedup_key": dedup_key,
        "finding_type": finding_type,
        "severity": severity,
        "identifiers": {"rule_id": rule_id},
    }


# --------------------------------------------------------------------------------------
# is_authenticated -- covers both `snyk auth` (local) and SNYK_TOKEN (CI) paths, since
# neither is checked directly: `snyk whoami` succeeds either way, so this is the one
# check that works regardless of which auth style the caller used.
# --------------------------------------------------------------------------------------

def test_is_authenticated_true_when_whoami_succeeds(monkeypatch):
    monkeypatch.setattr(
        _snyk_rescan.subprocess, "run",
        lambda cmd, **k: FakeCompletedProcess(returncode=0),
    )
    assert is_authenticated() is True


def test_is_authenticated_false_when_whoami_fails(monkeypatch):
    monkeypatch.setattr(
        _snyk_rescan.subprocess, "run",
        lambda cmd, **k: FakeCompletedProcess(returncode=1),
    )
    assert is_authenticated() is False


def test_is_authenticated_false_when_binary_missing(monkeypatch):
    def fake_run(cmd, **k):
        raise FileNotFoundError("snyk not found")

    monkeypatch.setattr(_snyk_rescan.subprocess, "run", fake_run)
    assert is_authenticated() is False


# --------------------------------------------------------------------------------------
# run_sast_scan / run_sca_scan
# --------------------------------------------------------------------------------------

def test_run_sast_scan_writes_sarif_and_returns_path(monkeypatch, tmp_path):
    calls = []
    sarif_out = tmp_path / "out.sarif.json"

    def fake_run(cmd, cwd=None, capture_output=True, text=True):
        calls.append(cmd)
        sarif_out.write_text("{}", encoding="utf-8")
        return FakeCompletedProcess(returncode=1)  # snyk exits 1 when issues are found

    monkeypatch.setattr(_snyk_rescan.subprocess, "run", fake_run)
    result = run_sast_scan(tmp_path, sarif_out)

    assert result == sarif_out
    assert calls == [["snyk", "code", "test", f"--sarif-file-output={sarif_out}"]]


def test_run_sca_scan_includes_org_when_set(monkeypatch, tmp_path):
    calls = []
    sarif_out = tmp_path / "out.sarif.json"
    monkeypatch.setattr(_snyk_rescan, "SNYK_ORG", "my-org")

    def fake_run(cmd, cwd=None, capture_output=True, text=True):
        calls.append(cmd)
        sarif_out.write_text("{}", encoding="utf-8")
        return FakeCompletedProcess(returncode=0)

    monkeypatch.setattr(_snyk_rescan.subprocess, "run", fake_run)
    run_sca_scan(tmp_path, sarif_out)

    assert calls == [["snyk", "test", f"--sarif-file-output={sarif_out}", "--org=my-org"]]


def test_run_scan_missing_binary_raises_snyk_scan_error(monkeypatch, tmp_path):
    def fake_run(cmd, cwd=None, capture_output=True, text=True):
        raise FileNotFoundError("snyk not found")

    monkeypatch.setattr(_snyk_rescan.subprocess, "run", fake_run)

    with pytest.raises(SnykScanError, match="not found"):
        run_sast_scan(tmp_path, tmp_path / "out.sarif.json")


def test_run_scan_no_sarif_written_raises_snyk_scan_error(monkeypatch, tmp_path):
    def fake_run(cmd, cwd=None, capture_output=True, text=True):
        return FakeCompletedProcess(returncode=2)  # e.g. auth failure, nothing written

    monkeypatch.setattr(_snyk_rescan.subprocess, "run", fake_run)

    with pytest.raises(SnykScanError, match="did not write"):
        run_sast_scan(tmp_path, tmp_path / "missing.sarif.json")


# --------------------------------------------------------------------------------------
# load_findings -- real SARIF fixture, keeps dedup_key (unlike build_ranked_unified)
# --------------------------------------------------------------------------------------

def test_load_findings_keeps_dedup_key(sarif_sample_path):
    findings = load_findings([sarif_sample_path["sast"]])
    assert findings
    assert all("dedup_key" in f for f in findings)


# --------------------------------------------------------------------------------------
# diff_findings -- remediated / persisted / introduced buckets
# --------------------------------------------------------------------------------------

def test_diff_findings_categorises_by_dedup_key():
    before = [_finding("a"), _finding("b"), _finding("c")]
    after = [_finding("b"), _finding("d")]

    diff = diff_findings(before, after)

    assert [f["dedup_key"] for f in diff.remediated] == ["a", "c"]
    assert [f["dedup_key"] for f in diff.persisted] == ["b"]
    assert [f["dedup_key"] for f in diff.introduced] == ["d"]


def test_diff_findings_empty_before_all_introduced():
    after = [_finding("x"), _finding("y")]
    diff = diff_findings([], after)
    assert diff.remediated == []
    assert diff.persisted == []
    assert {f["dedup_key"] for f in diff.introduced} == {"x", "y"}


def test_diff_findings_empty_after_all_remediated():
    before = [_finding("x"), _finding("y")]
    diff = diff_findings(before, [])
    assert {f["dedup_key"] for f in diff.remediated} == {"x", "y"}
    assert diff.persisted == []
    assert diff.introduced == []


def test_introduced_of_type_filters_by_finding_type():
    before = []
    after = [_finding("s1", finding_type="sast"), _finding("c1", finding_type="sca")]
    diff = diff_findings(before, after)

    assert [f["dedup_key"] for f in diff.introduced_of_type("sast")] == ["s1"]
    assert [f["dedup_key"] for f in diff.introduced_of_type("sca")] == ["c1"]


def test_introduced_high_severity_filters_critical_and_high_only():
    before = []
    after = [
        _finding("crit", severity="critical"),
        _finding("high", severity="high"),
        _finding("med", severity="medium"),
        _finding("low", severity="low"),
    ]
    diff = diff_findings(before, after)

    assert {f["dedup_key"] for f in diff.introduced_high_severity()} == {"crit", "high"}


# --------------------------------------------------------------------------------------
# assert_fully_remediated -- the "was it actually fixed" check, not just "no regression"
# --------------------------------------------------------------------------------------

def test_assert_fully_remediated_passes_when_expected_rule_ids_are_gone():
    before = [_finding("a", rule_id="javascript/CodeInjection"), _finding("b", rule_id="other/Rule")]
    after = [_finding("b", rule_id="other/Rule")]  # "a" (CodeInjection) is gone
    diff = diff_findings(before, after)

    assert_fully_remediated(before, diff, {"javascript/CodeInjection"})  # does not raise


def test_assert_fully_remediated_raises_when_rule_id_still_persists():
    before = [_finding("a", rule_id="javascript/CodeInjection")]
    after = [_finding("a", rule_id="javascript/CodeInjection")]  # unchanged -- not fixed
    diff = diff_findings(before, after)

    with pytest.raises(AssertionError, match="persisted"):
        assert_fully_remediated(before, diff, {"javascript/CodeInjection"})


def test_assert_fully_remediated_raises_when_rule_id_never_existed_in_before():
    """Guards against a vacuous pass: if the expected rule_id never appeared in `before` at
    all (e.g. a typo, or the scanner renamed the rule), there was nothing to remediate --
    that must be surfaced as a real failure, not a silent pass."""
    before = [_finding("a", rule_id="some/OtherRule")]
    after = [_finding("a", rule_id="some/OtherRule")]
    diff = diff_findings(before, after)

    with pytest.raises(AssertionError, match="check for a rule_id rename/typo"):
        assert_fully_remediated(before, diff, {"javascript/CodeInjection"})


def test_run_scan_error_includes_what_snyk_said(monkeypatch, tmp_path):
    class Proc:
        returncode = 2
        stdout = ""
        stderr = "Snyk Code is not supported for org my-org."

    monkeypatch.setattr(_snyk_rescan.subprocess, "run", lambda *a, **k: Proc())
    with pytest.raises(SnykScanError, match="not supported for org my-org"):
        run_sast_scan(tmp_path, tmp_path / "missing.sarif.json")

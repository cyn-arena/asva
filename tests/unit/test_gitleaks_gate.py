"""Unit tests for secrets_scan/gitleaks_gate.py -- fail-closed with
subprocess mocked. No real gitleaks binary is ever invoked in this file."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass

import pytest

from secrets_scan import gitleaks_gate
from secrets_scan.gitleaks_gate import GitleaksError, ScanResult, _safe_rel, added_leaks, scan_files

pytestmark = pytest.mark.unit


@dataclass
class FakeCompletedProcess:
    returncode: int
    stdout: str = ""
    stderr: str = ""


def _patch_run(monkeypatch, returncode: int) -> None:
    def fake_run(cmd, capture_output=True, text=True):
        return FakeCompletedProcess(returncode=returncode)

    monkeypatch.setattr(gitleaks_gate.subprocess, "run", fake_run)


# --------------------------------------------------------------------------------------
# _safe_rel
# --------------------------------------------------------------------------------------

def test_safe_rel_normalises_leading_slash_and_backslashes():
    assert _safe_rel("/app/routes/x.js") == "app/routes/x.js"
    assert _safe_rel("app\\routes\\x.js") == "app/routes/x.js"


def test_safe_rel_rejects_traversal():
    with pytest.raises(GitleaksError):
        _safe_rel("../../etc/passwd")


# --------------------------------------------------------------------------------------
# scan_files — exit-code semantics
# --------------------------------------------------------------------------------------

def test_scan_files_empty_list_is_clean_without_running_gitleaks(monkeypatch):
    def fail_if_called(*a, **k):
        raise AssertionError("subprocess.run should not be called for an empty file list")

    monkeypatch.setattr(gitleaks_gate.subprocess, "run", fail_if_called)
    result = scan_files([])
    assert result.clean is True
    assert bool(result) is True


def test_scan_files_exit_0_is_clean(monkeypatch):
    _patch_run(monkeypatch, returncode=0)
    result = scan_files([{"path": "app/config.js", "content": "module.exports = {};"}])
    assert result.clean is True
    assert bool(result) is True


def test_scan_files_exit_2_is_not_clean_even_with_unparseable_report(monkeypatch):
    # No report.json is ever written by the fake, so _parse_report sees a missing file and
    # returns leaks=[] — the authoritative signal must still be the exit code, not the
    # (empty) parsed report.
    _patch_run(monkeypatch, returncode=2)
    result = scan_files([{"path": "app/config.js", "content": "AKIA_FAKE_SECRET"}])
    assert result.clean is False
    assert bool(result) is False
    assert result.leaks == []


def test_scan_files_other_nonzero_with_no_leaks_raises(monkeypatch):
    _patch_run(monkeypatch, returncode=1)
    with pytest.raises(GitleaksError):
        scan_files([{"path": "app/config.js", "content": "x"}])


def test_scan_files_missing_binary_raises_gitleaks_error(monkeypatch):
    def fake_run(cmd, capture_output=True, text=True):
        raise FileNotFoundError("no such file: gitleaks")

    monkeypatch.setattr(gitleaks_gate.subprocess, "run", fake_run)
    with pytest.raises(GitleaksError):
        scan_files([{"path": "app/config.js", "content": "x"}])


def test_scan_files_directory_traversal_path_raises_without_running_gitleaks(monkeypatch):
    def fail_if_called(*a, **k):
        raise AssertionError("subprocess.run should not be reached for a traversal path")

    monkeypatch.setattr(gitleaks_gate.subprocess, "run", fail_if_called)
    with pytest.raises(GitleaksError):
        scan_files([{"path": "../../etc/passwd", "content": "x"}])


def test_a_scan_keeps_a_hash_of_the_secret_never_the_value(monkeypatch):
    def fake_run(cmd, capture_output=True, text=True):
        report = cmd[cmd.index("--report-path") + 1]
        with open(report, "w", encoding="utf-8") as f:
            json.dump([{"File": "x", "RuleID": "generic-api-key", "StartLine": 3,
                        "Secret": "the-real-value", "Match": "key=the-real-value"}], f)
        return FakeCompletedProcess(returncode=2)

    monkeypatch.setattr(gitleaks_gate.subprocess, "run", fake_run)
    result = scan_files([{"path": "a.py", "content": "x"}])
    assert result.leaks[0]["rule"] == "generic-api-key" and result.leaks[0]["line"] == 3
    assert result.leaks[0]["value_id"]
    assert "the-real-value" not in json.dumps(result.leaks)


# --------------------------------------------------------------------------------------
# added_leaks — what only the fix has
# --------------------------------------------------------------------------------------

def _scan(*values):
    return ScanResult(clean=not values, leaks=[{"value_id": v, "line": i} for i, v in enumerate(values)])


def test_a_secret_the_fix_moved_is_not_added():
    assert added_leaks(_scan("a", "b"), _scan("b", "a")) == []


def test_a_new_secret_is_added():
    assert [leak["value_id"] for leak in added_leaks(_scan("a"), _scan("a", "b"))] == ["b"]


def test_a_secret_copied_elsewhere_by_the_fix_is_added():
    assert len(added_leaks(_scan("a"), _scan("a", "a"))) == 1


def test_a_leak_with_no_value_to_compare_counts_as_added():
    assert len(added_leaks(_scan("a"), _scan(None))) == 1

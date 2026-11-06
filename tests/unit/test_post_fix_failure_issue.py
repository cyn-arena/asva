"""Unit tests for gitops/post_fix_failure_issue.py -- issue formatting + the no_commits
filter/dedup pass, offline against synthetic prs.json/batch data (no real gh calls)."""

from __future__ import annotations

import json

import pytest

from gitops import post_fix_failure_issue as pffi

pytestmark = pytest.mark.unit

BATCH = {
    "batch_id": "asva_sca_bf49b76a",
    "batch_type": "sca",
    "repo_name": "asva",
    "commit_sha": "bf49b76abcdef",
    "files_to_fix": [
        {
            "file": "package.json",
            "fix_type": "version_upgrade",
            "finding_type": "sca",
            "findings": [
                {
                    "title": "Prototype Pollution",
                    "severity": "high",
                    "identifiers": {"cve": "CVE-2021-1234", "cwe": None, "rule_id": None},
                },
                {
                    "title": "ReDoS",
                    "severity": "medium",
                    "identifiers": {"cve": None, "cwe": None, "rule_id": "SNYK-JS-FOO-123"},
                },
            ],
        }
    ],
}

NO_COMMITS_ENTRY = {
    "batch_id": "asva_sca_bf49b76a",
    "status": "no_commits",
    "pr_url": None,
    "blocked": [{"path": "package.json", "reason": "secrets detected"}],
    "failed": [{"path": "package.json", "reason": "fix made no change to the file"}],
}

PR_OPENED_ENTRY = {
    "batch_id": "asva_sast_bf49b76a_1",
    "status": "pr_opened",
    "pr_url": "https://github.com/o/r/pull/1",
    "failed": [],
    "blocked": [],
}

ERROR_ENTRY = {
    "batch_id": "asva_container_bf49b76a",
    "status": "error",
    "pr_url": None,
}


def test_format_issue_title():
    assert pffi.format_issue_title("asva_sca_bf49b76a") == (
        "ASVA: vulnerability confirmed, automated fix failed -- batch asva_sca_bf49b76a"
    )


def test_format_issue_body_includes_findings_table():
    body = pffi.format_issue_body(BATCH, NO_COMMITS_ENTRY)

    assert "asva_sca_bf49b76a" in body
    assert "package.json" in body
    assert "Prototype Pollution" in body
    assert "CVE-2021-1234" in body
    assert "ReDoS" in body
    assert "SNYK-JS-FOO-123" in body
    assert "still present and need a manual fix" in body


def test_format_issue_body_includes_blocked_and_failed_sections():
    body = pffi.format_issue_body(BATCH, NO_COMMITS_ENTRY)

    assert "Withheld by the secrets gate" in body
    assert "secrets detected" in body
    assert "Rejected before commit" in body
    assert "fix made no change to the file" in body


def test_format_issue_body_omits_sections_with_no_entries():
    entry = {"batch_id": "x", "status": "no_commits", "blocked": [], "failed": []}
    body = pffi.format_issue_body(BATCH, entry)

    assert "Withheld by the secrets gate" not in body
    assert "Rejected before commit" not in body


def test_process_no_commits_entries_only_selects_no_commits(monkeypatch):
    monkeypatch.setattr(pffi, "_load_batch", lambda batch_dir, batch_id: BATCH)
    monkeypatch.setattr(pffi, "find_open_issue", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("should not be called in a dry run")))
    monkeypatch.setattr(pffi, "open_issue", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("should not be called in a dry run")))

    exit_code = pffi.process_no_commits_entries(
        [NO_COMMITS_ENTRY, PR_OPENED_ENTRY, ERROR_ENTRY], "fix_batches", execute=False
    )

    assert exit_code == 0


def test_process_no_commits_entries_dry_run_does_not_call_gh(monkeypatch):
    monkeypatch.setattr(pffi, "_load_batch", lambda batch_dir, batch_id: BATCH)
    calls = []
    monkeypatch.setattr(pffi, "find_open_issue", lambda *a, **k: calls.append("find_open_issue"))
    monkeypatch.setattr(pffi, "open_issue", lambda *a, **k: calls.append("open_issue"))

    pffi.process_no_commits_entries([NO_COMMITS_ENTRY], "fix_batches", execute=False)

    assert calls == []


def test_process_no_commits_entries_execute_opens_issue(monkeypatch):
    monkeypatch.setattr(pffi, "_load_batch", lambda batch_dir, batch_id: BATCH)
    monkeypatch.setattr(pffi, "find_open_issue", lambda *a, **k: None)
    opened = []
    monkeypatch.setattr(
        pffi, "open_issue",
        lambda title, body, repo_dir=".": opened.append((title, body)) or "https://github.com/o/r/issues/9",
    )

    exit_code = pffi.process_no_commits_entries([NO_COMMITS_ENTRY], "fix_batches", execute=True)

    assert exit_code == 0
    assert len(opened) == 1
    assert opened[0][0] == pffi.format_issue_title("asva_sca_bf49b76a")


def test_process_no_commits_entries_dedup_skips_when_issue_already_open(monkeypatch):
    monkeypatch.setattr(pffi, "_load_batch", lambda batch_dir, batch_id: BATCH)
    monkeypatch.setattr(pffi, "find_open_issue", lambda *a, **k: "42")
    monkeypatch.setattr(pffi, "open_issue", lambda *a, **k: (_ for _ in ()).throw(
        AssertionError("should not open a duplicate issue")))

    exit_code = pffi.process_no_commits_entries([NO_COMMITS_ENTRY], "fix_batches", execute=True)

    assert exit_code == 0


def test_process_no_commits_entries_reports_error_on_open_issue_failure(monkeypatch):
    from gitops.git_gh_ops import GitOpError

    monkeypatch.setattr(pffi, "_load_batch", lambda batch_dir, batch_id: BATCH)
    monkeypatch.setattr(pffi, "find_open_issue", lambda *a, **k: None)

    def fake_open_issue(title, body, repo_dir="."):
        raise GitOpError("gh: rate limited")

    monkeypatch.setattr(pffi, "open_issue", fake_open_issue)

    exit_code = pffi.process_no_commits_entries([NO_COMMITS_ENTRY], "fix_batches", execute=True)

    assert exit_code == 1


def test_process_no_commits_entries_noop_when_none_present():
    exit_code = pffi.process_no_commits_entries([PR_OPENED_ENTRY, ERROR_ENTRY], "fix_batches", execute=True)
    assert exit_code == 0


def test_main_missing_prs_json_is_a_clean_noop(tmp_path, monkeypatch, capsys):
    """The agent can die before writing prs.json at all (e.g. LLM-outage abort). The CI
    step now runs even when the agent step failed, so a missing file must be a normal
    nothing-to-report exit, not a crash."""
    monkeypatch.setattr("sys.argv", [
        "post_fix_failure_issue",
        "--prs-json", str(tmp_path / "does_not_exist.json"),
        "--batch-dir", str(tmp_path),
        "--execute",
    ])

    pffi.main()  # must not raise, must not sys.exit nonzero

    out = capsys.readouterr().out
    assert "does not exist" in out
    assert "nothing" in out.lower() or "no per-batch failures" in out


def test_a_held_back_container_batch_is_left_to_the_container_report(tmp_path, monkeypatch, capsys):
    (tmp_path / "b_c.json").write_text(json.dumps({"batch_id": "b_c", "batch_type": "container"}), encoding="utf-8")
    monkeypatch.setattr(pffi, "open_issue", lambda *a, **k: pytest.fail("opened an issue"))
    entries = [{"batch_id": "b_c", "status": "no_commits", "generation": {"method": "rag"}}]
    assert pffi.process_no_commits_entries(entries, str(tmp_path), execute=True) == 0
    assert "see the container report" in capsys.readouterr().out


def test_a_held_back_dependency_batch_still_gets_its_issue(tmp_path, monkeypatch):
    (tmp_path / "b_s.json").write_text(json.dumps({"batch_id": "b_s", "batch_type": "sca"}), encoding="utf-8")
    opened = []
    monkeypatch.setattr(pffi, "find_open_issue", lambda *a, **k: None)
    monkeypatch.setattr(pffi, "open_issue", lambda title, body, repo_dir=".": opened.append(title) or "url")
    entries = [{"batch_id": "b_s", "status": "no_commits", "generation": {"method": "rag"}}]
    pffi.process_no_commits_entries(entries, str(tmp_path), execute=True)
    assert len(opened) == 1

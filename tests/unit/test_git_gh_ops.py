"""Unit tests for gitops/git_gh_ops.py. Pure functions are tested
directly; revert_uncommitted's untracked-file fallback uses a real throwaway git repo
(tmp_git_repo) since its behaviour depends on real git plumbing."""

from __future__ import annotations

from pathlib import Path

import pytest

from gitops import config, git_gh_ops
from gitops.git_gh_ops import (
    GitOpError,
    _finding_ids,
    _safe_rel,
    batch_pr_body,
    batch_pr_title,
    batch_branch_name,
    comment_on_pr,
    convert_pr_to_draft,
    file_commit_message,
    find_open_issue,
    gate_file,
    open_issue,
    repo_path,
    revert_uncommitted,
)
from secrets_scan.gitleaks_gate import GitleaksError, ScanResult

pytestmark = pytest.mark.unit


# --------------------------------------------------------------------------------------
# batch_branch_name
# --------------------------------------------------------------------------------------

def test_batch_branch_name_valid():
    assert batch_branch_name({"batch_id": "asva_sast_e6919194_1"}) == "fix/asva_sast_e6919194_1"


def test_batch_branch_name_missing_id_raises():
    with pytest.raises(GitOpError):
        batch_branch_name({})


def test_batch_branch_name_rejects_spaces():
    with pytest.raises(GitOpError):
        batch_branch_name({"batch_id": "asva sast e6919194"})


def test_batch_branch_name_rejects_slash():
    with pytest.raises(GitOpError):
        batch_branch_name({"batch_id": "asva/sast/e6919194"})


def test_batch_branch_name_rejects_dotdot():
    with pytest.raises(GitOpError):
        batch_branch_name({"batch_id": "asva..sast"})


# --------------------------------------------------------------------------------------
# _safe_rel
# --------------------------------------------------------------------------------------

def test_safe_rel_normalises_path():
    assert _safe_rel("/app/routes/x.js") == "app/routes/x.js"


def test_safe_rel_rejects_traversal():
    with pytest.raises(GitOpError):
        _safe_rel("../../etc/passwd")


# --------------------------------------------------------------------------------------
# repo_path — FIX_PATH_PREFIX mapping
# --------------------------------------------------------------------------------------

def test_repo_path_with_prefix(monkeypatch):
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "target-apps/NodeGoat")
    assert repo_path("app/routes/x.js") == "target-apps/NodeGoat/app/routes/x.js"


def test_repo_path_without_prefix(monkeypatch):
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "")
    assert repo_path("app/routes/x.js") == "app/routes/x.js"


# --------------------------------------------------------------------------------------
# file_commit_message / _finding_ids
# --------------------------------------------------------------------------------------

def test_file_commit_message_shape():
    ff = {"batch_type": "sast", "path": "app/routes/x.js", "batch_id": "asva_sast_sha_1",
          "findings": [{}, {}]}
    msg = file_commit_message(ff)
    assert msg == "fix(security): sast remediation in app/routes/x.js (2 finding(s)) [asva_sast_sha_1]"


def test_finding_ids_prefers_cve_over_cwe_and_rule_id():
    findings = [{"identifiers": {"cve": "CVE-2022-1", "cwe": "CWE-1", "rule_id": "r1"}}]
    assert _finding_ids(findings) == "CVE-2022-1"


def test_finding_ids_falls_back_to_cwe_then_rule_id():
    assert _finding_ids([{"identifiers": {"cwe": "CWE-1"}}]) == "CWE-1"
    assert _finding_ids([{"identifiers": {"rule_id": "r1"}}]) == "r1"
    assert _finding_ids([{"identifiers": {}}]) == "-"


def test_finding_ids_empty_list_returns_dash():
    assert _finding_ids([]) == "-"


# --------------------------------------------------------------------------------------
# batch_pr_title / batch_pr_body
# --------------------------------------------------------------------------------------

BATCH = {"repo_name": "asva", "commit_sha": "e6919194abc", "batch_type": "sast",
          "batch_id": "asva_sast_e6919194_1"}
COMMITTED = [{"path": "app/routes/x.js", "batch_type": "sast",
              "findings": [{"identifiers": {"cve": "CVE-2022-1"}}]}]


def test_batch_pr_title_shape():
    title = batch_pr_title(BATCH, COMMITTED)
    assert title == "[ASVA] sast fixes for asva @ e6919194 - 1 file(s), 1 finding(s)"


def test_batch_pr_body_includes_never_auto_merge_banner():
    body = batch_pr_body(BATCH, COMMITTED, [], [])
    assert "ASVA does NOT auto-merge" in body


def test_batch_pr_body_lists_fixed_files():
    body = batch_pr_body(BATCH, COMMITTED, [], [])
    assert "app/routes/x.js" in body
    assert "CVE-2022-1" in body


def test_batch_pr_body_shows_review_notes_for_committed_files_only():
    batch = {**BATCH, "batch_type": "sca", "review_notes": {
        "package.json": ["`mongodb` ^2.1.18 -> 3.1.13 is a breaking (major) upgrade. `server.js:11`"],
        "other/package.json": ["not committed, so not shown"],
    }}
    committed = [{"path": "package.json", "batch_type": "sca", "findings": []}]
    body = batch_pr_body(batch, committed, [], [])
    assert "Check before merging" in body
    assert "`server.js:11`" in body
    assert "not committed, so not shown" not in body


def test_batch_pr_body_without_review_notes_has_no_check_section():
    assert "Check before merging" not in batch_pr_body(BATCH, COMMITTED, [], [])


def test_sast_pr_body_groups_duplicate_scanner_findings():
    committed = [{
        "path": "app/routes/contributions.js",
        "batch_type": "sast",
        "findings": [
            {"title": "Code Injection", "identifiers": {"cwe": "CWE-94"}},
            {"title": "Code Injection", "identifiers": {"cwe": "CWE-94"}},
            {"title": "Code Injection", "identifiers": {"cwe": "CWE-94"}},
        ],
    }]

    body = batch_pr_body(BATCH, committed, [], [])

    assert "| File | Security finding | Occurrences |" in body
    assert "| `app/routes/contributions.js` | Code Injection (CWE-94) | 3 |" in body
    assert "CWE-94, CWE-94, CWE-94" not in body


def test_sast_pr_body_uses_dynamic_scanner_title_without_static_mapping():
    committed = [{
        "path": "src/example.js",
        "batch_type": "sast",
        "findings": [{
            "title": "Scanner Supplied Dynamic Title",
            "identifiers": {"cwe": "CWE-999"},
        }],
    }]

    body = batch_pr_body(BATCH, committed, [], [])

    assert "Scanner Supplied Dynamic Title (CWE-999)" in body


def test_non_sast_pr_body_keeps_identifier_list():
    batch = {**BATCH, "batch_type": "sca"}
    committed = [{
        "path": "package.json",
        "batch_type": "sca",
        "findings": [{"identifiers": {"cve": "CVE-2026-1234"}}],
    }]

    body = batch_pr_body(batch, committed, [], [])

    assert "| File | Type | Findings |" in body
    assert "| `package.json` | sca | CVE-2026-1234 |" in body


def test_batch_pr_body_omits_blocked_and_failed_sections_when_empty():
    body = batch_pr_body(BATCH, COMMITTED, [], [])
    assert "Withheld by the secrets gate" not in body
    assert "Not fixed (tests still failing)" not in body


def test_batch_pr_body_includes_blocked_and_failed_sections_when_present():
    blocked = [{"path": "app/secret.js", "reason": "secrets detected"}]
    failed = [{"path": "app/broken.js", "reason": "tests failed after 3 attempt(s)"}]
    body = batch_pr_body(BATCH, COMMITTED, blocked, failed)
    assert "Withheld by the secrets gate" in body
    assert "app/secret.js" in body
    assert "Not fixed (tests still failing)" in body
    assert "app/broken.js" in body


# --------------------------------------------------------------------------------------
# gate_file — fails closed
# --------------------------------------------------------------------------------------

def test_gate_file_clean(monkeypatch):
    monkeypatch.setattr(git_gh_ops, "scan_files", lambda files: ScanResult(clean=True))
    clean, reason = gate_file("app/x.js", "content")
    assert clean is True
    assert reason is None


def test_gate_file_not_clean(monkeypatch):
    monkeypatch.setattr(git_gh_ops, "scan_files", lambda files: ScanResult(clean=False, leaks=[{}]))
    clean, reason = gate_file("app/x.js", "content")
    assert clean is False
    assert reason == "secrets detected"


def test_gate_file_fails_closed_on_gitleaks_error(monkeypatch):
    def raise_gitleaks_error(files):
        raise GitleaksError("gitleaks binary not found")

    monkeypatch.setattr(git_gh_ops, "scan_files", raise_gitleaks_error)
    clean, reason = gate_file("app/x.js", "content")
    assert clean is False
    assert "scan error" in reason


def test_gate_file_fails_closed_on_unexpected_exception(monkeypatch):
    def raise_generic(files):
        raise RuntimeError("boom")

    monkeypatch.setattr(git_gh_ops, "scan_files", raise_generic)
    clean, reason = gate_file("app/x.js", "content")
    assert clean is False
    assert "gate error" in reason


def _leak(value, line, rule="generic-api-key"):
    return {"value_id": value, "line": line, "rule": rule}


def _scans_by_content(monkeypatch, scans):
    """scan_files gives the result set for that file content."""
    monkeypatch.setattr(git_gh_ops, "scan_files", lambda files: scans[files[0]["content"]])


@pytest.fixture
def original(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "target-apps/AnyApp")
    path = tmp_path / "target-apps/AnyApp/app/x.py"
    path.parent.mkdir(parents=True)
    path.write_text("before", encoding="utf-8")
    return tmp_path


def test_gate_file_lets_through_secrets_the_file_already_had(monkeypatch, original):
    _scans_by_content(monkeypatch, {
        "before": ScanResult(clean=False, leaks=[_leak("a", 8), _leak("b", 12)]),
        "after": ScanResult(clean=False, leaks=[_leak("b", 20), _leak("a", 15)]),
    })
    found = {}
    assert gate_file("app/x.py", "after", str(original), found) == (True, None)
    assert found == {"app/x.py": "lines 15, 20 (`generic-api-key`)"}


def test_gate_file_stops_a_secret_the_fix_adds_and_names_only_that_one(monkeypatch, original):
    _scans_by_content(monkeypatch, {
        "before": ScanResult(clean=False, leaks=[_leak("a", 8)]),
        "after": ScanResult(clean=False, leaks=[_leak("a", 9), _leak("new", 30, "aws-access-token")]),
    })
    found = {}
    assert gate_file("app/x.py", "after", str(original), found) == (
        False, "secrets detected: line 30 (`aws-access-token`)")
    assert found == {}


def test_gate_file_stops_a_secret_in_a_file_with_no_original(monkeypatch, original):
    _scans_by_content(monkeypatch, {"after": ScanResult(clean=False, leaks=[_leak("a", 1)])})
    clean, reason = gate_file("app/new.py", "after", str(original))
    assert clean is False and "line 1" in reason


def test_gate_file_stops_when_a_leak_report_could_not_be_read(monkeypatch, original):
    _scans_by_content(monkeypatch, {
        "before": ScanResult(clean=False, leaks=[_leak("a", 8)]),
        "after": ScanResult(clean=False, leaks=[]),
    })
    assert gate_file("app/x.py", "after", str(original)) == (False, "secrets detected")


def test_gate_file_stops_when_the_original_report_could_not_be_read(monkeypatch, original):
    _scans_by_content(monkeypatch, {
        "before": ScanResult(clean=False, leaks=[]),
        "after": ScanResult(clean=False, leaks=[_leak("a", 8)]),
    })
    assert gate_file("app/x.py", "after", str(original))[0] is False


def test_gate_file_stops_when_the_original_cannot_be_scanned(monkeypatch, original):
    def scan(files):
        if files[0]["content"] == "before":
            raise GitleaksError("gitleaks failed")
        return ScanResult(clean=False, leaks=[_leak("a", 8)])

    monkeypatch.setattr(git_gh_ops, "scan_files", scan)
    clean, reason = gate_file("app/x.py", "after", str(original))
    assert clean is False and "scan error" in reason


def test_gate_file_does_not_scan_the_original_when_the_fix_is_clean(monkeypatch, original):
    calls = []
    monkeypatch.setattr(git_gh_ops, "scan_files", lambda files: calls.append(files) or ScanResult(clean=True))
    found = {}
    assert gate_file("app/x.py", "after", str(original), found) == (True, None)
    assert len(calls) == 1 and found == {}


def test_the_pr_warns_about_secrets_already_there_without_their_values():
    batch = {"batch_id": "b", "batch_type": "sast", "repo_name": "r", "commit_sha": "abc"}
    body = git_gh_ops.batch_pr_body(batch, [], [], [], {"app/x.py": "lines 8, 12 (`generic-api-key`)"})
    assert "Possible secrets already in this code" in body
    assert "- `app/x.py`: lines 8, 12 (`generic-api-key`)" in body
    assert "Possible secrets" not in git_gh_ops.batch_pr_body(batch, [], [], [])


# --------------------------------------------------------------------------------------
# revert_uncommitted — untracked (NEW) file fallback
# --------------------------------------------------------------------------------------

def test_revert_uncommitted_on_new_untracked_file_leaves_tree_clean(monkeypatch, tmp_git_repo):
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "")
    new_file = tmp_git_repo / "app" / "brand_new.js"
    new_file.write_text("module.exports = 'not yet committed';\n", encoding="utf-8")

    revert_uncommitted("app/brand_new.js", repo_dir=str(tmp_git_repo))

    assert not new_file.exists()
    import subprocess
    status = subprocess.run(
        ["git", "status", "--porcelain"], cwd=tmp_git_repo,
        capture_output=True, text=True, check=True,
    ).stdout
    assert status.strip() == ""


def test_revert_uncommitted_on_modified_tracked_file_restores_original(monkeypatch, tmp_git_repo):
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "")
    existing = tmp_git_repo / "app" / "existing.js"
    original_content = existing.read_text(encoding="utf-8")
    existing.write_text("module.exports = 'tampered';\n", encoding="utf-8")

    revert_uncommitted("app/existing.js", repo_dir=str(tmp_git_repo))

    assert existing.read_text(encoding="utf-8") == original_content


@pytest.mark.parametrize("content, changed", [
    ("module.exports = {};\n", False),             # identical
    ("module.exports = {};", False),               # the LLM dropped the final newline
    ("module.exports = {};  \r\n", False),         # only trailing whitespace or line ending differs
    ("module.exports = {a: 1};\n", True),          # a real edit
    ("module.exports = {a: 1};", True),            # a real edit without the final newline
])
def test_path_has_change_ignores_end_of_line_whitespace(monkeypatch, tmp_git_repo, content, changed):
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "")
    (tmp_git_repo / "app" / "existing.js").write_bytes(content.encode())
    assert git_gh_ops.path_has_change("app/existing.js", repo_dir=str(tmp_git_repo)) is changed


@pytest.mark.parametrize("draft, expected", [(True, True), (False, False)])
def test_open_pr_opens_a_draft_when_asked(monkeypatch, draft, expected):
    monkeypatch.delenv("ASVA_FIX_DRAFT", raising=False)
    commands = []
    monkeypatch.setattr(git_gh_ops, "_run", lambda cmd, repo_dir, input_text=None: commands.append(cmd) or "url")
    git_gh_ops.open_pr("t", "b", "branch", "main", draft=draft)
    assert ("--draft" in commands[0]) is expected


def test_path_has_change_counts_a_new_file(monkeypatch, tmp_git_repo):
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "")
    (tmp_git_repo / "app" / "brand_new.js").write_text("x\n", encoding="utf-8")
    assert git_gh_ops.path_has_change("app/brand_new.js", repo_dir=str(tmp_git_repo)) is True


def test_a_fix_that_only_drops_the_final_newline_opens_no_pr_and_leaves_the_tree_clean(monkeypatch, tmp_git_repo):
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "")
    monkeypatch.setattr(git_gh_ops, "create_branch", lambda branch, base, repo_dir=".": branch)
    monkeypatch.setattr(git_gh_ops, "open_pr", lambda *a, **k: pytest.fail("a whitespace-only change must not open a PR"))
    batch = {"batch_id": "asva_container_x", "batch_type": "container", "repo_name": "asva", "commit_sha": "abc",
             "files_to_fix": [{"file": "app/existing.js", "fix_type": "version_upgrade", "findings": []}]}

    result = git_gh_ops.submit_fix_batch(batch, [{"path": "app/existing.js", "content": "module.exports = {};"}],
                                         base_branch="main", repo_dir=str(tmp_git_repo), run_secret_scan=False)

    assert result["status"] == "no_commits"
    assert result["failed"] == [{"path": "app/existing.js", "reason": "fix made no change to the file"}]
    assert git_gh_ops._run(["git", "status", "--porcelain"], str(tmp_git_repo)) == ""


# --------------------------------------------------------------------------------------
# comment_on_pr -- surfacing the smoke result on the PR
# --------------------------------------------------------------------------------------

def _patch_run_capturing(monkeypatch, stdout: str = "https://github.com/o/r/pull/1#issuecomment-1"):
    calls = []

    def fake_run(cmd, cwd=".", input=None, capture_output=True, text=True):
        calls.append({"cmd": cmd, "cwd": cwd, "input": input})

        class FakeCompletedProcess:
            returncode = 0
            stderr = ""

        proc = FakeCompletedProcess()
        proc.stdout = stdout
        return proc

    monkeypatch.setattr(git_gh_ops.subprocess, "run", fake_run)
    return calls


def test_comment_on_pr_builds_expected_gh_command(monkeypatch):
    monkeypatch.setattr(config, "GITHUB_TARGET_REPO", "")
    calls = _patch_run_capturing(monkeypatch)

    url = comment_on_pr("42", "some **markdown** body", repo_dir="/repo")

    assert url == "https://github.com/o/r/pull/1#issuecomment-1"
    assert calls[0]["cmd"] == ["gh", "pr", "comment", "42", "--body-file", "-"]
    assert calls[0]["cwd"] == "/repo"
    assert calls[0]["input"] == "some **markdown** body"


def test_comment_on_pr_includes_target_repo_when_configured(monkeypatch):
    monkeypatch.setattr(config, "GITHUB_TARGET_REPO", "cyn-arena/asva")
    calls = _patch_run_capturing(monkeypatch)

    comment_on_pr("https://github.com/cyn-arena/asva/pull/7", "body")

    assert calls[0]["cmd"] == [
        "gh", "pr", "comment", "https://github.com/cyn-arena/asva/pull/7",
        "--body-file", "-", "--repo", "cyn-arena/asva",
    ]


def test_comment_on_pr_raises_giterror_on_failure(monkeypatch):
    monkeypatch.setattr(config, "GITHUB_TARGET_REPO", "")

    def fake_run(cmd, cwd=".", input=None, capture_output=True, text=True):
        class FakeCompletedProcess:
            returncode = 1
            stdout = ""
            stderr = "pull request not found"
        return FakeCompletedProcess()

    monkeypatch.setattr(git_gh_ops.subprocess, "run", fake_run)

    with pytest.raises(GitOpError, match="pull request not found"):
        comment_on_pr("999", "body")


# --------------------------------------------------------------------------------------
# convert_pr_to_draft -- structural block on a PR pr-check found broken/still-vulnerable
# --------------------------------------------------------------------------------------

def test_convert_pr_to_draft_builds_expected_gh_command(monkeypatch):
    monkeypatch.setattr(config, "GITHUB_TARGET_REPO", "")
    calls = _patch_run_capturing(monkeypatch, stdout="")

    convert_pr_to_draft("42", repo_dir="/repo")

    assert calls[0]["cmd"] == ["gh", "pr", "ready", "42", "--undo"]
    assert calls[0]["cwd"] == "/repo"


def test_convert_pr_to_draft_includes_target_repo_when_configured(monkeypatch):
    monkeypatch.setattr(config, "GITHUB_TARGET_REPO", "cyn-arena/asva")
    calls = _patch_run_capturing(monkeypatch, stdout="")

    convert_pr_to_draft("https://github.com/cyn-arena/asva/pull/7")

    assert calls[0]["cmd"] == [
        "gh", "pr", "ready", "https://github.com/cyn-arena/asva/pull/7",
        "--undo", "--repo", "cyn-arena/asva",
    ]


def test_convert_pr_to_draft_raises_giterror_on_failure(monkeypatch):
    monkeypatch.setattr(config, "GITHUB_TARGET_REPO", "")

    def fake_run(cmd, cwd=".", input=None, capture_output=True, text=True):
        class FakeCompletedProcess:
            returncode = 1
            stdout = ""
            stderr = "pull request not found"
        return FakeCompletedProcess()

    monkeypatch.setattr(git_gh_ops.subprocess, "run", fake_run)

    with pytest.raises(GitOpError, match="pull request not found"):
        convert_pr_to_draft("999")


# --------------------------------------------------------------------------------------
# open_issue / find_open_issue -- surfacing a no_commits batch that has no PR to warn on
# --------------------------------------------------------------------------------------

def test_open_issue_builds_expected_gh_command(monkeypatch):
    monkeypatch.setattr(config, "GITHUB_TARGET_REPO", "")
    calls = _patch_run_capturing(monkeypatch, stdout="https://github.com/o/r/issues/9")

    url = open_issue("some title", "some **markdown** body", repo_dir="/repo")

    assert url == "https://github.com/o/r/issues/9"
    assert calls[0]["cmd"] == [
        "gh", "issue", "create", "--title", "some title", "--body-file", "-",
    ]
    assert calls[0]["cwd"] == "/repo"
    assert calls[0]["input"] == "some **markdown** body"


def test_open_issue_includes_target_repo_when_configured(monkeypatch):
    monkeypatch.setattr(config, "GITHUB_TARGET_REPO", "cyn-arena/asva")
    calls = _patch_run_capturing(monkeypatch, stdout="https://github.com/cyn-arena/asva/issues/9")

    open_issue("title", "body")

    assert calls[0]["cmd"] == [
        "gh", "issue", "create", "--title", "title", "--body-file", "-",
        "--repo", "cyn-arena/asva",
    ]


def test_open_issue_raises_giterror_on_failure(monkeypatch):
    monkeypatch.setattr(config, "GITHUB_TARGET_REPO", "")

    def fake_run(cmd, cwd=".", input=None, capture_output=True, text=True):
        class FakeCompletedProcess:
            returncode = 1
            stdout = ""
            stderr = "field title cannot be blank"
        return FakeCompletedProcess()

    monkeypatch.setattr(git_gh_ops.subprocess, "run", fake_run)

    with pytest.raises(GitOpError, match="field title cannot be blank"):
        open_issue("", "body")


def test_find_open_issue_builds_expected_gh_command_and_returns_number(monkeypatch):
    monkeypatch.setattr(config, "GITHUB_TARGET_REPO", "")
    calls = _patch_run_capturing(monkeypatch, stdout='[{"number": 42}]')

    number = find_open_issue("asva_sca_bf49b76a in:title", repo_dir="/repo")

    assert number == "42"
    assert calls[0]["cmd"] == [
        "gh", "issue", "list", "--state", "open", "--search",
        "asva_sca_bf49b76a in:title", "--json", "number", "--limit", "1",
    ]
    assert calls[0]["cwd"] == "/repo"


def test_find_open_issue_returns_none_when_no_match(monkeypatch):
    monkeypatch.setattr(config, "GITHUB_TARGET_REPO", "")
    _patch_run_capturing(monkeypatch, stdout="[]")

    assert find_open_issue("nothing in:title") is None


def test_find_open_issue_includes_target_repo_when_configured(monkeypatch):
    monkeypatch.setattr(config, "GITHUB_TARGET_REPO", "cyn-arena/asva")
    calls = _patch_run_capturing(monkeypatch, stdout="[]")

    find_open_issue("q in:title")

    assert calls[0]["cmd"] == [
        "gh", "issue", "list", "--state", "open", "--search", "q in:title",
        "--json", "number", "--limit", "1", "--repo", "cyn-arena/asva",
    ]


def test_find_open_issue_by_title_ignores_titles_that_only_contain_the_words(monkeypatch):
    listed = '[{"number": 1, "title": "ASVA container report for app-two"}, {"number": 2, "title": "ASVA container report for app"}]'
    monkeypatch.setattr(git_gh_ops, "_run", lambda cmd, repo_dir, **k: listed)
    assert git_gh_ops.find_open_issue_by_title("ASVA container report for app") == "2"
    assert git_gh_ops.find_open_issue_by_title("ASVA container report for three") is None


def test_an_issue_still_opens_if_its_label_cannot_be_used(monkeypatch):
    calls = []

    def run(cmd, repo_dir, **kwargs):
        calls.append(cmd)
        if cmd[:3] == ["gh", "label", "create"]:
            raise git_gh_ops.GitOpError("no permission")
        return "url"

    monkeypatch.setattr(git_gh_ops, "_run", run)
    assert git_gh_ops.open_issue("t", "b", label="x") == "url"
    assert "--label" not in calls[-1]


def test_update_issue_replaces_the_body(monkeypatch):
    seen = {}
    monkeypatch.setattr(git_gh_ops, "_run", lambda cmd, repo_dir, **k: seen.update(cmd=cmd, **k) or "")
    git_gh_ops.update_issue("7", "new body")
    assert seen["cmd"][:4] == ["gh", "issue", "edit", "7"] and seen["input_text"] == "new body"


def test_each_misuse_fix_is_its_own_commit(monkeypatch):
    written, commits = [], []
    monkeypatch.setattr(git_gh_ops, "gate_file", lambda path, content, *a: (True, ""))
    monkeypatch.setattr(git_gh_ops, "write_file", lambda path, content, repo_dir: written.append((path, content)))
    monkeypatch.setattr(git_gh_ops, "path_has_change", lambda path, repo_dir: True)
    monkeypatch.setattr(git_gh_ops, "commit", lambda paths, message, repo_dir: commits.append((paths, message)))
    batch = {"batch_id": "b", "misuse_fixes": [
        {"test": "test_one", "files": [{"path": "a.js", "content": "1"}, {"path": "b.js", "content": "2"}]},
        {"test": "test_two", "files": [{"path": "c.js", "content": "3"}]}]}
    assert git_gh_ops._commit_misuse_fixes(batch, [], ".", True) == ["test_one", "test_two"]
    assert commits == [(["a.js", "b.js"], "fix(security): hole shown by test_one [b]"),
                       (["c.js"], "fix(security): hole shown by test_two [b]")]


def test_a_secret_in_one_file_drops_that_whole_misuse_fix(monkeypatch):
    commits, blocked = [], []
    monkeypatch.setattr(git_gh_ops, "gate_file", lambda path, content, *a: (path != "b.js", "secret found"))
    monkeypatch.setattr(git_gh_ops, "write_file", lambda path, content, repo_dir: pytest.fail("wrote a file"))
    monkeypatch.setattr(git_gh_ops, "commit", lambda *a: commits.append(a))
    batch = {"batch_id": "b", "misuse_fixes": [{"test": "t", "files": [{"path": "a.js", "content": "1"}, {"path": "b.js", "content": "2"}]}]}
    assert git_gh_ops._commit_misuse_fixes(batch, blocked, ".", True) == []
    assert commits == [] and blocked[0]["path"] == "b.js"


def test_only_a_misuse_fix_that_made_it_in_is_listed_as_having_secrets_already_there(monkeypatch):
    def gate(path, content, repo_dir, found):
        found[path] = "line 1 (`r`)"
        return (path != "stopped.js", "secret found")

    monkeypatch.setattr(git_gh_ops, "gate_file", gate)
    monkeypatch.setattr(git_gh_ops, "write_file", lambda *a: None)
    monkeypatch.setattr(git_gh_ops, "path_has_change", lambda path, repo_dir: True)
    monkeypatch.setattr(git_gh_ops, "commit", lambda *a: None)
    batch = {"batch_id": "b", "misuse_fixes": [
        {"test": "kept", "files": [{"path": "in.js", "content": "1"}]},
        {"test": "dropped", "files": [{"path": "out.js", "content": "2"}, {"path": "stopped.js", "content": "3"}]}]}
    already_there = {}
    git_gh_ops._commit_misuse_fixes(batch, [], ".", True, already_there)
    assert already_there == {"in.js": "line 1 (`r`)"}


def test_the_npm_pair_is_required_whatever_the_app(monkeypatch):
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "target-apps/AnyApp")
    with pytest.raises(git_gh_ops.GitOpError, match="both package.json and package-lock.json"):
        git_gh_ops._submit_dependency_pair({"batch_id": "b"}, [{"path": "package.json", "content": "{}"}], "main", ".", False, None)


def test_a_pr_that_is_one_of_two_choices_says_which_in_its_title():
    batch = {"batch_type": "sca", "repo_name": "repo", "commit_sha": "abc", "pr_choice": "safe upgrades, no major versions"}
    assert "sca fixes (safe upgrades, no major versions) for repo" in git_gh_ops.batch_pr_title(batch, [])
    del batch["pr_choice"]
    assert "sca fixes for repo" in git_gh_ops.batch_pr_title(batch, [])

"""Unit tests for gitops/post_pr_check_comment.py's Snyk rescan handling: reducing the
validation JSON to one rescan outcome, and treating a failed rescan as a failing result.
Offline -- gh calls are replaced, nothing is posted."""

from __future__ import annotations

import json
import sys

import pytest

from gitops import post_pr_check_comment
from gitops.post_pr_check_comment import rescan_outcome

pytestmark = pytest.mark.unit

JUNIT_CHECKS = [
    {"name": "app starts up", "kind": "app_start", "status": "passed", "detail": None},
    {"name": "test_profile_renders[chromium]", "kind": "smoke", "status": "passed", "detail": None},
]
INSTALLED = {"name": "scan dependencies installed", "kind": "scan_preparation",
             "status": "passed", "detail": None}
TARGETED_ABSENT = {"name": "targeted scanner findings absent from candidate",
                   "kind": "security_scan", "status": "passed", "detail": "[]"}
TARGETED_PRESENT = {"name": "targeted scanner findings absent from candidate",
                    "kind": "security_scan", "status": "failed",
                    "detail": json.dumps([["javascript/CodeInjection", "app/routes/contributions.js"]])}
RESCAN_NOT_COMPLETED = {"name": "candidate rescan completed", "kind": "security_scan",
                        "status": "failed", "detail": "Missing or failed scan/normalisation"}
INSTALL_FAILED = {"name": "scan dependencies installed", "kind": "scan_preparation",
                  "status": "failed", "detail": "npm install failed"}
WORKFLOW_FAILED = {"name": "candidate workflow completed", "kind": "pipeline", "status": "failed",
                   "detail": "Setup or candidate checking did not produce a complete result; "
                             "inspect the Actions log."}


def _validation(tmp_path, checks):
    path = tmp_path / "validation.json"
    path.write_text(json.dumps({"tested_sha": "abc", "result": "x", "checks": checks}),
                    encoding="utf-8")
    return path


def test_rescan_outcome_passed(tmp_path):
    outcome = rescan_outcome(_validation(tmp_path, [*JUNIT_CHECKS, INSTALLED, TARGETED_ABSENT]))
    assert outcome.status == "passed"


def test_rescan_outcome_ignores_failed_junit_checks(tmp_path):
    # Test failures are already their own rows; they must not change the rescan outcome.
    failed_smoke = dict(JUNIT_CHECKS[1], status="failed", detail="boom")
    outcome = rescan_outcome(_validation(tmp_path, [failed_smoke, INSTALLED, TARGETED_ABSENT]))
    assert outcome.status == "passed"


def test_rescan_outcome_still_present_lists_the_findings(tmp_path):
    outcome = rescan_outcome(_validation(tmp_path, [*JUNIT_CHECKS, INSTALLED, TARGETED_PRESENT]))
    assert outcome.status == "still_present"
    assert outcome.findings == [("javascript/CodeInjection", "app/routes/contributions.js")]


@pytest.mark.parametrize("checks,reason", [
    ([INSTALLED, RESCAN_NOT_COMPLETED], "Missing or failed scan/normalisation"),
    ([INSTALL_FAILED, RESCAN_NOT_COMPLETED], "npm install failed"),
    ([INSTALLED, TARGETED_ABSENT, WORKFLOW_FAILED], WORKFLOW_FAILED["detail"]),
    # The rescan step crashed before adding anything; only the JUnit checks and the
    # failure recorder's entry are left.
    ([WORKFLOW_FAILED], "No rescan result was recorded for this PR."),
    ([], "No rescan result was recorded for this PR."),
    ([INSTALLED, dict(TARGETED_ABSENT, status="skipped")], ""),
])
def test_rescan_outcome_incomplete(tmp_path, checks, reason):
    outcome = rescan_outcome(_validation(tmp_path, [*JUNIT_CHECKS, *checks]))
    assert outcome.status == "incomplete"
    assert outcome.reason == reason


def test_rescan_outcome_missing_file_fails_closed(tmp_path):
    outcome = rescan_outcome(tmp_path / "does-not-exist.json")
    assert outcome.status == "incomplete"
    assert outcome.reason == "No rescan result was saved for this PR."


@pytest.mark.parametrize("content", ["not json", "[]", '{"checks": null}', '{"no_checks": 1}'])
def test_rescan_outcome_unreadable_file_fails_closed(tmp_path, content):
    path = tmp_path / "validation.json"
    path.write_text(content, encoding="utf-8")
    outcome = rescan_outcome(path)
    assert outcome.status == "incomplete"
    assert outcome.reason == "The rescan result could not be read."


# --------------------------------------------------------------------------------------
# main(): a failed rescan is a failing result (exit code + draft conversion)
# --------------------------------------------------------------------------------------

SMOKE_ALL_PASS_XML = """<?xml version="1.0" encoding="utf-8"?>
<testsuite name="pytest" tests="1" failures="0" errors="0" skipped="0">
  <testcase classname="tests.e2e.browser.test_smoke" name="test_profile_renders[chromium]" time="1.0"/>
</testsuite>
"""


@pytest.fixture
def gh_calls(monkeypatch):
    calls = []
    monkeypatch.setattr(post_pr_check_comment, "comment_on_pr",
                        lambda pr, body, repo_dir=".": calls.append(("comment", body)) or "url")
    monkeypatch.setattr(post_pr_check_comment, "convert_pr_to_draft",
                        lambda pr, repo_dir=".": calls.append(("draft", pr)))
    return calls


def _run_main(monkeypatch, tmp_path, *extra):
    (tmp_path / "smoke.xml").write_text(SMOKE_ALL_PASS_XML, encoding="utf-8")
    (tmp_path / "matched.json").write_text(
        json.dumps({"changed_files": ["app/routes/contributions.js"], "matched_tests": []}),
        encoding="utf-8")
    monkeypatch.setattr(sys, "argv", [
        "post_pr_check_comment", "--smoke-xml", str(tmp_path / "smoke.xml"),
        "--matched-json", str(tmp_path / "matched.json"), "--pr", "7", "--sha", "abc",
        "--app-started", "true", "--execute", *extra])
    post_pr_check_comment.main()


def test_main_without_rescan_json_is_unchanged(monkeypatch, tmp_path, gh_calls):
    _run_main(monkeypatch, tmp_path)  # all tests pass: no draft, no non-zero exit
    assert [kind for kind, _ in gh_calls] == ["comment"]
    assert "Security rescan" not in gh_calls[0][1]


def test_main_rescan_passed_is_not_failing(monkeypatch, tmp_path, gh_calls):
    path = _validation(tmp_path, [*JUNIT_CHECKS, INSTALLED, TARGETED_ABSENT])
    _run_main(monkeypatch, tmp_path, "--rescan-json", str(path))
    assert [kind for kind, _ in gh_calls] == ["comment"]
    assert "Security rescan (Snyk) | :white_check_mark: Passed" in gh_calls[0][1]


@pytest.mark.parametrize("checks", [[INSTALLED, TARGETED_PRESENT], [INSTALLED, RESCAN_NOT_COMPLETED]])
def test_main_failed_rescan_drafts_and_exits_non_zero(monkeypatch, tmp_path, gh_calls, checks):
    path = _validation(tmp_path, [*JUNIT_CHECKS, *checks])
    with pytest.raises(SystemExit) as exc:
        _run_main(monkeypatch, tmp_path, "--rescan-json", str(path))
    assert exc.value.code == 1
    assert [kind for kind, _ in gh_calls] == ["draft", "comment"]
    assert "Not ready to merge" in gh_calls[1][1]


def test_main_missing_rescan_json_fails_closed(monkeypatch, tmp_path, gh_calls):
    with pytest.raises(SystemExit) as exc:
        _run_main(monkeypatch, tmp_path, "--rescan-json", str(tmp_path / "missing.json"), "--no-draft")
    assert exc.value.code == 1
    assert [kind for kind, _ in gh_calls] == ["comment"]
    assert "| Security rescan (Snyk) | :x: Failed |" in gh_calls[0][1]


# --------------------------------------------------------------------------------------
# --validation-json: PyGoat's pre-merge comment, rendered from dashboard_evidence.py's record
# --------------------------------------------------------------------------------------

from scripts import dashboard_evidence as evidence

PYGOAT_SHA = "a" * 40


def _pygoat_validation(tmp_path, smoke_passed=True, **extra):
    """The record pygoat-pr-check.yml writes before commenting (commit_sha, no tested_sha)."""
    smoke = tmp_path / "smoke.json"
    smoke.write_text(json.dumps({"checks": [evidence.check("login reaches home", smoke_passed,
                                                           None if smoke_passed else "redirected")]}),
                     encoding="utf-8")
    report = evidence.validation(app="pygoat", batch_id="pygoat_sast_1", pr_url="https://x/pull/9",
                                 sha=PYGOAT_SHA, started=True, build_result="success",
                                 smoke_result="success" if smoke_passed else "failure",
                                 smoke_json=str(smoke))
    report.update(extra)
    path = tmp_path / "validation.json"
    path.write_text(json.dumps(report), encoding="utf-8")
    return path


def _run_validation_main(monkeypatch, path, *extra):
    monkeypatch.setattr(sys, "argv", ["post_pr_check_comment", "--validation-json", str(path),
                                      "--pr", "9", "--sha", PYGOAT_SHA, *extra])
    post_pr_check_comment.main()


def test_validation_comment_reads_commit_sha_when_tested_sha_absent(tmp_path):
    report = json.loads(_pygoat_validation(tmp_path).read_text(encoding="utf-8"))
    assert "tested_sha" not in report
    comment = post_pr_check_comment.format_validation_comment(report)
    assert f"Tested commit: `{PYGOAT_SHA}`" in comment
    assert "Ready to merge, pending review" in comment
    assert "| login reaches home | smoke | passed |" in comment


def test_validation_comment_lists_out_of_scope_checks_separately(tmp_path):
    out_of_scope = [{"name": "test_cmd_injection", "status": "failed", "detail": "still vulnerable",
                     "scope": "not_targeted_by_batch"}]
    report = json.loads(_pygoat_validation(tmp_path, out_of_scope_checks=out_of_scope)
                        .read_text(encoding="utf-8"))
    comment = post_pr_check_comment.format_validation_comment(report)
    assert "did not target" in comment
    assert "| test_cmd_injection | failed | still vulnerable |" in comment
    assert "Ready to merge" in comment  # out-of-scope rows never decide the result


def test_validation_main_passed_comments_without_draft(monkeypatch, tmp_path, gh_calls):
    _run_validation_main(monkeypatch, _pygoat_validation(tmp_path), "--execute")
    assert [kind for kind, _ in gh_calls] == ["comment"]
    assert "converted to a draft" not in gh_calls[0][1]


def test_validation_main_failed_drafts_then_comments_and_exits_non_zero(monkeypatch, tmp_path, gh_calls):
    with pytest.raises(SystemExit) as exc:
        _run_validation_main(monkeypatch, _pygoat_validation(tmp_path, smoke_passed=False), "--execute")
    assert exc.value.code == 1
    assert [kind for kind, _ in gh_calls] == ["draft", "comment"]
    assert "Not ready to merge" in gh_calls[1][1]
    assert "converted to a draft" in gh_calls[1][1]


def test_validation_main_no_draft_only_comments(monkeypatch, tmp_path, gh_calls):
    with pytest.raises(SystemExit):
        _run_validation_main(monkeypatch, _pygoat_validation(tmp_path, smoke_passed=False),
                             "--execute", "--no-draft")
    assert [kind for kind, _ in gh_calls] == ["comment"]
    assert "converted to a draft" not in gh_calls[0][1]


def test_validation_main_draft_failure_still_comments(monkeypatch, tmp_path, gh_calls):
    def refuse(pr, repo_dir="."):
        raise post_pr_check_comment.GitOpError("no permission")
    monkeypatch.setattr(post_pr_check_comment, "convert_pr_to_draft", refuse)
    with pytest.raises(SystemExit):
        _run_validation_main(monkeypatch, _pygoat_validation(tmp_path, smoke_passed=False), "--execute")
    assert [kind for kind, _ in gh_calls] == ["comment"]
    assert "converted to a draft" not in gh_calls[0][1]  # never claims a draft that didn't happen


def test_validation_main_dry_run_posts_nothing(monkeypatch, tmp_path, gh_calls):
    _run_validation_main(monkeypatch, _pygoat_validation(tmp_path, smoke_passed=False))
    assert gh_calls == []


def test_validation_main_rejects_a_different_candidate_sha(monkeypatch, tmp_path, gh_calls):
    path = _pygoat_validation(tmp_path)
    monkeypatch.setattr(sys, "argv", ["post_pr_check_comment", "--validation-json", str(path),
                                      "--pr", "9", "--sha", "b" * 40, "--execute"])
    with pytest.raises(SystemExit) as exc:
        post_pr_check_comment.main()
    assert exc.value.code == 2
    assert gh_calls == []
def test_new_findings_are_read_from_the_batch_file(tmp_path):
    path = tmp_path / "b.json"
    path.write_text(json.dumps({"new_before_pr": ["one"]}), encoding="utf-8")
    assert post_pr_check_comment.new_before_pr(str(path)) == ["one"]


@pytest.mark.parametrize("content", [None, "not json", "[]", "{}"])
def test_a_batch_file_with_nothing_readable_adds_nothing(tmp_path, content):
    path = tmp_path / "b.json"
    if content is not None:
        path.write_text(content, encoding="utf-8")
    assert post_pr_check_comment.new_before_pr(str(path)) == []


def test_no_batch_file_adds_nothing():
    assert post_pr_check_comment.new_before_pr(None) == []


def test_a_dropped_misuse_fix_is_marked_on_its_test_only(tmp_path):
    path = tmp_path / "b.json"
    path.write_text(json.dumps({"misuse_dropped": ["test_a"]}), encoding="utf-8")
    matched = [{"test_name": "test_a", "attempted": False}, {"test_name": "test_b", "attempted": False}]
    assert post_pr_check_comment.with_dropped_fixes(matched, str(path)) == [
        {"test_name": "test_a", "attempted": False, "fix_dropped": True},
        {"test_name": "test_b", "attempted": False}]
    assert post_pr_check_comment.with_dropped_fixes(matched, None) == matched


def test_main_new_findings_draft_and_say_so_but_do_not_fail_the_job(monkeypatch, tmp_path, gh_calls):
    path = tmp_path / "b.json"
    path.write_text(json.dumps({"new_before_pr": ["`a.py`: py/PT, high (1 before this fix, 2 now)"]}), encoding="utf-8")
    _run_main(monkeypatch, tmp_path, "--batch-file", str(path))  # no SystemExit
    assert [kind for kind, _ in gh_calls] == ["draft", "comment"]
    assert "Not ready to merge" in gh_calls[1][1] and "`a.py`: py/PT" in gh_calls[1][1]


def test_main_batch_file_with_nothing_new_changes_nothing(monkeypatch, tmp_path, gh_calls):
    path = tmp_path / "b.json"
    path.write_text("{}", encoding="utf-8")
    _run_main(monkeypatch, tmp_path, "--batch-file", str(path))
    assert [kind for kind, _ in gh_calls] == ["comment"] and "Ready to merge" in gh_calls[0][1]

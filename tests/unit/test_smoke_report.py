"""Unit tests for gitops/smoke_report.py -- junit-xml parsing and PR-comment
formatting, offline against sample XML (no pytest run, no gh)."""

from __future__ import annotations

import pytest

from gitops.smoke_report import (
    misuse_fails_pr,
    RescanResult,
    format_pr_check_comment,
    format_pr_comment,
    parse_junit_xml,
)

pytestmark = pytest.mark.unit

ALL_PASS_XML = """<?xml version="1.0" encoding="utf-8"?>
<testsuites>
  <testsuite name="pytest" tests="2" failures="0" errors="0" skipped="0">
    <testcase classname="tests.e2e.browser.test_smoke" name="test_login_redirects_to_dashboard" time="1.2"/>
    <testcase classname="tests.e2e.browser.test_smoke" name="test_profile_renders" time="0.8"/>
  </testsuite>
</testsuites>
"""

WITH_FAILURE_XML = """<?xml version="1.0" encoding="utf-8"?>
<testsuites>
  <testsuite name="pytest" tests="3" failures="1" errors="0" skipped="1">
    <testcase classname="tests.e2e.browser.test_smoke" name="test_login_redirects_to_dashboard" time="1.2"/>
    <testcase classname="tests.e2e.browser.test_smoke" name="test_learning_resources_link_reaches_offsite" time="0.4">
      <failure message="assert '/dashboard' == 'https://www.khanacademy.org/...'">AssertionError</failure>
    </testcase>
    <testcase classname="tests.e2e.browser.test_smoke" name="test_flaky_thing" time="0.1">
      <skipped message="not reachable"/>
    </testcase>
  </testsuite>
</testsuites>
"""

BARE_TESTSUITE_XML = """<?xml version="1.0" encoding="utf-8"?>
<testsuite name="pytest" tests="1" failures="0" errors="0" skipped="0">
  <testcase classname="x" name="test_one" time="0.1"/>
</testsuite>
"""


def test_parse_junit_xml_all_passed(tmp_path):
    p = tmp_path / "smoke.xml"
    p.write_text(ALL_PASS_XML, encoding="utf-8")

    result = parse_junit_xml(p)

    assert result.total == 2
    assert result.passed == 2
    assert result.failed == 0
    assert result.skipped == 0
    assert result.failures == []
    assert result.all_passed is True


def test_parse_junit_xml_with_failure_and_skip(tmp_path):
    p = tmp_path / "smoke.xml"
    p.write_text(WITH_FAILURE_XML, encoding="utf-8")

    result = parse_junit_xml(p)

    assert result.total == 3
    assert result.passed == 1
    assert result.failed == 1
    assert result.skipped == 1
    assert result.all_passed is False
    assert len(result.failures) == 1
    assert result.failures[0].name == "test_learning_resources_link_reaches_offsite"
    assert "khanacademy" in result.failures[0].message


def test_parse_junit_xml_accepts_bare_testsuite_root(tmp_path):
    p = tmp_path / "smoke.xml"
    p.write_text(BARE_TESTSUITE_XML, encoding="utf-8")

    result = parse_junit_xml(p)

    assert result.total == 1
    assert result.passed == 1
    assert result.all_passed is True


def test_format_pr_comment_all_passed(tmp_path):
    p = tmp_path / "smoke.xml"
    p.write_text(ALL_PASS_XML, encoding="utf-8")
    result = parse_junit_xml(p)

    comment = format_pr_comment(result, base_url="http://localhost:4001")

    assert "All smoke checks passed" in comment
    assert "http://localhost:4001" in comment
    assert "2 total" in comment
    assert "Failed checks" not in comment


def test_format_pr_comment_with_failure_lists_it(tmp_path):
    p = tmp_path / "smoke.xml"
    p.write_text(WITH_FAILURE_XML, encoding="utf-8")
    result = parse_junit_xml(p)

    comment = format_pr_comment(result)

    assert "Smoke checks failed" in comment
    assert "Failed checks" in comment
    assert "test_learning_resources_link_reaches_offsite" in comment


def test_all_passed_is_false_when_no_tests_ran():
    from gitops.smoke_report import SmokeResult

    result = SmokeResult(total=0, passed=0, failed=0, skipped=0)
    assert result.all_passed is False


# --------------------------------------------------------------------------------------
# format_pr_check_comment (pre-merge PR check)
# --------------------------------------------------------------------------------------

SMOKE_ALL_PASS_XML = """<?xml version="1.0" encoding="utf-8"?>
<testsuite name="pytest" tests="5" failures="0" errors="0" skipped="0">
  <testcase classname="tests.e2e.browser.test_smoke" name="test_login_redirects_to_dashboard[chromium]" time="1.0"/>
  <testcase classname="tests.e2e.browser.test_smoke" name="test_dashboard_loads_for_logged_in_user[chromium]" time="1.0"/>
  <testcase classname="tests.e2e.browser.test_smoke" name="test_normal_contribution_submits[chromium]" time="1.0"/>
  <testcase classname="tests.e2e.browser.test_smoke" name="test_profile_renders[chromium]" time="1.0"/>
  <testcase classname="tests.e2e.browser.test_smoke" name="test_learning_resources_link_reaches_offsite" time="1.0"/>
</testsuite>
"""

SMOKE_LEARNING_LINK_FAILED_XML = """<?xml version="1.0" encoding="utf-8"?>
<testsuite name="pytest" tests="5" failures="1" errors="0" skipped="0">
  <testcase classname="tests.e2e.browser.test_smoke" name="test_login_redirects_to_dashboard[chromium]" time="1.0"/>
  <testcase classname="tests.e2e.browser.test_smoke" name="test_dashboard_loads_for_logged_in_user[chromium]" time="1.0"/>
  <testcase classname="tests.e2e.browser.test_smoke" name="test_normal_contribution_submits[chromium]" time="1.0"/>
  <testcase classname="tests.e2e.browser.test_smoke" name="test_profile_renders[chromium]" time="1.0"/>
  <testcase classname="tests.e2e.browser.test_smoke" name="test_learning_resources_link_reaches_offsite" time="1.0">
    <failure message="assert '/' == 'https://www.khanacademy.org/...'">AssertionError</failure>
  </testcase>
</testsuite>
"""

MISUSE_SSJI_PASS_XML = """<?xml version="1.0" encoding="utf-8"?>
<testsuite name="pytest" tests="1" failures="0" errors="0" skipped="0">
  <testcase classname="tests.e2e.api.test_misuse_cases" name="test_ssji_eval_contributions" time="0.3"/>
</testsuite>
"""

MISUSE_IDOR_FAILED_XML = """<?xml version="1.0" encoding="utf-8"?>
<testsuite name="pytest" tests="1" failures="1" errors="0" skipped="0">
  <testcase classname="tests.e2e.api.test_misuse_cases" name="test_idor_allocations" time="0.3">
    <failure message="AssertionError: expected this to be fixed, but it still works: user1 requesting /allocations/3 (user2's id) should not surface user2's name">AssertionError</failure>
  </testcase>
</testsuite>
"""

SSJI_MATCH = {
    "test_name": "test_ssji_eval_contributions",
    "files": ["app/routes/contributions.js"],
    "case_id": "a1_ssji_eval",
    "label": "Code-injection fix (contributions form)",
    "when_fixed": "The unsafe input is now rejected instead of being executed.",
    "when_vulnerable": "This form still runs unsafe input as code instead of rejecting it.",
}

IDOR_MATCH = {
    "test_name": "test_idor_allocations",
    "files": ["app/routes/index.js"],
    "case_id": "a4_idor",
    "label": "Data-exposure check (/allocations)",
    "when_fixed": "A logged-in user can no longer view another user's private data by "
                  "changing the ID in the URL.",
    "when_vulnerable": "A logged-in user can still view another user's private data by "
                        "changing the ID in the URL.",
}


def _smoke_result(xml: str, tmp_path, name="smoke.xml"):
    p = tmp_path / name
    p.write_text(xml, encoding="utf-8")
    return parse_junit_xml(p)


def test_format_pr_check_comment_app_never_started(tmp_path):
    smoke = _smoke_result(SMOKE_ALL_PASS_XML, tmp_path)

    comment = format_pr_check_comment(
        smoke,
        short_sha="bf49b76a",
        changed_files=["package.json"],
        matched_tests=[],
        app_started=False,
    )

    assert "App starts up" in comment
    assert "Not ready to merge" in comment
    assert "never finished starting" in comment
    assert "break the app entirely" in comment
    assert "vulnerability this PR targets is still present" in comment
    # Nothing else should be reported once the app itself never came up.
    assert "Login, dashboard" not in comment


def test_format_pr_check_comment_no_matched_tests(tmp_path):
    smoke = _smoke_result(SMOKE_ALL_PASS_XML, tmp_path)

    comment = format_pr_check_comment(
        smoke,
        short_sha="bf49b76a",
        changed_files=["package.json"],
        matched_tests=[],
    )

    assert "bf49b76a" in comment
    assert "package.json" in comment
    assert "no security-behavior check applies" in comment
    assert "Ready to merge" in comment


def test_format_pr_check_comment_matched_and_fixed(tmp_path):
    smoke = _smoke_result(SMOKE_ALL_PASS_XML, tmp_path)
    misuse = _smoke_result(MISUSE_SSJI_PASS_XML, tmp_path, name="misuse.xml")

    comment = format_pr_check_comment(
        smoke,
        short_sha="bf49b76a",
        changed_files=["app/routes/contributions.js"],
        matched_tests=[SSJI_MATCH],
        misuse=misuse,
    )

    assert "Code-injection fix (contributions form)" in comment
    assert "Fixed" in comment
    assert "unsafe input is now rejected" in comment
    assert "Ready to merge" in comment


def test_format_pr_check_comment_matched_and_still_vulnerable(tmp_path):
    smoke = _smoke_result(SMOKE_ALL_PASS_XML, tmp_path)
    misuse = _smoke_result(MISUSE_IDOR_FAILED_XML, tmp_path, name="misuse.xml")

    comment = format_pr_check_comment(
        smoke,
        short_sha="bf49b76a",
        changed_files=["app/routes/index.js"],
        matched_tests=[IDOR_MATCH],
        misuse=misuse,
    )

    assert "Still vulnerable" in comment
    assert "can still view another user's private data" in comment
    assert "doesn't fix this specific issue" in comment
    assert "Not ready to merge" in comment
    assert "does not address" in comment


def test_format_pr_check_comment_learning_link_failure_has_specific_explanation(tmp_path):
    smoke = _smoke_result(SMOKE_LEARNING_LINK_FAILED_XML, tmp_path)

    comment = format_pr_check_comment(
        smoke,
        short_sha="bf49b76a",
        changed_files=["app/routes/index.js"],
        matched_tests=[],
    )

    assert '"Learning Resources" link' in comment
    assert "sends them back to the homepage instead" in comment
    assert "broke something in the app itself" in comment


def test_format_pr_check_comment_never_attempted_says_so(tmp_path):
    smoke = _smoke_result(SMOKE_ALL_PASS_XML, tmp_path)
    misuse = _smoke_result(MISUSE_IDOR_FAILED_XML, tmp_path, name="misuse.xml")
    idor_unasked = dict(IDOR_MATCH, attempted=False,
                        why_no_attempt="The scanner could not detect this bug (a missing "
                                        "permission check).")

    comment = format_pr_check_comment(
        smoke,
        short_sha="bf49b76a",
        changed_files=["app/routes/index.js"],
        matched_tests=[idor_unasked],
        misuse=misuse,
    )

    assert "The scanner could not detect this bug (a missing permission check)." in comment
    assert ("This was included because this PR edits the file `app/routes/index.js`, "
            "and it still requires its own fix") in comment
    assert "never attempted to fix the Data-exposure check (/allocations) issue" in comment
    # the ambiguous legacy wording must be gone once attempted-info is present
    assert "touches a related file but doesn't fix" not in comment


def test_format_pr_check_comment_says_a_dropped_fix_was_tried(tmp_path):
    smoke = _smoke_result(SMOKE_ALL_PASS_XML, tmp_path)
    misuse = _smoke_result(MISUSE_IDOR_FAILED_XML, tmp_path, name="misuse.xml")
    dropped = dict(IDOR_MATCH, attempted=False, fix_dropped=True,
                   why_no_attempt="The scanner could not detect this bug (a missing permission check).")

    comment = format_pr_check_comment(
        smoke,
        short_sha="bf49b76a",
        changed_files=["app/routes/index.js"],
        matched_tests=[dropped],
        misuse=misuse,
    )

    assert "Still vulnerable, fix tried and dropped" in comment
    assert "ASVA tried to fix the Data-exposure check (/allocations) issue" in comment
    assert "never attempted" not in comment and "not attempted" not in comment
    assert "could not detect" not in comment
    assert "Ready to merge" in comment  # as with one not attempted: this PR didn't cause it


def test_format_pr_check_comment_attempted_but_failed_says_the_fix_does_not_work(tmp_path):
    smoke = _smoke_result(SMOKE_ALL_PASS_XML, tmp_path)
    misuse_xml = """<?xml version="1.0" encoding="utf-8"?>
<testsuite name="pytest" tests="1" failures="1" errors="0" skipped="0">
  <testcase classname="tests.e2e.api.test_misuse_cases" name="test_ssji_eval_contributions" time="0.3">
    <failure message="AssertionError">AssertionError</failure>
  </testcase>
</testsuite>
"""
    misuse = _smoke_result(misuse_xml, tmp_path, name="misuse.xml")
    ssji_tried = dict(SSJI_MATCH, attempted=True, why_no_attempt="")

    comment = format_pr_check_comment(
        smoke,
        short_sha="bf49b76a",
        changed_files=["app/routes/contributions.js"],
        matched_tests=[ssji_tried],
        misuse=misuse,
    )

    assert "includes a fix aimed at this, but the check shows it doesn't work" in comment
    assert ("Its fix for the Code-injection fix (contributions form) issue does not work"
            in comment)
    assert "touches a related file but doesn't fix" not in comment


def test_format_pr_check_comment_mixed_result_summary_mentions_both(tmp_path):
    smoke = _smoke_result(SMOKE_ALL_PASS_XML, tmp_path)
    misuse_xml = """<?xml version="1.0" encoding="utf-8"?>
<testsuite name="pytest" tests="2" failures="1" errors="0" skipped="0">
  <testcase classname="tests.e2e.api.test_misuse_cases" name="test_ssji_eval_contributions" time="0.3"/>
  <testcase classname="tests.e2e.api.test_misuse_cases" name="test_idor_allocations" time="0.3">
    <failure message="AssertionError: expected this to be fixed, but it still works: user1 requesting /allocations/3 (user2's id) should not surface user2's name">AssertionError</failure>
  </testcase>
</testsuite>
"""
    misuse = _smoke_result(misuse_xml, tmp_path, name="misuse.xml")

    comment = format_pr_check_comment(
        smoke,
        short_sha="d14693eb",
        changed_files=["app/routes/index.js", "app/routes/contributions.js"],
        matched_tests=[SSJI_MATCH, IDOR_MATCH],
        misuse=misuse,
    )

    assert "1 of the security fixes in this PR are good" in comment
    assert "does not address the Data-exposure check (/allocations) issue" in comment


def test_format_pr_check_comment_fixed_but_broke_something_a10_shape(tmp_path):
    smoke = _smoke_result(SMOKE_LEARNING_LINK_FAILED_XML, tmp_path)
    misuse = _smoke_result(MISUSE_SSJI_PASS_XML, tmp_path, name="misuse.xml")

    comment = format_pr_check_comment(
        smoke,
        short_sha="bf49b76a",
        changed_files=["app/routes/contributions.js"],
        matched_tests=[SSJI_MATCH],
        misuse=misuse,
    )

    assert "does close the vulnerability it targets" in comment
    assert "can't be merged as-is" in comment
    assert "vulnerability remains unfixed in the app until someone writes a better fix" in comment
    assert "Not ready to merge" in comment


def test_format_pr_check_comment_marked_draft_appends_notice(tmp_path):
    smoke = _smoke_result(SMOKE_LEARNING_LINK_FAILED_XML, tmp_path)

    comment = format_pr_check_comment(
        smoke,
        short_sha="bf49b76a",
        changed_files=["app/routes/index.js"],
        matched_tests=[],
        marked_draft=True,
    )

    assert "converted to a draft so it can't be merged by accident" in comment
    assert "Mark it \"Ready for review\" only after a person has resolved the problem above" in comment


def test_format_pr_check_comment_not_marked_draft_omits_notice(tmp_path):
    smoke = _smoke_result(SMOKE_LEARNING_LINK_FAILED_XML, tmp_path)

    comment = format_pr_check_comment(
        smoke,
        short_sha="bf49b76a",
        changed_files=["app/routes/index.js"],
        matched_tests=[],
    )

    assert "converted to a draft" not in comment


# --------------------------------------------------------------------------------------
# format_pr_check_comment with the Snyk rescan row
# --------------------------------------------------------------------------------------

RESCAN_PASSED = RescanResult("passed")
RESCAN_STILL_PRESENT = RescanResult(
    "still_present", findings=[("javascript/CodeInjection", "app/routes/contributions.js")]
)
RESCAN_INCOMPLETE = RescanResult("incomplete", reason="Missing or failed scan/normalisation")


def _all_tests_pass_comment(tmp_path, **kwargs):
    smoke = _smoke_result(SMOKE_ALL_PASS_XML, tmp_path)
    misuse = _smoke_result(MISUSE_SSJI_PASS_XML, tmp_path, name="misuse.xml")
    return format_pr_check_comment(
        smoke,
        short_sha="bf49b76a",
        changed_files=["app/routes/contributions.js"],
        matched_tests=[SSJI_MATCH],
        misuse=misuse,
        **kwargs,
    )


def test_format_pr_check_comment_rescan_passed_adds_a_counted_row(tmp_path):
    without = _all_tests_pass_comment(tmp_path)
    comment = _all_tests_pass_comment(tmp_path, rescan=RESCAN_PASSED)

    # App start + core flows + learning link + one misuse case = 4 rows; the rescan is a 5th.
    assert "all 4 checks passed" in without
    assert "all 5 checks passed" in comment
    assert ("| Security rescan (Snyk) | :white_check_mark: Passed | The scanner no longer "
            "reports any of the issues this PR targets. |") in comment
    assert "every check passed" in comment


def test_format_pr_check_comment_tests_pass_but_rescan_still_finds_the_issue(tmp_path):
    comment = _all_tests_pass_comment(tmp_path, rescan=RESCAN_STILL_PRESENT)

    assert "Not ready to merge -- 1 of 5 checks failed" in comment
    assert "| Security rescan (Snyk) | :x: Still vulnerable |" in comment
    assert "`javascript/CodeInjection` in `app/routes/contributions.js`" in comment
    assert "still reports 1 of the issues this PR targets" in comment
    summary = next(line for line in comment.splitlines() if line.startswith("**Summary:**"))
    assert "every check passed" not in summary
    assert "security rescan still finds 1 of the issues this PR targets" in summary


def test_format_pr_check_comment_rescan_incomplete_fails_closed(tmp_path):
    comment = _all_tests_pass_comment(tmp_path, rescan=RESCAN_INCOMPLETE)

    assert "Not ready to merge -- 1 of 5 checks failed" in comment
    assert "| Security rescan (Snyk) | :x: Failed |" in comment
    assert "it is not confirmed that the issues are gone" in comment
    assert "Missing or failed scan/normalisation. See the Actions log." in comment
    assert "every check passed" not in comment
    assert "security rescan could not be completed" in comment


def test_format_pr_check_comment_rescan_not_provided_is_unchanged(tmp_path):
    for rescan_kwargs in ({}, {"rescan": None}):
        assert _all_tests_pass_comment(tmp_path, **rescan_kwargs) == (
            "## :white_check_mark: Ready to merge, pending review -- all 4 checks passed\n"
            "\n"
            "This was tested by building this PR's branch (`bf49b76a`) on its own and running "
            "it in isolation.\n"
            "\n"
            "| Check | Result | What we found |\n"
            "|---|---|---|\n"
            "| App starts up | :white_check_mark: Passed |  |\n"
            "| Login, dashboard, contributions, profile | :white_check_mark: Passed | Core site "
            "still works normally |\n"
            "| \"Learning Resources\" link | :white_check_mark: Passed |  |\n"
            "| Code-injection fix (contributions form) | :white_check_mark: Fixed | The unsafe "
            "input is now rejected instead of being executed. |\n"
            "\n"
            "**Summary:** every check passed. This fix looks safe to merge, pending review.\n"
            "\n"
            "_Tested on a throwaway copy of this branch, not the environment the team shares. "
            "A person still needs to review and merge this._\n"
        )


def test_format_pr_check_comment_app_never_started_still_shows_rescan(tmp_path):
    smoke = _smoke_result(SMOKE_ALL_PASS_XML, tmp_path)

    comment = format_pr_check_comment(
        smoke,
        short_sha="bf49b76a",
        changed_files=["package.json"],
        matched_tests=[],
        app_started=False,
        rescan=RESCAN_PASSED,
    )

    assert "Not ready to merge -- 1 of 2 checks failed" in comment
    assert "| Security rescan (Snyk) | :white_check_mark: Passed |" in comment
    assert "the security rescan below checks the code itself" in comment
    assert "Login, dashboard" not in comment


def test_format_pr_check_comment_rescan_lists_five_findings_then_counts_the_rest(tmp_path):
    findings = [(f"rule/{i}", f"app/file{i}.js") for i in range(7)]

    comment = _all_tests_pass_comment(tmp_path, rescan=RescanResult("still_present", findings=findings))

    assert "still reports 7 of the issues" in comment
    assert "`rule/4` in `app/file4.js`, and 2 more." in comment
    assert "rule/5" not in comment


def test_format_pr_check_comment_rescan_detail_cannot_break_the_table(tmp_path):
    rescan = RescanResult("incomplete", reason="scan failed | exit 2\nsee log")

    comment = _all_tests_pass_comment(tmp_path, rescan=rescan)

    row = next(line for line in comment.splitlines() if line.startswith("| Security rescan"))
    assert "scan failed \\| exit 2 see log." in row
    assert row.endswith(" |")


def test_a_hole_the_pr_did_not_attempt_is_listed_but_does_not_stop_it(tmp_path):
    smoke = _smoke_result(SMOKE_ALL_PASS_XML, tmp_path)
    misuse = _smoke_result(MISUSE_IDOR_FAILED_XML, tmp_path, name="misuse.xml")
    comment = format_pr_check_comment(
        smoke, short_sha="bf49b76a", changed_files=["app/routes/index.js"],
        matched_tests=[dict(IDOR_MATCH, attempted=False)], misuse=misuse,
    )
    assert "Ready to merge, pending review" in comment and "Not ready to merge" not in comment
    assert "Still vulnerable, not attempted by this PR:** Data-exposure check (/allocations)" in comment
    assert ":warning: Still vulnerable, not attempted" in comment
    assert not misuse_fails_pr(misuse, [dict(IDOR_MATCH, attempted=False)])


@pytest.mark.parametrize("flags", [{"attempted": True}, {"attempted": None}, {}], ids=["attempted", "unknown", "no flag"])
def test_a_failed_check_the_pr_attempted_or_might_have_still_stops_it(tmp_path, flags):
    smoke = _smoke_result(SMOKE_ALL_PASS_XML, tmp_path)
    misuse = _smoke_result(MISUSE_IDOR_FAILED_XML, tmp_path, name="misuse.xml")
    matched = [dict(IDOR_MATCH, **flags)]
    comment = format_pr_check_comment(smoke, short_sha="bf49b76a", changed_files=["app/routes/index.js"],
                                      matched_tests=matched, misuse=misuse)
    assert "Not ready to merge" in comment and "not attempted by this PR" not in comment
    assert misuse_fails_pr(misuse, matched)


def test_misuse_results_with_no_tests_in_them_still_count_against_the_pr(tmp_path):
    empty = _smoke_result('<testsuite name="pytest" tests="0"></testsuite>', tmp_path, name="misuse.xml")
    assert misuse_fails_pr(empty, [])
    assert not misuse_fails_pr(None, [])


def _comment_with_new_findings(new_findings):
    return format_pr_check_comment(parse_junit_xml_text(SMOKE_ALL_PASS_XML), short_sha="abc", changed_files=[], matched_tests=[], new_findings=new_findings)


def parse_junit_xml_text(xml):
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as folder:
        path = Path(folder) / "smoke.xml"
        path.write_text(xml, encoding="utf-8")
        return parse_junit_xml(str(path))


def test_new_findings_stop_the_comment_saying_ready_even_when_every_test_passed():
    comment = _comment_with_new_findings(["`a.py`: py/PT, high (1 before this fix, 2 now)"])
    assert "Not ready to merge -- 1 of" in comment and "Ready to merge" not in comment
    assert "New findings (scan before this PR)" in comment and "`a.py`: py/PT" in comment
    assert "The scan before this PR also found new critical or high findings" in comment


def test_new_findings_rule_out_the_all_clear_summary(tmp_path):
    comment = _all_tests_pass_comment(tmp_path, new_findings=["`a.py`: py/PT, high (1 before this fix, 2 now)"])
    assert "every test passed, but the scan before this PR found new critical or high findings" in comment
    assert "looks safe to merge" not in comment and "every check passed" not in comment


def test_no_new_findings_leaves_the_comment_as_it_was():
    assert _comment_with_new_findings(None) == _comment_with_new_findings([])
    assert "Ready to merge, pending review" in _comment_with_new_findings(None)


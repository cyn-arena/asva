"""Unit tests for agent/pr_test_selector.py -- matching a fix batch's changed
files against the misuse-case suite's "# @a" annotations, offline (no pytest collection,
no live target)."""

from __future__ import annotations

import pytest

from agent.pr_test_selector import (
    TEST_CASE_LABELS,
    batch_changed_files,
    batch_rule_ids,
    build_match_report,
    matching_tests,
)

pytestmark = pytest.mark.unit


SOURCE = '''\
# @a app/routes/contributions.js
def test_ssji_eval_contributions(user1_client):
    pass


# @a app/data/allocations-dao.js
# @a app/routes/allocations.js
def test_idor_allocations(user1_client, user2_client):
    pass


def test_no_annotation(user1_client):
    pass
'''


def test_batch_changed_files_reads_files_to_fix():
    batch = {"files_to_fix": [{"file": "app/routes/contributions.js"}, {"file": "package.json"}]}
    assert batch_changed_files(batch) == ["app/routes/contributions.js", "package.json"]


def test_batch_changed_files_empty_when_no_files_to_fix():
    assert batch_changed_files({}) == []


def test_matching_tests_single_file_overlap():
    result = matching_tests(["app/routes/contributions.js"], SOURCE)
    assert result == {"test_ssji_eval_contributions": ["app/routes/contributions.js"]}


def test_matching_tests_no_overlap_is_empty():
    assert matching_tests(["package.json"], SOURCE) == {}


def test_matching_tests_matches_more_than_one_test_when_files_overlap_both():
    result = matching_tests(
        ["app/routes/contributions.js", "app/routes/allocations.js"], SOURCE
    )
    assert set(result) == {"test_ssji_eval_contributions", "test_idor_allocations"}


def test_build_match_report_includes_case_label_for_known_test():
    report = build_match_report(["app/routes/contributions.js"], SOURCE)
    assert report["changed_files"] == ["app/routes/contributions.js"]
    assert len(report["matched_tests"]) == 1
    entry = report["matched_tests"][0]
    assert entry["test_name"] == "test_ssji_eval_contributions"
    assert entry["files"] == ["app/routes/contributions.js"]
    assert entry["case_id"] == "a1_ssji_eval"
    assert entry["label"] == "Code-injection fix (contributions form)"
    assert "rejected instead of being executed" in entry["when_fixed"]
    assert "runs unsafe input as code" in entry["when_vulnerable"]


def test_build_match_report_empty_when_nothing_matches():
    report = build_match_report(["package.json"], SOURCE)
    assert report["matched_tests"] == []


def test_build_match_report_unknown_test_falls_back_to_test_name_as_label():
    source = "# @a app/x.js\ndef test_unlisted_case():\n    pass\n"
    report = build_match_report(["app/x.js"], source)
    entry = report["matched_tests"][0]
    assert entry["case_id"] is None
    assert entry["label"] == "test_unlisted_case"
    assert entry["when_fixed"] == ""
    assert entry["when_vulnerable"] == ""


def test_batch_rule_ids_collects_across_files_and_skips_missing():
    batch = {"files_to_fix": [
        {"file": "a.js", "findings": [
            {"identifiers": {"rule_id": "javascript/OR"}},
            {"identifiers": {"rule_id": None}},
            {"identifiers": {}},
        ]},
        {"file": "b.js", "findings": [{"identifiers": {"rule_id": "javascript/CodeInjection"}}]},
    ]}
    assert batch_rule_ids(batch) == {"javascript/OR", "javascript/CodeInjection"}


def test_build_match_report_attempted_true_when_batch_has_the_cases_rule_id():
    report = build_match_report(
        ["app/routes/contributions.js"], SOURCE,
        rule_ids={"javascript/CodeInjection", "javascript/OR"},
    )
    entry = report["matched_tests"][0]
    assert entry["test_name"] == "test_ssji_eval_contributions"
    assert entry["attempted"] is True


def test_build_match_report_attempted_false_for_case_the_scanner_cannot_detect():
    # IDOR has no scanner rule at all -- a file-overlap match can never mean "attempted"
    report = build_match_report(
        ["app/routes/allocations.js"], SOURCE, rule_ids={"javascript/OR"}
    )
    entry = report["matched_tests"][0]
    assert entry["test_name"] == "test_idor_allocations"
    assert entry["attempted"] is False
    assert "scanner could not detect" in entry["why_no_attempt"]


def test_build_match_report_omits_attempted_when_rule_ids_not_given():
    report = build_match_report(["app/routes/contributions.js"], SOURCE)
    entry = report["matched_tests"][0]
    assert "attempted" not in entry
    assert "why_no_attempt" not in entry


def test_test_case_labels_cover_all_pr_validation_tests():
    assert set(TEST_CASE_LABELS) == {
        "test_idor_allocations",
        "test_missing_access_control_benefits",
        "test_unvalidated_redirect_learn",
        "test_ssji_eval_contributions",
        "test_redos_regex_bankrouting_still_validates",
        "test_ssrf_research_symbol_lookup",
        "test_development_zap_key_uses_environment_and_rescans_clean",
    }


def test_build_match_report_a_test_it_has_no_label_for_stays_in_scope():
    source = "# @a app/x.js\ndef test_another_apps_case():\n    pass\n"
    report = build_match_report(["app/x.js"], source, {"some/rule"})
    assert report["matched_tests"][0]["attempted"] is None

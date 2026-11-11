"""A finding a reviewer skipped (false positive, accepted risk, needs a manual fix) is left out of
the PR, so the PR check shows its security check as "skipped, reviewer decision" and does not count
it. The app's tests, and the fixes the PR did attempt, still decide the result.

agent/agent_loop.py writes the skipped findings into the batch file; agent/pr_test_selector.py,
gitops/smoke_report.py and gitops/post_pr_check_comment.py read them there."""

from __future__ import annotations

import json

import pytest

from agent import agent_loop
from agent.pr_test_selector import batch_rule_ids, build_match_report, reviewer_skipped_tests
from gitops import config
from gitops.post_pr_check_comment import format_validation_comment, reviewer_skipped
from gitops.smoke_report import format_pr_check_comment, misuse_fails_pr, parse_junit_xml

pytestmark = pytest.mark.unit

ZAP_TEST = "test_development_zap_key_uses_environment_and_rescans_clean"
ZAP_RULE = "javascript/HardcodedNonCryptoSecret"
SOURCE = f"# @a config/env/development.js\ndef {ZAP_TEST}():\n    pass\n"
SKIPPED = {"rule_id": ZAP_RULE, "file": "config/env/development.js", "line": 6,
           "decision": "false_positive", "note": "Dummy test key, never deployed."}


def _finding(rule, file, line):
    return {"finding_type": "sast", "title": "t", "description": "d", "severity": "high",
            "identifiers": {"rule_id": rule}, "location": {"file": file, "line": line}}


def _junit(tmp_path, name, cases):
    body = "".join(f'<testcase classname="c" name="{n}">' + ("" if ok else '<failure message="x">x</failure>')
                   + "</testcase>" for n, ok in cases)
    path = tmp_path / name
    path.write_text(f'<testsuite name="pytest" tests="{len(cases)}">{body}</testsuite>', encoding="utf-8")
    return parse_junit_xml(path)


SMOKE_OK = [("test_login_redirects_to_dashboard[chromium]", True), ("test_profile_renders[chromium]", True),
            ("test_learning_resources_link_reaches_offsite", True)]


# -- the agent: what it writes into the batch file ------------------------------------------------

def test_the_batch_file_gets_the_findings_a_reviewer_skipped(tmp_path, monkeypatch, fake_llm):
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "")
    for name in ("development.js", "index.js"):
        (tmp_path / name).write_text("original", encoding="utf-8")
    decisions = tmp_path / "decisions.json"
    decisions.write_text(json.dumps({"decisions": [{
        "finding_key": f"{ZAP_RULE}|development.js|6", "decision": "false_positive",
        "note": "Dummy test key, never deployed.", "decided_by": "r", "decided_at": "2026-11-10T00:00:00Z"}]}),
        encoding="utf-8")
    monkeypatch.setenv("ASVA_DECISIONS_PATH", str(decisions))
    batch_path = tmp_path / "b.json"
    batch_path.write_text(json.dumps({"batch_id": "b", "batch_type": "sast", "total_files": 2, "total_findings": 2, "files_to_fix": [
        {"file": "development.js", "fix_type": "code_change", "findings": [_finding(ZAP_RULE, "development.js", 6)]},
        {"file": "index.js", "fix_type": "code_change", "findings": [_finding("javascript/OR", "index.js", 72)]},
    ]}), encoding="utf-8")

    entry = agent_loop.process_batch(batch_path, str(tmp_path), use_repo_context=False)
    agent_loop.save_for_pr_check(batch_path, entry)

    saved = json.loads(batch_path.read_text(encoding="utf-8"))
    assert saved["reviewer_skipped"] == [{"rule_id": ZAP_RULE, "file": "development.js", "line": 6,
                                          "decision": "false_positive", "note": "Dummy test key, never deployed."}]
    assert batch_rule_ids(saved) == {"javascript/OR"}  # the skipped finding is not something the PR attempted


def test_a_finding_marked_while_the_agent_works_is_not_attempted_either():
    # Before the batch file is written (the test before the PR, agent/test_first.py).
    skipped = dict(_finding(ZAP_RULE, "development.js", 6), memory_applied={"decision": "false_positive", "note": ""})
    fixed = _finding("javascript/OR", "index.js", 72)
    assert batch_rule_ids({"files_to_fix": [{"file": "development.js", "findings": [skipped]},
                                            {"file": "index.js", "findings": [fixed]}]}) == {"javascript/OR"}


def test_the_misuse_round_is_told_which_tests_a_reviewer_skipped():
    skipped = dict(_finding(ZAP_RULE, "development.js", 6), memory_applied={"decision": "false_positive", "note": ""})
    batch = {"files_to_fix": [{"file": "development.js", "findings": [skipped]},
                              {"file": "index.js", "findings": [_finding("javascript/OR", "index.js", 72)]}]}
    assert reviewer_skipped_tests(batch) == {ZAP_TEST}
    # A rule the PR still fixes elsewhere is not skipped.
    batch["files_to_fix"][1]["findings"].append(_finding(ZAP_RULE, "index.js", 9))
    assert reviewer_skipped_tests(batch) == set()


def test_a_retry_fix_is_not_a_skip(tmp_path):
    finding = dict(_finding("javascript/OR", "index.js", 72), memory_applied={"decision": "retry_fix", "note": "hint"})
    assert agent_loop.reviewer_skipped({"files_to_fix": [{"file": "index.js", "findings": [finding]}]}) == []


# -- the PR check: which security checks count ---------------------------------------------------

def test_a_check_whose_findings_were_all_skipped_is_marked_with_the_decision():
    batch = {"files_to_fix": [{"file": "config/env/development.js",
                               "findings": [_finding(ZAP_RULE, "config/env/development.js", 6)]}],
             "reviewer_skipped": [SKIPPED]}
    report = build_match_report(["config/env/development.js"], SOURCE, rule_ids=batch_rule_ids(batch),
                                reviewer_skipped=batch["reviewer_skipped"])
    m = report["matched_tests"][0]
    assert m["attempted"] is False
    assert m["reviewer_decision"] == {"decision": "false_positive", "note": "Dummy test key, never deployed."}


def test_a_rule_the_pr_still_fixes_elsewhere_stays_attempted():
    # One finding of the rule skipped, another of the same rule still fixed: the PR attempted it.
    batch = {"files_to_fix": [{"file": "config/env/development.js", "findings": [
        _finding(ZAP_RULE, "config/env/development.js", 6), _finding(ZAP_RULE, "config/env/development.js", 9)]}],
             "reviewer_skipped": [SKIPPED]}
    report = build_match_report(["config/env/development.js"], SOURCE, rule_ids=batch_rule_ids(batch),
                                reviewer_skipped=batch["reviewer_skipped"])
    m = report["matched_tests"][0]
    assert m["attempted"] is True and "reviewer_decision" not in m


# -- the PR comment --------------------------------------------------------------------------------

def _zap_match(**extra):
    return {"test_name": ZAP_TEST, "files": ["config/env/development.js"], "label": "Hardcoded ZAP API key fix",
            "when_fixed": "fixed", "when_vulnerable": "still there.", **extra}


def test_a_skipped_check_says_so_and_does_not_fail_the_pr(tmp_path):
    smoke = _junit(tmp_path, "smoke.xml", SMOKE_OK)
    misuse = _junit(tmp_path, "misuse.xml", [(ZAP_TEST, False)])  # the key is still there, on purpose
    matched = [_zap_match(attempted=False, reviewer_decision={"decision": "false_positive",
                                                              "note": "Dummy test key, never deployed."})]
    assert not misuse_fails_pr(misuse, matched)
    comment = format_pr_check_comment(smoke, short_sha="abc", changed_files=["config/env/development.js"],
                                      matched_tests=matched, misuse=misuse, reviewer_skipped=[SKIPPED])
    assert "| Hardcoded ZAP API key fix | :fast_forward: Skipped, reviewer decision | " \
           "false positive: Dummy test key, never deployed. |" in comment
    assert "Ready to merge" in comment and "Still vulnerable" not in comment
    assert "skipped by reviewer decision, not counted" in comment
    assert f"`{ZAP_RULE}` in `config/env/development.js:6` -- false positive" in comment


def test_the_apps_own_tests_still_fail_the_pr(tmp_path):
    smoke = _junit(tmp_path, "smoke.xml", [(n, n != "test_profile_renders[chromium]") for n, _ in SMOKE_OK])
    matched = [_zap_match(attempted=False, reviewer_decision={"decision": "accepted_risk", "note": ""})]
    comment = format_pr_check_comment(smoke, short_sha="abc", changed_files=["config/env/development.js"],
                                      matched_tests=matched, misuse=_junit(tmp_path, "m.xml", [(ZAP_TEST, False)]))
    assert "Not ready to merge" in comment and "Skipped, reviewer decision" in comment


def test_an_attempted_fix_that_does_not_work_still_fails_the_pr(tmp_path):
    misuse = _junit(tmp_path, "misuse.xml", [(ZAP_TEST, False)])
    assert misuse_fails_pr(misuse, [_zap_match(attempted=True)])


def test_the_validation_comment_lists_the_skipped_findings_too(tmp_path):
    batch = tmp_path / "b.json"
    batch.write_text(json.dumps({"reviewer_skipped": [SKIPPED]}), encoding="utf-8")
    report = {"result": "passed", "checks": [{"name": "smoke", "kind": "smoke", "status": "passed"}],
              "commit_sha": "abc"}
    comment = format_validation_comment(report, reviewer_skipped=reviewer_skipped(str(batch)))
    assert "Ready to merge" in comment and "Skipped by reviewer decision" in comment


def test_without_decisions_nothing_changes(tmp_path):
    report = {"result": "passed", "checks": [{"name": "smoke", "kind": "smoke", "status": "passed"}],
              "commit_sha": "abc"}
    assert "reviewer" not in format_validation_comment(report, reviewer_skipped=reviewer_skipped(None))

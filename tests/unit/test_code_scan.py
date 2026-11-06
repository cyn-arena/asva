"""Scanning a code fix before its PR: what counts as something the fix added. No scanner runs here."""

from __future__ import annotations

import json
import subprocess

import pytest

from agent import agent_loop, code_scan
from gitops import config
from gitops.post_pr_summary import distinct

pytestmark = pytest.mark.unit


def flagged(flow, rule="py/PT", severity="high", line=None):
    return {"finding_type": "sast", "severity": severity, "title": "Path Traversal", "summary": "Input flows into open.",
            "identifiers": {"rule_id": rule}, "location": {"file": flow[0][0] if flow else "a.py", "line": line or (flow[-1][1] if flow else 1)},
            "code_flow": [{"file": f, "line": n} for f, n in flow]}


def found(*findings):
    return distinct(list(findings), "sast")


ROUTE = [("a.py", 27), ("a.py", 38), ("b.py", 8)]
OTHER = [("a.py", 27), ("a.py", 70), ("c.py", 3)]


def test_a_new_route_of_a_changed_file_counts_and_says_what_changed():
    new = code_scan.new_findings(found(flagged(ROUTE)), found(flagged(ROUTE), flagged(OTHER)), {"a.py"})
    assert code_scan.extra(new) == 1 and len(new) == 1
    assert (new[0]["rule"], new[0]["file"], new[0]["before"], new[0]["now"]) == ("py/PT", "a.py", 1, 2)
    assert new[0]["routes"] == ["a.py:27 -> a.py:38 -> b.py:8", "a.py:27 -> a.py:70 -> c.py:3"]


def test_a_rule_new_to_a_file_counts():
    new = code_scan.new_findings(found(), found(flagged(ROUTE, rule="py/Sqli")), {"a.py"})
    assert [item["rule"] for item in new] == ["py/Sqli"] and new[0]["before"] == 0


def test_moved_lines_and_one_route_reported_twice_are_not_new():
    wrapped = [("a.py", 45), ("a.py", 56), ("a.py", 32), ("b.py", 8)]
    after = found(flagged(wrapped, line=32), flagged(wrapped, line=56))
    assert code_scan.new_findings(found(flagged(ROUTE)), after, {"a.py"}) == []


def test_new_medium_and_low_are_left_to_the_table():
    after = found(flagged(ROUTE, severity="medium"), flagged(OTHER, rule="py/X", severity="low"))
    assert code_scan.new_findings(found(), after, {"a.py"}) == []


def test_a_new_critical_counts():
    assert code_scan.new_findings(found(), found(flagged(ROUTE, severity="critical")), {"a.py"})[0]["severity"] == "critical"


def test_a_route_through_no_changed_file_is_not_this_fix():
    assert code_scan.new_findings(found(), found(flagged(ROUTE)), {"elsewhere.py"}) == []


def test_a_route_that_only_passes_through_a_changed_file_counts():
    assert code_scan.new_findings(found(), found(flagged(ROUTE)), {"b.py"})


def test_a_finding_with_no_route_uses_its_own_file():
    new = code_scan.new_findings(found(), found(flagged([], rule="py/Key")), {"a.py"})
    assert new[0]["routes"] == ["a.py:1"] and code_scan.suspects(new, ["a.py", "z.py"]) == ["a.py"]


def test_only_changed_files_on_the_routes_are_retried():
    new = code_scan.new_findings(found(), found(flagged(ROUTE)), {"a.py", "b.py", "z.py"})
    assert code_scan.suspects(new, ["z.py", "b.py", "a.py"]) == ["b.py", "a.py"]


def test_the_llm_is_told_it_was_the_scanner_and_where():
    text = code_scan.reason(code_scan.new_findings(found(), found(flagged(ROUTE)), {"a.py"}))
    assert "security scanner" in text and "py/PT" in text and "route: a.py:27 -> a.py:38 -> b.py:8" in text
    assert "Input flows into open." in text and "0 route(s) before the fix, 1 now" in text


def test_the_routes_shown_are_capped(monkeypatch):
    monkeypatch.setattr(code_scan, "MAX_ROUTES_SHOWN", 1)
    new = code_scan.new_findings(found(), found(flagged(ROUTE), flagged(OTHER)), {"a.py"})
    assert len(new[0]["routes"]) == 1 and new[0]["now"] == 2


@pytest.mark.parametrize("content", [None, "not json", '{"no_findings": 1}'])
def test_todays_findings_that_cannot_be_read_are_none_not_empty(tmp_path, content):
    path = tmp_path / "findings.json"
    if content:
        path.write_text(content, encoding="utf-8")
    assert code_scan.today(str(path)) is None


def test_no_findings_path_is_none():
    assert code_scan.today(None) is None


@pytest.mark.parametrize("wrap", [lambda f: f, lambda f: {"findings": f}])
def test_todays_findings_are_read_in_either_shape(tmp_path, wrap):
    path = tmp_path / "findings.json"
    path.write_text(json.dumps(wrap([flagged(ROUTE)])), encoding="utf-8")
    assert list(code_scan.today(str(path))) == [("py/PT", "a.py", 1)]


SARIF = {"runs": [{"tool": {"driver": {"name": "SnykCode", "rules": [{"id": "py/PT", "shortDescription": {"text": "Path Traversal"},
         "defaultConfiguration": {"level": "error"}, "properties": {"cwe": ["CWE-23"]}}]}},
         "results": [{"ruleId": "py/PT", "level": "error", "message": {"text": "Input flows into open."},
                      "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 38}}}],
                      "codeFlows": [{"threadFlows": [{"locations": [
                          {"location": {"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 27}}}},
                          {"location": {"physicalLocation": {"artifactLocation": {"uri": "b.py"}, "region": {"startLine": 8}}}}]}]}]}]}]}


@pytest.fixture
def repo(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "target-apps/AnyApp")
    folder = tmp_path / "target-apps" / "AnyApp"
    folder.mkdir(parents=True)
    (folder / "a.py").write_text("today\n", encoding="utf-8")
    return tmp_path


def fake_snyk(monkeypatch, code=1, sarif=SARIF, seen=None):
    def run(command, cwd=None, **kwargs):
        if seen is not None:
            seen.update(command=command, cwd=cwd, content=(cwd / "a.py").read_text(encoding="utf-8"))
        if sarif is not None:
            path = next(a for a in command if a.startswith("--sarif-file-output=")).split("=", 1)[1]
            with open(path, "w", encoding="utf-8") as f:
                json.dump(sarif, f)
        return subprocess.CompletedProcess(command, code)
    monkeypatch.setattr(code_scan.subprocess, "run", run)


def test_the_scan_reads_the_fixed_code_and_gives_findings_the_table_can_compare(repo, monkeypatch):
    seen = {}
    fake_snyk(monkeypatch, seen=seen)
    result = code_scan.scan({"a.py": "fixed\n"}, str(repo))
    assert seen["content"] == "fixed\n" and seen["command"][:3] == ["snyk", "code", "test"]
    assert list(result) == [("py/PT", "a.py", 1)]
    assert (repo / "target-apps" / "AnyApp" / "a.py").read_text(encoding="utf-8") == "today\n"  # a copy was scanned


def test_a_clean_scan_is_an_empty_result_not_none(repo, monkeypatch):
    fake_snyk(monkeypatch, code=0, sarif={"runs": []})
    assert code_scan.scan({"a.py": "fixed\n"}, str(repo)) == {}


@pytest.mark.parametrize("code,sarif", [(2, SARIF), (3, None), (1, None)])
def test_a_scanner_that_could_not_run_is_none(repo, monkeypatch, code, sarif):
    fake_snyk(monkeypatch, code=code, sarif=sarif)
    assert code_scan.scan({"a.py": "fixed\n"}, str(repo)) is None


@pytest.mark.parametrize("error", [FileNotFoundError("snyk"), subprocess.TimeoutExpired("snyk", 1)])
def test_a_missing_or_stuck_scanner_is_none(repo, monkeypatch, error):
    def run(*args, **kwargs):
        raise error
    monkeypatch.setattr(code_scan.subprocess, "run", run)
    assert code_scan.scan({"a.py": "fixed\n"}, str(repo)) is None


def test_off_unless_the_app_turns_it_on(monkeypatch):
    monkeypatch.delenv("ASVA_SCAN_BEFORE_PR", raising=False)
    assert not code_scan.enabled()
    monkeypatch.setenv("ASVA_SCAN_BEFORE_PR", "1")
    assert code_scan.enabled()


def test_the_batch_file_gets_only_the_new_findings(tmp_path):
    path = tmp_path / "b.json"
    path.write_text(json.dumps({"batch_id": "s", "files_to_fix": [{"file": "on disk"}]}), encoding="utf-8")
    agent_loop.save_for_pr_check(path, {"batch": {"new_before_pr": ["one"], "misuse_dropped": ["test_a"], "files_to_fix": [{"file": "changed in memory"}]}})
    assert json.loads(path.read_text(encoding="utf-8")) == {"batch_id": "s", "files_to_fix": [{"file": "on disk"}], "new_before_pr": ["one"], "misuse_dropped": ["test_a"]}


def test_a_batch_with_nothing_new_is_left_alone(tmp_path):
    path = tmp_path / "b.json"
    path.write_text("as it was", encoding="utf-8")
    agent_loop.save_for_pr_check(path, {"batch": {}})
    assert path.read_text(encoding="utf-8") == "as it was"


def test_the_code_names_no_app():
    text = open(code_scan.__file__, encoding="utf-8").read().lower()
    for name in ("nodegoat", "pygoat"):
        assert name not in text

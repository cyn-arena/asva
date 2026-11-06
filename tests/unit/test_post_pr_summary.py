"""The table at the top of each fix PR: numbers only from the rescans, and missing ones say so."""

from __future__ import annotations

import json

import pytest

from agent import base_image, test_first
from gitops import post_pr_summary as summary

pytestmark = pytest.mark.unit


def finding(cve, package, severity="high", finding_type="sca", kind=None):
    return {"finding_type": finding_type, "severity": severity, "identifiers": {"cve": cve},
            "location": {"kind": kind, "package": f"{package}@1.0", "file": "f"}}


def write_run(tmp_path, today, rescans, app="app", tests=None):
    root = tmp_path / f"{app}-fix-output"
    (root / "fix_batches").mkdir(parents=True)
    (root / "findings").mkdir()
    (root / "findings" / "ranked_unified_findings.json").write_text(json.dumps(today), encoding="utf-8")
    entries = []
    for number, (batch_id, info) in enumerate(rescans.items(), 10):
        (root / "fix_batches" / f"{batch_id}.json").write_text(json.dumps({"batch_id": batch_id, "batch_type": info.get("type", "sca"), "pr_choice": info.get("choice")}), encoding="utf-8")
        entries.append({"batch_id": batch_id, "pr_url": f"https://x/pull/{number}"})
        if info.get("after") is not None:
            folder = tmp_path / f"{app}-after-fix-{batch_id}" / "findings"
            folder.mkdir(parents=True)
            (folder / "ranked_unified_findings.json").write_text(json.dumps(info["after"]), encoding="utf-8")
        result = (tests or {}).get(batch_id)
        if result:
            folder = tmp_path / f"{app}-validation-{batch_id}" / "validation"
            folder.mkdir(parents=True)
            (folder / f"{batch_id}.json").write_text(json.dumps({"result": result}), encoding="utf-8")
    (root / "prs.json").write_text(json.dumps(entries + [{"batch_id": "no_pr", "pr_url": None}]), encoding="utf-8")
    return summary.collect(tmp_path, app)


TODAY = [finding("C1", "a", "critical"), finding("H1", "b"), finding("H2", "c"), finding("L1", "d", "low")]


def two_prs(tmp_path, major_after, safe_after, tests=None):
    return write_run(tmp_path, TODAY, {"s_sca": {"after": major_after}, "s_sca_same_major": {"after": safe_after, "choice": "safe upgrades, no major versions"}}, tests=tests)


def block_for(items, batch_id):
    me, options, today, batch_type = next(i for i in items if i[0]["batch_id"] == batch_id)
    return summary.build_summary(me, options, today, batch_type)


def test_both_prs_show_all_options_with_this_one_marked(tmp_path):
    items = two_prs(tmp_path, [finding("L1", "d", "low")], [finding("C1", "a", "critical"), finding("L1", "d", "low")], {"s_sca": "passed", "s_sca_same_major": "passed"})
    major, safe = block_for(items, "s_sca"), block_for(items, "s_sca_same_major")
    assert "| Don't merge (today) | 1 | 2 | 0 | 1 | 4 | - | - |" in major
    assert "| **This PR: major version upgrades** | 0 | 0 | 0 | 1 | 1 | 0 | passed |" in major
    assert "| [#11](https://x/pull/11): safe upgrades, no major versions | 1 | 0 | 0 | 1 | 2 | 0 | passed |" in major
    assert "| **This PR: safe upgrades, no major versions** |" in safe and "| [#10](https://x/pull/10): major version upgrades |" in safe


def test_the_safe_option_comes_first(tmp_path):
    items = two_prs(tmp_path, [], [])
    assert [o["batch_id"] for o in items[0][1]] == ["s_sca_same_major", "s_sca"]


def test_a_major_pr_no_better_than_the_safe_one_is_called_out(tmp_path):
    items = two_prs(tmp_path, [finding("L1", "d", "low"), finding("N1", "e", "medium")], [finding("L1", "d", "low")])
    assert "safe PR is at least as good" in block_for(items, "s_sca")
    assert "safe PR is at least as good" in block_for(items, "s_sca_same_major")


def test_a_better_major_pr_says_by_how_much_and_still_asks_for_a_look(tmp_path):
    items = two_prs(tmp_path, [finding("L1", "d", "low")], [finding("C1", "a", "critical"), finding("H1", "b"), finding("L1", "d", "low")])
    assert "leaves 2 fewer findings (2 fewer critical or high)" in block_for(items, "s_sca") and "closer look" in block_for(items, "s_sca")


def test_new_ones_and_ones_rated_higher_are_told_apart(tmp_path):
    items = write_run(tmp_path, [finding("L1", "d", "low")], {"s": {"after": [finding("L1", "d", "high"), finding("N1", "e", "critical")]}})
    block = block_for(items, "s")
    assert "1 is new and 1 was already there, but the scanner rates it lower today" in block
    assert "| `e` | N1 | critical | **no, new** |" in block and "| `d` | L1 | high | yes |" in block


def test_several_new_ones_read_properly(tmp_path):
    items = write_run(tmp_path, [finding("L1", "d", "low"), finding("L2", "f", "low")], {"s": {"after": [
        finding("L1", "d", "high"), finding("L2", "f", "high"), finding("N1", "e", "critical"), finding("N2", "g")]}})
    assert "2 are new and 2 were already there, but the scanner rates them lower today" in block_for(items, "s")


def test_the_same_vulnerability_in_several_files_counts_once(tmp_path):
    items = write_run(tmp_path, [finding("H1", "b"), finding("H1", "b")], {"s": {"after": [finding("H1", "b"), finding("H1", "b")]}})
    assert "| Don't merge (today) | 0 | 1 | 0 | 0 | 1 | - | - |" in block_for(items, "s")


def test_a_missing_rescan_says_so_and_invents_nothing(tmp_path):
    items = two_prs(tmp_path, None, [finding("L1", "d", "low")])
    block = block_for(items, "s_sca")
    assert "rescan missing" in block and "at least as good" not in block and "left after this PR</summary>" not in block


def test_unknown_test_results_say_unknown(tmp_path):
    assert "| unknown |" in block_for(two_prs(tmp_path, [], []), "s_sca")


def test_a_container_pr_counts_only_os_packages(tmp_path):
    today = [finding("O1", "zlib", "critical", "container", "os_package"), finding("D1", "lib", "high", "container", "dependency")]
    after = [finding("D1", "lib", "high", "container", "dependency")]
    items = write_run(tmp_path, today, {"c": {"type": "container", "after": after, "choice": "OS upgrade"}})
    block = block_for(items, "c")
    assert "OS package findings left after merging" in block
    assert "| Don't merge (today) | 1 | 0 | 0 | 0 | 1 | - | - |" in block
    assert "| **This PR: OS upgrade** | 0 | 0 | 0 | 0 | 0 | 0 | unknown |" in block
    assert "No critical or high left" in block


def test_a_code_pr_stays_a_single_option(tmp_path):
    items = write_run(tmp_path, [finding("R1", "", "high", "sast")], {"c": {"type": "sast", "after": []}})
    assert len(items) == 1 and "code findings left after merging" in block_for(items, "c")


def test_a_long_list_is_cut(tmp_path, monkeypatch):
    monkeypatch.setattr(summary, "MAX_LISTED", 2)
    items = write_run(tmp_path, [], {"s": {"after": [finding(f"H{i}", f"p{i}") for i in range(5)]}})
    assert "3 more not shown" in block_for(items, "s")


def test_the_block_goes_on_top_and_a_rerun_replaces_it():
    first = summary.with_summary("the description", f"{summary.START}\nold\n{summary.END}\n")
    assert first.startswith(summary.START) and first.endswith("the description")
    second = summary.with_summary(first, f"{summary.START}\nnew\n{summary.END}\n")
    assert "old" not in second and "new" in second and second.count(summary.START) == 1 and second.endswith("the description")


def test_a_github_failure_warns_and_the_others_still_go(tmp_path, monkeypatch, capsys):
    two_prs(tmp_path, [], [])
    calls = []

    def gh(*args, stdin=None):
        calls.append(args)
        raise summary.subprocess.SubprocessError("gh failed")

    monkeypatch.setattr(summary, "_gh", gh)
    monkeypatch.setattr("sys.argv", ["prog", "--app", "app", "--artifacts", str(tmp_path), "--execute"])
    summary.main()
    assert capsys.readouterr().out.count("::warning::") == 2 and len(calls) == 2


def test_no_artifacts_warns_and_does_not_fail(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", ["prog", "--app", "app", "--artifacts", str(tmp_path)])
    summary.main()
    assert "::warning::" in capsys.readouterr().out


def test_the_labels_match_what_the_agent_puts_in_titles():
    assert summary.MAJOR_LABEL == test_first.MAJOR_LABEL
    assert summary.SAME_MAJOR_SUFFIX == test_first.SAME_MAJOR_SUFFIX
    assert base_image.PR_LABEL


def test_the_code_names_no_app():
    text = open(summary.__file__, encoding="utf-8").read().lower()
    for name in ("nodegoat", "pygoat", "mongo", "debian", "ubuntu"):
        assert name not in text


def test_each_place_a_code_rule_flags_counts_and_a_fix_that_moves_lines_is_not_new(tmp_path):
    def flagged(line):
        return {"finding_type": "sast", "severity": "high", "identifiers": {"rule_id": "py/Sqli"}, "location": {"file": "a.py", "line": line}}

    items = write_run(tmp_path, [flagged(10), flagged(20), flagged(30)], {"c": {"type": "sast", "after": [flagged(55), flagged(70)]}})
    block = block_for(items, "c")
    assert "| Don't merge (today) | 0 | 3 | 0 | 0 | 3 | - | - |" in block
    assert "| **This PR: this fix** | 0 | 2 | 0 | 0 | 2 | 0 | unknown |" in block
    assert "Each route the scanner traces counts once" in block


def code_finding(line, flow, rule="py/PT", file="a.py", severity="high"):
    return {"finding_type": "sast", "severity": severity, "identifiers": {"rule_id": rule}, "location": {"file": file, "line": line},
            "code_flow": [{"file": f, "line": n} for f, n in flow]}


OLD_ROUTE = [("a.py", 27), ("a.py", 38), ("b.py", 8)]
WRAPPED_ROUTE = [("a.py", 45), ("a.py", 56), ("a.py", 32), ("b.py", 8)]


def code_pr(tmp_path, today, after, targets, **outcome):
    root = tmp_path / "app-fix-output"
    write_run(tmp_path, today, {"c": {"type": "sast", "after": after}})
    batch = json.loads((root / "fix_batches" / "c.json").read_text(encoding="utf-8"))
    batch["files_to_fix"] = [{"file": "a.py", "findings": targets}]
    (root / "fix_batches" / "c.json").write_text(json.dumps(batch), encoding="utf-8")
    entries = json.loads((root / "prs.json").read_text(encoding="utf-8"))
    entries[0].update(outcome)
    (root / "prs.json").write_text(json.dumps(entries), encoding="utf-8")
    return block_for(summary.collect(tmp_path, "app"), "c")


def test_one_route_reported_at_two_lines_is_not_new_but_is_still_flagged(tmp_path):
    today = [code_finding(38, OLD_ROUTE)]
    block = code_pr(tmp_path, today, [code_finding(32, WRAPPED_ROUTE), code_finding(56, WRAPPED_ROUTE)], today)
    assert "| **This PR: this fix** | 0 | 1 | 0 | 0 | 1 | 0 | unknown |" in block
    assert "**no, new**" not in block and " new." not in block
    assert "**Still flagged after this fix.**" in block and "- `a.py`: py/PT" in block


def test_a_second_route_with_another_sink_is_new(tmp_path):
    today = [code_finding(38, OLD_ROUTE)]
    other = [("a.py", 27), ("a.py", 70), ("c.py", 3)]
    block = code_pr(tmp_path, today, [code_finding(38, OLD_ROUTE), code_finding(70, other)], [])
    assert "| **This PR: this fix** | 0 | 2 | 0 | 0 | 2 | 1 | unknown |" in block and "1 is new" in block
    assert "Still flagged" not in block


def test_a_target_that_is_gone_is_not_called_still_flagged(tmp_path):
    today = [code_finding(38, OLD_ROUTE), code_finding(90, [("a.py", 80), ("a.py", 90)])]
    block = code_pr(tmp_path, today, [code_finding(90, [("a.py", 85), ("a.py", 95)])], [today[0]])
    assert "Still flagged" not in block


def test_only_what_the_fix_left_is_counted_as_still_flagged(tmp_path):
    routes = [[("a.py", n), ("a.py", n + 1)] for n in (10, 20, 30)]
    today = [code_finding(r[1][1], r) for r in routes]
    block = code_pr(tmp_path, today, today[:2], today)
    assert "- `a.py`: py/PT (2 of them)" in block


def test_findings_the_scanner_traced_no_route_for_stay_one_per_line():
    found = summary.distinct([code_finding(10, []), code_finding(20, []), code_finding(20, [])], "sast")
    assert len(found) == 2


@pytest.mark.parametrize("outcome", ["blocked", "failed"])
def test_a_file_left_out_of_the_pr_is_not_called_still_flagged(tmp_path, outcome):
    today = [code_finding(38, OLD_ROUTE)]
    block = code_pr(tmp_path, today, today, today, **{outcome: [{"path": "a.py", "reason": "secrets detected"}]})
    assert "Still flagged" not in block


def test_a_missing_rescan_invents_no_still_flagged(tmp_path):
    today = [code_finding(38, OLD_ROUTE)]
    assert "Still flagged" not in code_pr(tmp_path, today, None, today)


def test_dependency_prs_have_no_still_flagged(tmp_path):
    items = write_run(tmp_path, [finding("H1", "b")], {"s": {"after": [finding("H1", "b")]}})
    assert "Still flagged" not in block_for(items, "s")


def test_severity_counts_add_up():
    found = summary.distinct([finding("A", "a", "critical"), finding("B", "b"), finding("C", "c", "low")], "sca")
    assert summary.severity_counts(found) == {"critical": 1, "high": 1, "medium": 0, "low": 1, "total": 3}


def test_scoped_npm_packages_keep_their_whole_name_and_stay_separate(tmp_path):
    today = [finding("CVE-1", "@babel/traverse"), finding("CVE-1", "@babel/core")]
    items = write_run(tmp_path, today, {"s": {"after": today}})
    block = block_for(items, "s")
    assert "| Don't merge (today) | 0 | 2 | 0 | 0 | 2 | - | - |" in block
    assert "| `@babel/traverse` | CVE-1 | high | yes |" in block and "| `@babel/core` | CVE-1 | high | yes |" in block


def test_a_pipe_in_a_name_does_not_break_the_table(tmp_path):
    odd = {"finding_type": "sast", "severity": "high", "identifiers": {"rule_id": "py/a|b"}, "location": {"file": "x|y.py"}}
    block = block_for(write_run(tmp_path, [odd], {"c": {"type": "sast", "after": [odd]}}), "c")
    assert "| `x\\|y.py` | py/a\\|b | high | yes |" in block

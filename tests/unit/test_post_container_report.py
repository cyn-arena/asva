"""The container report: every finding is accounted for, sources are quoted rather than guessed, and
a problem never fails the run. Nothing here names a particular app."""

from __future__ import annotations

import json

import pytest

from gitops import config, post_container_report as report
from gitops.git_gh_ops import GitOpError

pytestmark = pytest.mark.unit

PR = "https://github.com/o/r/pull/9"


def finding(kind, cve, package, severity="high", fixable=False, upgrade=None, file="image_1", finding_type="container", fid=None):
    return {"finding_id": fid or f"{cve}-{package}-{file}", "finding_type": finding_type, "severity": severity,
            "title": f"{cve} in {package}", "identifiers": {"cve": cve},
            "location": {"kind": kind, "file": file, "package": f"{package}@1.0", "image_name": "img", "image_tag": "1.2"},
            "remediation": {"fixable": fixable, "type": "version_upgrade" if fixable else "no_fix", "upgrade_to": upgrade}}


def advisory(cve, package, fixed="1.1", subscription_only=False, availability=None):
    return {"type": "advisory", "id": f"OS-{cve}", "package": package, "fixed_in": fixed,
            "subscription_only": subscription_only, "availability": availability}


def answer(*references, upgrades=None, warnings=()):
    return {"references": list(references), "warnings": list(warnings),
            "upgrades": [{"kind": "image", "name": "img", "current": "1.2", "ecosystem": "SomeOS 1", "status": "unknown"}]
            if upgrades is None else upgrades}


def sca_batch(*found):
    return {"batch_id": "b_sca", "batch_type": "sca", "files_to_fix": [{"file": "deps.txt", "findings": list(found)}]}


def container_batch(*found):
    return {"batch_id": "b_c", "batch_type": "container", "files_to_fix": [{"file": "compose.yml", "findings": list(found)}]}


# -- why each finding has no automatic fix ---------------------------------------------------------

def test_every_kind_of_finding_gets_its_own_reason():
    sent = finding("os_package", "CVE-1", "a", fixable=True)
    in_scan = {("CVE-5", "e")}
    assert report.reason(sent, {sent["finding_id"]}, in_scan) == "attempted"
    assert report.reason(finding("os_package", "CVE-2", "b"), set(), in_scan) == "no_fix"
    assert report.reason(finding("os_package", "CVE-3", "c", "medium", True), set(), in_scan) == "fix_below_severity"
    assert report.reason(finding("os_package", "CVE-4", "d", "high", True), set(), in_scan) == "fix_not_selected"
    assert report.reason(finding("dependency", "CVE-5", "e"), set(), in_scan) == "same_as_dependency_scan"
    assert report.reason(finding("dependency", "CVE-6", "f"), set(), in_scan) == "app_library"
    assert report.reason(finding("container_package", "CVE-7", "g"), set(), in_scan) == "inside_program"


def test_the_counts_add_up_to_every_container_finding():
    findings = [finding("os_package", f"CVE-{i}", "a", "low") for i in range(3)] + [
        finding("container_package", "CVE-9", "lib", file=f"/usr/bin/p{i}") for i in range(4)] + [
        finding("os_package", "CVE-20", "z", finding_type="sast")]
    body = report.build_report(findings, {}, [], "abcdef123", None)
    assert "**Findings:** 7 (0 critical, 4 high, 0 medium, 3 low)" in body
    assert "| OS package, the scanner knows no fix | 3 | 3 | 0 | 0 |" in body
    assert "| Inside a program that comes with the image | 4 | 1 | 0 | 4 |" in body  # one vulnerability, four programs


def test_repeats_of_the_dependency_scan_are_shown_as_repeats_with_the_pr_and_their_files():
    repeated = finding("dependency", "CVE-5", "lib", file="/app/deps.txt")
    other_file = finding("dependency", "CVE-5", "lib", file="/app/lab/deps.txt")
    scanned = finding("dependency", "CVE-5", "lib", finding_type="sca")
    body = report.build_report([repeated, other_file, scanned], {"b_sca": sca_batch(scanned)},
                               [{"batch_id": "b_sca", "pr_url": PR}], "abcdef123", None)
    assert f"Handled with the dependency findings: {PR}" in body
    assert "| `/app/deps.txt` | 1 |" in body and "| `/app/lab/deps.txt` | 1 |" in body


# -- where a fix is published ----------------------------------------------------------------------

def test_a_paid_fix_is_only_called_paid_when_the_source_says_so_and_is_quoted():
    f = finding("os_package", "CVE-1", "a")
    state, words = report.fix_availability(f, answer(advisory("CVE-1", "a", subscription_only=True, availability="Available with Some Pro")))
    assert state == "paid" and "Available with Some Pro" in words


def test_a_fix_in_the_standard_packages_can_be_picked_up_by_a_rebuild():
    f = finding("os_package", "CVE-1", "a")
    state, words = report.fix_availability(f, answer(advisory("CVE-1", "a", "1.5")))
    assert state == "standard" and "1.5" in words and "rebuild" in words


def test_an_older_rag_that_does_not_say_who_can_get_the_fix_is_not_called_free():
    reference = advisory("CVE-1", "a", "1.5")
    del reference["subscription_only"]
    state, words = report.fix_availability(finding("os_package", "CVE-1", "a"), answer(reference))
    assert state == "unknown" and "1.5" in words and "standard" not in words


def test_a_fix_only_in_a_newer_os_release_names_those_releases():
    reference = {"type": "os_release_fix", "id": "OS-CVE-1", "package": "a", "newer_release_fixes": {"13": "1.5"}}
    state, words = report.fix_availability(finding("os_package", "CVE-1", "a"), answer(reference))
    assert state == "newer" and "13 (1.5)" in words


def test_no_entry_for_this_release_says_none_is_listed():
    assert report.fix_availability(finding("os_package", "CVE-1", "a"), answer())[0] == "none"


def test_another_packages_fix_for_the_same_cve_does_not_count():
    assert report.fix_availability(finding("os_package", "CVE-1", "a"), answer(advisory("CVE-1", "other")))[0] == "none"


@pytest.mark.parametrize("rag", [None, answer(warnings=["OSV.dev unavailable for OS-CVE-1"]), answer(upgrades=[])],
                         ids=["rag off", "osv down", "base os unknown"])
def test_when_the_sources_cannot_say_it_is_unknown_not_a_guess(rag):
    assert report.fix_availability(finding("os_package", "CVE-1", "a"), rag)[0] == "unknown"


def test_the_rag_is_asked_only_about_critical_and_high_os_packages_once_each(monkeypatch):
    asked = {}
    monkeypatch.setattr(report.rag_client, "response", lambda found, fix_type: asked.update(found=found) or {})
    report._rag_answer([finding("os_package", "CVE-1", "a", "critical"), finding("os_package", "CVE-1", "a", file="other"),
                        finding("os_package", "CVE-2", "b", "low"), finding("container_package", "CVE-3", "c")])
    assert [f["identifiers"]["cve"] for f in asked["found"]] == ["CVE-1"]


def test_nothing_to_look_up_does_not_call_the_rag(monkeypatch):
    monkeypatch.setattr(report.rag_client, "response", lambda *a: pytest.fail("asked"))
    assert report._rag_answer([finding("os_package", "CVE-1", "a", "low")]) is None


def test_the_report_says_when_the_rag_was_not_available():
    assert "RAG was not available" in report.build_report([finding("os_package", "CVE-1", "a")], {}, [], "abcdef123", None)


def test_a_summary_counts_where_fixes_are_published():
    findings = [finding("os_package", "CVE-1", "a"), finding("os_package", "CVE-2", "b"), finding("os_package", "CVE-3", "c")]
    rag = answer(advisory("CVE-1", "a", subscription_only=True), advisory("CVE-2", "b"))
    assert "1 only with a paid subscription, 1 in the standard packages, 0 only in a newer OS release, 1 with no fix listed, 0 unknown" in report.build_report(findings, {}, [], "abcdef123", rag)


# -- the container fix -----------------------------------------------------------------------------

def test_a_held_back_batch_gives_its_reason():
    sent = finding("os_package", "CVE-1", "a", fixable=True)
    entries = [{"batch_id": "b_c", "status": "no_commits", "generation": {"method": "rag"},
                "failed": [{"path": "compose.yml", "reason": "no compatible image"}]}]
    body = report.build_report([sent], {"b_c": container_batch(sent)}, entries, "abcdef123", None)
    assert "Held back, no PR" in body and "no compatible image" in body
    assert "| Sent to the fix stage | 1 |" in body


def test_a_container_pr_is_linked():
    sent = finding("os_package", "CVE-1", "a", fixable=True)
    body = report.build_report([sent], {"b_c": container_batch(sent)}, [{"batch_id": "b_c", "pr_url": PR}], "abcdef123", None)
    assert f"A PR was opened: {PR}" in body


def test_with_nothing_sent_it_says_why():
    assert "Nothing was sent to the fix stage" in report.build_report([finding("os_package", "CVE-1", "a")], {}, [], "abcdef123", None)


def test_newer_image_lines_appear_only_when_the_rag_found_some():
    lines = {"kind": "image", "name": "img", "current": "1.2", "ecosystem": "SomeOS 1", "status": "newer_line_needed", "target": "2.0",
             "candidates": [{"tag": "2.0", "version": "2.0.1"}]}
    assert "Newer versions of this image" in report.build_report([finding("os_package", "CVE-1", "a")], {}, [], "abcdef123", answer(upgrades=[lines]))
    assert "Newer versions of this image" not in report.build_report([finding("os_package", "CVE-1", "a")], {}, [], "abcdef123", answer())


def test_a_huge_report_is_cut_to_fit_an_issue(monkeypatch):
    monkeypatch.setattr(report, "MAX_BODY_CHARS", 500)
    findings = [finding("os_package", f"CVE-{i}", f"p{i}") for i in range(40)]
    body = report.build_report(findings, {}, [], "abcdef123", None)
    assert len(body) < 600 and "Cut here" in body


# -- posting ---------------------------------------------------------------------------------------

@pytest.fixture
def gh(monkeypatch):
    state = {"existing": None, "opened": [], "updated": []}
    monkeypatch.setattr(report, "find_open_issue_by_title", lambda title, repo_dir=".": state["existing"])
    monkeypatch.setattr(report, "update_issue", lambda number, body, repo_dir=".": state["updated"].append((number, body)))
    monkeypatch.setattr(report, "open_issue", lambda title, body, repo_dir=".", label=None: state["opened"].append((title, label)) or "url")
    return state


def test_an_existing_report_is_updated_not_duplicated(gh):
    gh["existing"] = "7"
    report.post("title", "body", True)
    assert gh["updated"] == [("7", "body")] and gh["opened"] == []


def test_the_first_report_is_opened_with_its_label(gh):
    report.post("title", "body", True)
    assert gh["opened"] == [("title", report.LABEL)]


def test_no_findings_and_no_report_opens_nothing(gh):
    report.post("title", "body", False)
    assert gh["opened"] == []


def test_the_title_uses_the_apps_folder(monkeypatch):
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "target-apps/AnyApp")
    assert report.app_name("repo") == "AnyApp"
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "")
    assert report.app_name("repo") == "repo"


@pytest.fixture
def scan(tmp_path):
    (tmp_path / "fix_batches").mkdir()
    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps([finding("os_package", "CVE-1", "a")]), encoding="utf-8")
    return ["prog", "--findings", str(findings), "--batch-dir", str(tmp_path / "fix_batches"),
            "--prs-json", str(tmp_path / "missing.json"), "--commit-sha", "abcdef123", "--repo-name", "repo"]


def test_a_dry_run_prints_and_posts_nothing(scan, gh, monkeypatch, capsys):
    monkeypatch.setattr("sys.argv", scan)
    monkeypatch.setattr(report.rag_client, "response", lambda *a: None)
    report.main()
    assert "[DRY RUN]" in capsys.readouterr().out and gh["opened"] == []


@pytest.mark.parametrize("branch,posted", [("main", True), ("rel/26.11", True), ("feat/rag-service", False), ("", False)])
def test_only_official_branches_post_the_report(scan, gh, monkeypatch, capsys, branch, posted):
    monkeypatch.setattr("sys.argv", [*scan, "--execute"])
    monkeypatch.setattr(report.rag_client, "response", lambda *a: None)
    monkeypatch.setenv("GITHUB_REF_NAME", branch)
    monkeypatch.delenv("ASVA_REPORT_BRANCHES", raising=False)
    report.main()
    assert bool(gh["opened"]) is posted
    out = capsys.readouterr().out
    assert "Where a fix is published" in out or "OS packages, critical and high" in out  # in the log either way
    assert ("[NOT POSTED]" in out) is not posted


def test_a_team_can_choose_its_own_branches(scan, gh, monkeypatch):
    monkeypatch.setattr("sys.argv", [*scan, "--execute"])
    monkeypatch.setattr(report.rag_client, "response", lambda *a: None)
    monkeypatch.setenv("GITHUB_REF_NAME", "feat/rag-service")
    monkeypatch.setenv("ASVA_REPORT_BRANCHES", "develop feat/*")
    report.main()
    assert gh["opened"]


def test_a_github_failure_warns_and_does_not_fail_the_run(scan, gh, monkeypatch, capsys):
    def broken(*args, **kwargs):
        raise GitOpError("gh failed")

    monkeypatch.setattr("sys.argv", [*scan, "--execute"])
    monkeypatch.setenv("GITHUB_REF_NAME", "main")
    monkeypatch.setattr(report.rag_client, "response", lambda *a: None)
    monkeypatch.setattr(report, "find_open_issue_by_title", broken)
    report.main()
    assert "::warning::" in capsys.readouterr().out


def test_the_code_names_no_app():
    source = report.__file__
    text = open(source, encoding="utf-8").read().lower()
    for name in ("nodegoat", "pygoat", "vulnbank", "mongo", "ubuntu", "debian"):
        assert name not in text


# -- the options -------------------------------------------------------------------------------------

def _options(entries, findings=None):
    findings = findings or [finding("os_package", "CVE-1", "a", "critical"), finding("os_package", "CVE-2", "b"), finding("dependency", "CVE-3", "c")]
    batches = {"b_c": {"batch_id": "b_c", "batch_type": "container", "files_to_fix": []}}
    return report.build_report(findings, batches, entries, "abcdef123", None)


SCAN = {"name": "newer", "today": {}, "after": {"critical": 0, "high": 3, "medium": 0, "low": 0, "total": 5}}


def test_the_options_compare_staying_with_the_os_upgrade_pr():
    body = _options([{"batch_id": "b_c", "pr_url": PR, "generation": {"base_image_scan": SCAN}}])
    assert "| Stay on the current OS | 1 | 1 | 2 |" in body  # OS packages only
    assert f"| Merge the OS upgrade to `newer`: {PR} | 0 | 3 | 5 |" in body


def test_with_no_upgrade_to_offer_staying_is_the_only_option():
    body = _options([])
    assert "| Stay on the current OS | 1 | 1 | 2 |" in body and "Merge the OS upgrade" not in body


def test_an_upgrade_that_did_not_help_is_shown_as_not_opened():
    assert "no PR, as it does not help | 0 | 3 | 5 |" in _options([{"batch_id": "b_c", "status": "no_commits", "generation": {"method": "test_first", "base_image_scan": SCAN}}])


def test_an_upgrade_the_scan_could_not_check_says_so():
    scan = dict(SCAN, after=None)
    assert "not scanned" in _options([{"batch_id": "b_c", "pr_url": PR, "generation": {"base_image_scan": scan}}])


def test_no_os_findings_means_no_options_section():
    assert "Your options" not in _options([], [finding("dependency", "CVE-3", "c")])

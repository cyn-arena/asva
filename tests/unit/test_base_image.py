"""A newer base image: only what the OS data says helps, only named OS releases, never untested."""

from __future__ import annotations

import json

import pytest

from agent import app_check, base_image, rag_client, test_first
from agent.agent_loop import sca_upgrade_map
from agent.app_check import Result
from gitops import config, post_fix_failure_issue as pffi

pytestmark = pytest.mark.unit

DOCKERFILE = "# build\nFROM python:3.11-slim-bookworm\nRUN echo bookworm-notes\n"


def finding(cve, package, severity="high", fixable=False, kind="os_package"):
    return {"finding_id": f"{cve}-{package}", "finding_type": "container", "severity": severity, "identifiers": {"cve": cve},
            "location": {"kind": kind, "package": f"{package}@1.0"}, "remediation": {"fixable": fixable}}


def reference(cve, package, fixes, current="bookworm", names=None):
    names = {"13": "trixie", "14": "forky"} if names is None else names
    return {"type": "os_release_fix", "id": f"DEBIAN-{cve}", "package": package, "newer_release_fixes": fixes,
            "release_name": current, "newer_release_names": names}


# -- which options ---------------------------------------------------------------------------------

def test_the_from_line_changes_and_nothing_else():
    assert base_image.with_release(DOCKERFILE, "bookworm", "trixie") == "# build\nFROM python:3.11-slim-trixie\nRUN echo bookworm-notes\n"


@pytest.mark.parametrize("text", ["FROM python:3.11-slim\n", "FROM mybookworm:1\n", "RUN bookworm\n"])
def test_a_from_line_that_does_not_name_the_release_is_left_alone(text):
    assert base_image.with_release(text, "bookworm", "trixie") is None


def test_every_from_line_of_a_multi_stage_build_moves_together():
    text = "FROM python:3.11-bookworm AS build\nFROM --platform=linux/amd64 python:3.11-slim-bookworm\n"
    assert base_image.with_release(text, "bookworm", "trixie").count("trixie") == 2


def test_alpine_releases_are_swapped_whole():
    assert base_image.with_release("FROM node:20-alpine3.19\n", "alpine3.19", "alpine3.20") == "FROM node:20-alpine3.20\n"
    assert base_image.with_release("FROM node:20-alpine3.190\n", "alpine3.19", "alpine3.20") is None


def test_only_the_next_release_is_offered_as_later_ones_may_not_be_out_yet():
    answer = {"references": [reference("CVE-1", "zlib", {"13": "1.3", "14": "1.3"})]}
    assert [o["name"] for o in base_image.options([finding("CVE-1", "zlib")], answer, DOCKERFILE)] == ["trixie"]


def test_options_take_the_smallest_step_first_with_the_findings_each_fixes(monkeypatch):
    monkeypatch.setattr(base_image, "MAX_OPTIONS", 2)
    findings = [finding("CVE-1", "zlib"), finding("CVE-2", "bind9"), finding("CVE-3", "util-linux")]
    answer = {"references": [reference("CVE-1", "zlib", {"13": "1.3", "14": "1.3"}), reference("CVE-2", "bind9", {"13": "9.2"}),
                             reference("CVE-3", "util-linux", {"14": "2.4"})]}
    found = base_image.options(findings, answer, DOCKERFILE)
    assert [o["name"] for o in found] == ["trixie", "forky"]
    assert [f["identifiers"]["cve"] for f in found[0]["fixes"]] == ["CVE-1", "CVE-2"]
    assert "slim-trixie" in found[0]["text"]


def test_a_same_cve_in_another_package_does_not_count():
    assert base_image.options([finding("CVE-1", "zlib")], {"references": [reference("CVE-1", "other", {"13": "1"})]}, DOCKERFILE) == []


@pytest.mark.parametrize("answer", [None, {"references": []}, {"references": [reference("CVE-1", "zlib", {"13": "1"}, current=None)]},
                                    {"references": [reference("CVE-1", "zlib", {"13": "1"}, names={})]}],
                         ids=["rag off", "no data", "release name unknown", "newer name unknown"])
def test_when_the_sources_cannot_say_there_is_nothing_to_try(answer):
    assert base_image.options([finding("CVE-1", "zlib")], answer, DOCKERFILE) == []


# -- preparing the batch ---------------------------------------------------------------------------

@pytest.fixture
def source(tmp_path, monkeypatch):
    monkeypatch.setenv("ASVA_BASE_IMAGE_FIX", "1")
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "target-apps/AnyApp")
    monkeypatch.setattr(app_check, "supported", lambda: True)
    monkeypatch.setattr(rag_client, "enabled", lambda: True)
    monkeypatch.setattr(rag_client, "response", lambda found, fix_type: {"references": [reference("CVE-1", "zlib", {"13": "1.3"})]})
    app = tmp_path / "target-apps" / "AnyApp"
    app.mkdir(parents=True)
    (app / "Dockerfile").write_text(DOCKERFILE, encoding="utf-8")
    batches = tmp_path / "batches"
    batches.mkdir()
    (batches / "a.json").write_text(json.dumps({"batch_id": "a", "batch_type": "sca", "repo_name": "repo", "commit_sha": "abc"}), encoding="utf-8")
    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps([finding("CVE-1", "zlib"), finding("CVE-1", "zlib"), finding("CVE-9", "low", "low"),
                                    finding("CVE-8", "fixed", fixable=True), finding("CVE-7", "lib", kind="dependency")]), encoding="utf-8")
    return {"root": tmp_path, "batches": batches, "findings": str(findings)}


def _prepare(source, container_file="Dockerfile"):
    return base_image.prepare(source["batches"], str(source["root"]), source["findings"], container_file)


def test_a_batch_is_written_with_only_what_it_fixes(source):
    batch = json.loads(_prepare(source).read_text(encoding="utf-8"))
    assert batch["batch_id"] == "repo_container_abc" and batch["remediation_method"] == base_image.METHOD
    assert [f["identifiers"]["cve"] for f in batch["files_to_fix"][0]["findings"]] == ["CVE-1"]
    assert batch["total_findings"] == 1
    assert batch["pr_choice"] == base_image.PR_LABEL


def test_off_by_default(source, monkeypatch):
    monkeypatch.delenv("ASVA_BASE_IMAGE_FIX")
    assert _prepare(source) is None


def test_an_app_without_check_settings_gets_no_batch_as_it_could_not_be_tested(source, monkeypatch):
    monkeypatch.setattr(app_check, "supported", lambda: False)
    assert _prepare(source) is None


def test_a_container_batch_already_there_is_left_alone(source):
    (source["batches"] / "b.json").write_text(json.dumps({"batch_type": "container"}), encoding="utf-8")
    assert _prepare(source) is None


def test_a_missing_container_file_or_broken_findings_only_skips_it(source):
    assert _prepare(source, "Nope") is None
    Path_ = source["findings"]
    open(Path_, "w", encoding="utf-8").write("not json")
    assert _prepare(source) is None


# -- testing it ------------------------------------------------------------------------------------

TODAY = {"critical": 1, "high": 11, "medium": 16, "low": 209, "total": 237}
BETTER = {"critical": 0, "high": 14, "medium": 9, "low": 166, "total": 189}


def counts(critical, total):
    return {"critical": critical, "high": 0, "medium": 0, "low": 0, "total": total}


@pytest.mark.parametrize("after, opened", [(BETTER, True), (counts(2, 100), False), (counts(1, 237), False), (counts(1, 300), False), (counts(1, 236), True)],
                         ids=["this jump: high up but allowed", "critical up", "total the same", "total up", "same critical, total down"])
def test_rule_b(after, opened):
    assert base_image.worth_opening(TODAY, after) is opened


def _entry():
    option = {"release": "13", "name": "trixie", "text": "FROM a-trixie\n", "fixes": [finding("CVE-1", "zlib")]}
    second = {"release": "14", "name": "forky", "text": "FROM a-forky\n", "fixes": [finding("CVE-1", "zlib"), finding("CVE-2", "b")]}
    batch = {"batch_id": "repo_container_abc", "batch_type": "container", "remediation_method": base_image.METHOD, "total_findings": 1,
             "os_findings_today": TODAY,
             "base_image_options": [option, second],
             "files_to_fix": [{"file": "Dockerfile", "findings": option["fixes"], "finding_count": 1}]}
    return base_image.generate(batch)


@pytest.fixture
def check(monkeypatch):
    state = {"passes": lambda text: True, "seen": []}

    def fake(files, repo_dir=".", security_tests=None):
        text = files.get("Dockerfile", "")
        state["seen"].append(text)
        return Result(True, "passed") if state["passes"](text) else Result(False, "build", "no such image")

    monkeypatch.setenv("ASVA_TEST_FIRST", "1")
    monkeypatch.setattr(app_check, "supported", lambda: True)
    monkeypatch.setattr(app_check, "check", fake)
    monkeypatch.setattr(base_image, "scan_candidate", lambda text, path, repo_dir: BETTER)
    return state


def test_the_first_option_that_passes_is_the_pr_and_it_warns_the_reviewer(check):
    out = test_first.run(_entry(), ".", sca_upgrade_map)
    assert out["files"][0]["content"] == "FROM a-trixie\n" and len(check["seen"]) == 1
    assert "Review this carefully" in out["batch"]["rag_pr_text"]


def test_a_failing_option_moves_to_the_next_and_the_pr_claims_what_that_one_fixes(check):
    check["passes"] = lambda text: "forky" in text
    out = test_first.run(_entry(), ".", sca_upgrade_map)
    assert out["files"][0]["content"] == "FROM a-forky\n"
    assert out["batch"]["files_to_fix"][0]["finding_count"] == 2 and out["batch"]["total_findings"] == 2


def test_nothing_passing_means_no_pr(check):
    check["passes"] = lambda text: False
    out = test_first.run(_entry(), ".", sca_upgrade_map)
    assert out["files"] == [] and out["generation"]["status"] == "no_candidate"


def test_a_check_that_could_not_run_does_not_count_as_passing(check, monkeypatch):
    monkeypatch.setattr(app_check, "check", lambda *a, **k: Result(False, "unavailable", "docker is down"))
    assert test_first.run(_entry(), ".", sca_upgrade_map)["files"] == []


def test_an_unexpected_error_never_opens_this_one_untested(check, monkeypatch):
    def broken(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(app_check, "check", broken)
    assert test_first.run(_entry(), ".", sca_upgrade_map)["files"] == []


def test_no_failure_issue_as_the_container_report_covers_it(tmp_path, monkeypatch):
    (tmp_path / "b.json").write_text(json.dumps({"batch_id": "b", "batch_type": "container", "remediation_method": "base_image"}), encoding="utf-8")
    monkeypatch.setattr(pffi, "open_issue", lambda *a, **k: pytest.fail("opened an issue"))
    entries = [{"batch_id": "b", "status": "no_commits", "generation": {"method": "test_first"}}]
    assert pffi.process_no_commits_entries(entries, str(tmp_path), execute=True) == 0


def test_the_code_names_no_app_or_image():
    text = open(base_image.__file__, encoding="utf-8").read().lower()
    for name in ("nodegoat", "pygoat", "bookworm", "trixie", "debian", "mongo"):
        assert name not in text


def test_a_jump_the_scan_says_is_no_better_opens_no_pr_and_says_why(check, monkeypatch):
    monkeypatch.setattr(base_image, "scan_candidate", lambda *a: counts(5, 300))
    out = test_first.run(_entry(), ".", sca_upgrade_map)
    assert out["files"] == [] and "the scan shows no gain" in out["generation"]["files"][0]["status"]
    assert out["generation"]["base_image_scan"]["after"]["total"] == 300


def test_a_better_jump_opens_with_the_numbers_saved_for_the_report(check):
    out = test_first.run(_entry(), ".", sca_upgrade_map)
    assert out["files"] and out["generation"]["base_image_scan"] == {"name": "trixie", "today": TODAY, "after": BETTER}
    assert "Not scanned" not in out["batch"]["rag_pr_text"]


def test_a_scan_that_cannot_run_does_not_stop_it_and_the_pr_says_so(check, monkeypatch):
    monkeypatch.setattr(base_image, "scan_candidate", lambda *a: None)
    out = test_first.run(_entry(), ".", sca_upgrade_map)
    assert out["files"] and "Not scanned before this PR" in out["batch"]["rag_pr_text"]


def test_a_failed_app_check_is_not_scanned(check, monkeypatch):
    monkeypatch.setattr(base_image, "scan_candidate", lambda *a: pytest.fail("scanned"))
    check["passes"] = lambda text: False
    assert test_first.run(_entry(), ".", sca_upgrade_map)["files"] == []


def test_todays_os_counts_are_saved_with_the_batch(source):
    batch = json.loads(_prepare(source).read_text(encoding="utf-8"))
    assert batch["os_findings_today"]["total"] == 3 and batch["os_findings_today"]["low"] == 1

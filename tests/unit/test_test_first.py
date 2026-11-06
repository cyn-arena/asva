"""Testing dependency fixes before there is a PR. The app check and the RAG are faked: what is under
test is what the loop keeps, drops and says. No Docker, network or LLM."""

from __future__ import annotations

import copy
import json

import pytest

from agent import app_check, code_scan, npm_remediation, rag_client, test_first
from agent.agent_loop import sca_upgrade_map
from agent.app_check import Result
from gitops import config
from gitops.post_pr_summary import distinct

pytestmark = pytest.mark.unit

ORIGINAL = "Django==4.2\nPyYAML==5.1\nPillow==9.4.0\ncryptography==39.0.1\ncffi==1.15.1\nsqlparse==0.3.1\n"
SAFE = "Django==4.2.28\nPyYAML==5.4\nPillow==9.4.0\ncryptography==39.0.1\ncffi==1.15.1\nsqlparse==0.3.1\n"
OK = Result(True, "passed")
BROKEN = Result(False, "build", "pip failed at PyYAML==5.4: did not run successfully")


def sca(package, upgrade_to, finding_id="CVE-1"):
    return {"finding_type": "sca", "identifiers": {"cve": finding_id}, "location": {"package": package},
            "remediation": {"upgrade_to": upgrade_to, "scanner_upgrade_to": upgrade_to}}


def trial(order, name, current, target, fixes, kind="major_upgrade", also_needs=None, dev_only=False, note="Try it."):
    return {"order": order, "kind": kind, "name": name, "current": current, "target": target, "fixes": fixes,
            "known_exploited": [], "also_needs": also_needs or [], "dev_only": dev_only, "note": note}


PILLOW = trial(1, "pillow", "9.4.0", "12.3.0", ["CVE-P"])
CRYPTOGRAPHY = trial(2, "cryptography", "39.0.1", "49.0.0", ["CVE-C"],
                     also_needs=[{"name": "cffi", "current": "1.15.1", "suggest": "2.0.0", "reason": "needs cffi>=2"}])
SQLPARSE = trial(3, "sqlparse", "0.3.1", "0.6.0", ["CVE-S"])


@pytest.fixture
def app(tmp_path, monkeypatch):
    """An app of any name, with the app check answering by what the test says is broken."""
    monkeypatch.setenv("ASVA_TEST_FIRST", "1")
    monkeypatch.setenv("ASVA_APP_COMPOSE_FILES", "compose.yml")
    monkeypatch.setenv("ASVA_APP_READY_URL", "http://127.0.0.1:9/")
    monkeypatch.setenv("ASVA_APP_SMOKE_COMMAND", "python smoke.py")
    monkeypatch.delenv("ASVA_APP_SECURITY_COMMAND", raising=False)
    monkeypatch.delenv("ASVA_APP_SECURITY_TESTS_FILE", raising=False)
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "target-apps/AnyApp")
    (tmp_path / "target-apps" / "AnyApp").mkdir(parents=True)
    (tmp_path / "target-apps" / "AnyApp" / "requirements.txt").write_text(ORIGINAL, encoding="utf-8")
    state = {"broken": lambda files: False, "checked": [], "repo": str(tmp_path)}

    def check(files, repo_dir=".", security_tests=None):
        state["checked"].append(copy.deepcopy(files))
        state["security_tests"] = security_tests
        return state.get("result", BROKEN) if state["broken"](files) else OK

    monkeypatch.setattr(app_check, "check", check)
    return state


@pytest.fixture
def rag(monkeypatch):
    state = {"trials": [PILLOW, CRYPTOGRAPHY, SQLPARSE]}

    def answer(*args, **kwargs):
        return {"items": [], "references": [], "upgrades": [], "warnings": [], "trials": state["trials"]}

    monkeypatch.setattr(rag_client, "manifest_response", answer)
    monkeypatch.setattr(rag_client, "npm_response", answer)
    return state


def requirements_entry(content=SAFE):
    findings = [sca("django@4.2", "django@4.2.28"), sca("pyyaml@5.1", "pyyaml@5.4", "CVE-Y"),
                sca("pillow@9.4.0", None, "CVE-P"), sca("cryptography@39.0.1", None, "CVE-C"), sca("sqlparse@0.3.1", None, "CVE-S")]
    batch = {"batch_id": "b", "batch_type": "sca",
             "files_to_fix": [{"file": "requirements.txt", "fix_type": "version_upgrade", "findings": findings}]}
    return {"batch": batch, "files": [{"path": "requirements.txt", "content": content}],
            "generation": {"method": "llm", "status": "generated"}}


def run(entry, app):
    return test_first.run(entry, app["repo"], sca_upgrade_map)


def upgrade_to(entry, package):
    findings = entry["batch"]["files_to_fix"][0]["findings"]
    return next(f["remediation"]["upgrade_to"] for f in findings if f["location"]["package"].startswith(package))


# -- when it runs ----------------------------------------------------------------------------------

def test_off_by_default(app, rag, monkeypatch):
    monkeypatch.delenv("ASVA_TEST_FIRST")
    entry = requirements_entry()
    assert run(entry, app) is entry and app["checked"] == []


def test_an_app_without_settings_is_not_tested_and_the_pr_says_so(app, rag, monkeypatch):
    monkeypatch.delenv("ASVA_APP_SMOKE_COMMAND")
    entry = run(requirements_entry(), app)
    assert app["checked"] == []
    assert entry["files"][0]["content"] == SAFE
    assert "Not tested" in entry["batch"]["rag_pr_text"]


def test_a_dependency_file_the_trial_loop_cannot_edit_is_tested_and_retried_like_a_code_fix(app, rag):
    entry = code_entry({"pom.xml": "<old/>"})
    entry["batch"]["batch_type"] = "sca"
    app["broken"] = lambda files: files and files.get("pom.xml") == "<old/>"
    result = code_run(entry, app, make_refix({"pom.xml": "<new/>"}))
    assert content_of(result) == {"pom.xml": "<new/>"} and not result["batch"].get("draft")


def test_not_for_logic_batches(app, rag):
    entry = requirements_entry()
    entry["batch"]["batch_type"] = "logic"
    run(entry, app)
    assert app["checked"] == []


# -- the safe candidate ----------------------------------------------------------------------------

def test_a_working_candidate_is_kept_and_the_trials_are_added_on_top_of_it(app, rag):
    entry = run(requirements_entry(), app)
    content = entry["files"][0]["content"]
    assert "PyYAML==5.4" in content and "Pillow==12.3.0" in content and "cryptography==49.0.0" in content
    assert "cffi==2.0.0" in content  # the upgrade it needs comes with it
    assert upgrade_to(entry, "pillow") == "pillow@12.3.0"  # so the PR counts what it now addresses
    text = entry["batch"]["rag_pr_text"]
    assert "Tested before this PR" in text and "`pillow` 9.4.0 → 12.3.0" in text
    assert "Upgrades to try next" not in text  # all tried: nothing left to suggest


def test_a_candidate_that_breaks_is_rebuilt_one_upgrade_at_a_time(app, rag):
    # What PyGoat does: PyYAML 5.4 cannot install, and everything else works.
    app["broken"] = lambda files: "PyYAML==5.4" in files.get("requirements.txt", "")
    entry = run(requirements_entry(), app)
    content = entry["files"][0]["content"]
    assert "PyYAML==5.1" in content and "Django==4.2.28" in content and "Pillow==12.3.0" in content
    assert upgrade_to(entry, "pyyaml") is None  # not claimed as addressed
    assert upgrade_to(entry, "django") == "django@4.2.28"
    text = entry["batch"]["rag_pr_text"]
    assert "pip failed at PyYAML" in text and "| `pyyaml` 5.4 | failed |" in text


def test_a_failed_trial_is_left_out_and_later_ones_still_run(app, rag):
    app["broken"] = lambda files: "cryptography==49.0.0" in files.get("requirements.txt", "")
    entry = run(requirements_entry(), app)
    content = entry["files"][0]["content"]
    assert "cryptography==39.0.1" in content and "cffi==1.15.1" in content
    assert "Pillow==12.3.0" in content and "sqlparse==0.6.0" in content
    assert upgrade_to(entry, "cryptography") is None
    assert "| `cryptography` 39.0.1 → 49.0.0 with `cffi` 2.0.0 | failed |" in entry["batch"]["rag_pr_text"]


def test_trials_for_development_tools_or_that_fix_nothing_are_skipped(app, rag):
    rag["trials"] = [trial(1, "forever", "2.0.0", "4.0.3", []), trial(2, "grunt", "1.0.3", "1.6.3", ["CVE-G"], dev_only=True)]
    run(requirements_entry(), app)
    assert len(app["checked"]) == 1  # the safe candidate only


def test_when_nothing_passes_there_is_no_pr_and_the_reason_is_reported(app, rag):
    app["broken"] = lambda files: bool(files)  # the unchanged app passes; every change breaks it
    entry = run(requirements_entry(), app)
    assert entry["files"] == []
    assert entry["generation"]["status"] == "no_candidate" and entry["generation"]["method"] == "test_first"
    assert "every candidate failed" in entry["generation"]["files"][0]["status"]


# -- a check that cannot judge must not cost us the fix --------------------------------------------

def test_if_the_unchanged_app_also_fails_the_candidate_goes_ahead_marked_unverified(app, rag):
    app["broken"] = lambda files: True
    entry = run(requirements_entry(), app)
    assert entry["files"][0]["content"] == SAFE
    assert "Not verified" in entry["batch"]["rag_pr_text"] and "unchanged app also fails" in entry["batch"]["rag_pr_text"]


def test_if_the_check_cannot_run_the_candidate_goes_ahead_marked_unverified(app, rag, monkeypatch):
    monkeypatch.setattr(app_check, "check", lambda files, repo_dir=".", security_tests=None: Result(False, "unavailable", "docker not found"))
    entry = run(requirements_entry(), app)
    assert entry["files"][0]["content"] == SAFE and "docker not found" in entry["batch"]["rag_pr_text"]


def test_an_unexpected_error_keeps_the_candidate_as_generated(app, rag, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(rag_client, "manifest_response", boom)
    entry = run(requirements_entry(), app)
    assert entry["files"][0]["content"] == SAFE


def test_the_time_limit_stops_the_trials_and_the_rest_stay_on_the_list(app, rag, monkeypatch):
    monkeypatch.setenv("ASVA_TEST_FIRST_MINUTES", "0")
    entry = run(requirements_entry(), app)
    assert "Pillow==9.4.0" in entry["files"][0]["content"]
    assert "Upgrades to try next" in entry["batch"]["rag_pr_text"]


# -- npm -------------------------------------------------------------------------------------------

@pytest.fixture
def npm(app, rag, monkeypatch):
    """generate() faked: its answer shows what it was asked for, as the real one copies the batch."""
    state = {"updates": []}

    def generate(batch, repo_dir, update=None):
        copied = copy.deepcopy(batch)
        wanted = sorted({f["remediation"]["upgrade_to"] for e in batch["files_to_fix"] for f in e["findings"]
                         if f["remediation"].get("upgrade_to")})
        state["updates"].append(update)
        copied["npm_upgrades"] = {w.rpartition("@")[0]: {"to": w.rpartition("@")[2], "section": "dependencies"} for w in wanted}
        manifest = " ".join(wanted + [f"update:{u}" for u in update or []])
        return {"batch": copied, "generation": {"method": "npm", "status": "generated", "message": "ok"},
                "files": [{"path": "package.json", "content": manifest}, {"path": "package-lock.json", "content": "{}"}]}

    monkeypatch.setattr(npm_remediation, "generate", generate)
    return state


def npm_entry():
    findings = [sca("marked@0.3.5", "marked@0.3.18", "CVE-M"), sca("mongodb@2.2.36", None, "CVE-DB"),
                sca("qs@6.5.2", None, "CVE-Q"), sca("ini@1.3.5", None, "CVE-I")]
    batch = {"batch_id": "b", "batch_type": "sca", "remediation_method": "npm",
             "npm_upgrades": {"marked": {"to": "0.3.18", "section": "dependencies"}},
             "files_to_fix": [{"file": "package.json", "fix_type": "version_upgrade", "findings": findings}]}
    return {"batch": batch, "generation": {"method": "npm", "status": "generated", "message": "ok"},
            "files": [{"path": "package.json", "content": "marked@0.3.18"}, {"path": "package-lock.json", "content": "{}"}]}


def test_npm_trials_keep_what_works_and_drop_what_breaks_the_app(app, rag, npm):
    # NodeGoat: a newer express works, the mongodb driver jump does not.
    rag["trials"] = [trial(1, "express", "4.16.4", "4.22.3", ["CVE-Q"], kind="parent_upgrade"),
                     trial(2, "mongodb", "2.2.36", "3.1.13", ["CVE-DB"])]
    app["broken"] = lambda files: "mongodb@3.1.13" in files.get("package.json", "")
    entry = run(npm_entry(), app)
    manifest = entry["files"][0]["content"]
    assert "express@4.22.3" in manifest and "mongodb" not in manifest and "marked@0.3.18" in manifest
    assert "| `mongodb` 2.2.36 → 3.1.13 | failed |" in entry["batch"]["rag_pr_text"]


def test_npm_a_kept_trial_stays_in_every_later_attempt(app, rag, npm):
    rag["trials"] = [trial(1, "express", "4.16.4", "4.22.3", ["CVE-Q"], kind="parent_upgrade"),
                     trial(2, "forever", "2.0.0", "4.0.3", ["CVE-I"])]
    entry = run(npm_entry(), app)
    manifest = entry["files"][0]["content"]
    assert "express@4.22.3" in manifest and "forever@4.0.3" in manifest


def test_npm_a_package_that_is_not_a_direct_dependency_is_not_reported_as_kept(app, rag, npm, monkeypatch):
    # package.json cannot set it, so npm changes nothing: testing would only repeat the last result.
    rag["trials"] = [trial(1, "getobject", "0.1.0", "1.0.0", ["CVE-Q"])]
    real = npm_remediation.generate

    def generate(batch, repo_dir, update=None):
        result = real(batch, repo_dir, update)
        result["batch"]["npm_upgrades"].pop("getobject", None)
        return result

    monkeypatch.setattr(npm_remediation, "generate", generate)
    entry = run(npm_entry(), app)
    assert len(app["checked"]) == 1  # the safe candidate only
    assert "| `getobject` 0.1.0 → 1.0.0 | not tried | not a direct dependency of the app |" in entry["batch"]["rag_pr_text"]
    assert upgrade_to(entry, "qs") is None  # not claimed as addressed


def test_npm_a_refresh_of_indirect_packages_runs_npm_update_and_is_kept(app, rag, npm):
    rag["trials"] = [trial(1, "(indirect)", None, None, ["CVE-I"], kind="lockfile_refresh", note="`npm update ini`: newer versions."),
                     trial(2, "express", "4.16.4", "4.22.3", ["CVE-Q"], kind="parent_upgrade")]
    entry = run(npm_entry(), app)
    assert npm["updates"] == [["ini"], ["ini"]]  # and it stays for the next attempt
    assert "update:ini" in entry["files"][0]["content"]
    assert "`npm update ini`" in entry["batch"]["rag_pr_text"]


def test_npm_a_broken_safe_set_is_rebuilt_one_upgrade_at_a_time(app, rag, npm):
    rag["trials"] = []
    entry = npm_entry()
    entry["batch"]["files_to_fix"][0]["findings"].append(sca("underscore@1.9.1", "underscore@1.13.8", "CVE-U"))
    entry["batch"]["npm_upgrades"]["underscore"] = {"to": "1.13.8", "section": "dependencies"}
    entry["files"][0]["content"] = "marked@0.3.18 underscore@1.13.8"
    app["broken"] = lambda files: "underscore" in files.get("package.json", "")
    result = run(entry, app)
    assert result["files"][0]["content"] == "marked@0.3.18"
    assert upgrade_to(result, "underscore") is None


def test_npm_nothing_passes_opens_no_pr(app, rag, npm):
    app["broken"] = lambda files: bool(files)
    result = run(npm_entry(), app)
    assert result["files"] == [] and result["generation"]["method"] == "test_first"


# -- reviewer notes for the major versions that were kept ------------------------------------------

def test_kept_major_upgrades_get_the_reviewers_notes(app, rag):
    asked = []

    def notes(path, original, upgrades):
        asked.append((path, original, upgrades))
        return ["Check `app.py:1`: it uses pillow."]

    entry = test_first.run(requirements_entry(), app["repo"], sca_upgrade_map, notes=notes)
    assert entry["batch"]["review_notes"]["requirements.txt"] == ["Check `app.py:1`: it uses pillow."]
    assert asked[0][1] == ORIGINAL and asked[0][2]["pillow"] == "12.3.0"  # from the old version to the new


def test_a_problem_with_the_notes_does_not_cost_the_tested_fixes(app, rag):
    def notes(path, original, upgrades):
        raise RuntimeError("no index")

    entry = test_first.run(requirements_entry(), app["repo"], sca_upgrade_map, notes=notes)
    assert "Pillow==12.3.0" in entry["files"][0]["content"]


# -- code fixes ------------------------------------------------------------------------------------

def code_entry(files=None):
    files = files or {"app/a.js": "a first", "app/b.js": "b first"}
    batch = {"batch_id": "s", "batch_type": "sast", "files_to_fix": [
        {"file": path, "fix_type": "code_change", "findings": [{"finding_type": "sast", "title": path, "identifiers": {"rule_id": "r"}}]}
        for path in files]}
    return {"batch": batch, "generation": {"method": "llm", "status": "generated"},
            "files": [{"path": path, "content": content} for path, content in files.items()]}


def make_refix(answers, asked=None):
    """The LLM retry: `answers` is {path: new content}, or a function of the round."""
    def factory(entry):
        def refix(path, findings, attempt, reason=None):
            if asked is not None:
                asked.append((path, attempt, reason))
            return answers(path, attempt) if callable(answers) else answers.get(path)
        return refix
    return factory


def code_run(entry, app, factory=None):
    return test_first.run(entry, app["repo"], sca_upgrade_map, make_refix=factory)


def content_of(entry):
    return {f["path"]: f["content"] for f in entry["files"]}


def test_a_code_fix_that_passes_goes_ahead_as_it_is(app):
    entry = code_run(code_entry(), app, make_refix({}))
    assert content_of(entry) == {"app/a.js": "a first", "app/b.js": "b first"}
    assert "First attempt | passed" in entry["batch"]["rag_pr_text"] and not entry["batch"].get("draft")
    assert len(app["checked"]) == 1


def test_a_failure_goes_back_to_the_llm_with_the_reason_and_the_fixed_version_is_kept(app):
    app["broken"] = lambda files: files and files.get("app/a.js") == "a first"
    app["result"] = Result(False, "start", "Error: key not set", "at /app/app/a.js:3")
    asked = []
    entry = code_run(code_entry(), app, make_refix({"app/a.js": "a second"}, asked))
    assert content_of(entry)["app/a.js"] == "a second"
    assert not entry["batch"].get("draft")
    assert [a[0] for a in asked] == ["app/a.js"]  # the log named it, so b.js is left alone
    assert "Error: key not set" in asked[0][2] and "at /app/app/a.js:3" in asked[0][2]
    text = entry["batch"]["rag_pr_text"]
    assert "First attempt | failed" in text and "Retry 1: `app/a.js` | passed" in text


def test_a_failure_that_points_nowhere_retries_every_file(app):
    app["broken"] = lambda files: files and files.get("app/a.js") == "a first"
    app["result"] = Result(False, "smoke", "FAILED test_login")
    asked = []
    code_run(code_entry(), app, make_refix({"app/a.js": "a second", "app/b.js": "b first"}, asked))
    assert {a[0] for a in asked} == {"app/a.js", "app/b.js"}


def test_when_one_failure_points_nowhere_every_file_is_retried():
    paths = ["a.js", "b.js"]
    result = Result(False, "smoke", "FAILED a broken link | FAILED something in a.js")
    assert test_first._suspects(result, paths) == paths


def test_when_every_failure_points_somewhere_only_those_files_are_retried():
    result = Result(False, "smoke", "FAILED in a.js | FAILED in c.js")
    assert test_first._suspects(result, ["a.js", "b.js", "c.js"]) == ["a.js", "c.js"]


def test_a_file_the_log_mentions_does_not_narrow_a_smoke_failure():
    result = Result(False, "smoke", "FAILED a broken link", "loading config from a.js")
    assert test_first._suspects(result, ["a.js", "b.js"]) == ["a.js", "b.js"]


def test_the_log_of_an_app_that_did_not_start_names_the_file():
    result = Result(False, "start", "TypeError: boom", "  at a.js:3")
    assert test_first._suspects(result, ["a.js", "b.js"]) == ["a.js"]


def test_a_long_failure_does_not_hide_the_next_one_in_the_table():
    result = Result(False, "smoke", "FAILED first " + "x" * 400 + " | FAILED second_test")
    assert "second_test" in test_first._why(result) and "\\|" in test_first._why(result)


def test_a_failed_security_test_points_at_its_annotated_file(app, monkeypatch):
    app["broken"] = lambda files: files and files.get("config/env/development.js") == "old"
    app["result"] = Result(False, "smoke", "FAILED tests/e2e/api/test_misuse_cases.py::test_development_zap_key_uses_environment_and_rescans_clean")
    monkeypatch.setenv("ASVA_APP_SECURITY_TESTS_FILE", "tests/e2e/api/test_misuse_cases.py")
    asked = []
    code_run(code_entry({"config/env/development.js": "old", "app/routes/index.js": "x"}), app,
             make_refix({"config/env/development.js": "new"}, asked))
    assert [a[0] for a in asked] == ["config/env/development.js"]


def test_retries_stop_at_the_limit_and_the_pr_opens_as_a_draft_with_the_failure(app):
    app["broken"] = lambda files: bool(files)
    app["result"] = Result(False, "smoke", "FAILED test_link")
    asked = []
    entry = code_run(code_entry(), app, make_refix(lambda path, attempt: f"{path} v{attempt}", asked))
    assert entry["batch"]["draft"] is True
    assert {a[1] for a in asked} == {1, 2}  # two rounds by default
    assert entry["files"]  # the PR still opens
    text = entry["batch"]["rag_pr_text"]
    assert "This did not pass, so it is a draft" in text and "FAILED test_link" in text
    # Remembered for the next run (memory: errors from pass N-1). The failure names no file, so both.
    assert set(entry["check_failures"]) == {"app/a.js", "app/b.js"}
    assert "FAILED test_link" in entry["check_failures"]["app/a.js"]


def test_a_fix_that_passes_leaves_nothing_to_remember(app):
    entry = code_run(code_entry(), app, make_refix({}))
    assert "check_failures" not in entry


def test_the_draft_holds_the_attempt_that_got_furthest(app, monkeypatch):
    results = iter([Result(False, "smoke", "FAILED one"),  # first attempt: runs, one test fails
                    Result(True, "passed"),                # the unchanged app passes
                    Result(False, "start", "crash"),       # retry 1: worse, does not even start
                    Result(False, "smoke", "FAILED one | FAILED two")])  # retry 2: worse, two tests fail
    monkeypatch.setattr(app_check, "check", lambda files, repo_dir=".", security_tests=None: next(results))
    entry = code_run(code_entry(), app, make_refix(lambda path, attempt: f"{path} v{attempt}"))
    assert content_of(entry) == {"app/a.js": "a first", "app/b.js": "b first"}
    assert entry["batch"]["draft"] is True


def test_a_later_attempt_that_gets_further_is_kept_even_if_it_still_fails(app, monkeypatch):
    results = iter([Result(False, "start", "crash"), Result(True, "passed"),
                    Result(False, "smoke", "FAILED one"), Result(False, "smoke", "FAILED one | FAILED two")])
    monkeypatch.setattr(app_check, "check", lambda files, repo_dir=".", security_tests=None: next(results))
    entry = code_run(code_entry(), app, make_refix(lambda path, attempt: f"{path} v{attempt}"))
    assert content_of(entry) == {"app/a.js": "app/a.js v1", "app/b.js": "app/b.js v1"}


def test_a_code_fix_is_not_retried_when_the_unchanged_app_also_fails(app):
    app["broken"] = lambda files: True
    asked = []
    entry = code_run(code_entry(), app, make_refix({}, asked))
    assert asked == [] and not entry["batch"].get("draft")
    assert "Not verified" in entry["batch"]["rag_pr_text"]
    assert "check_failures" not in entry  # not the fix's fault: nothing for the next pass to avoid


def test_an_llm_outage_during_a_retry_ends_in_a_draft(app):
    app["broken"] = lambda files: bool(files)
    entry = code_run(code_entry(), app, make_refix(lambda path, attempt: None))
    assert entry["batch"]["draft"] is True and len(app["checked"]) == 2  # first attempt, unchanged app


def test_only_security_tests_the_batch_aims_at_are_run(app, monkeypatch):
    # index.js also carries the access-control tests, which the scanner cannot fix: still vulnerable by design.
    monkeypatch.setenv("ASVA_APP_SECURITY_COMMAND", "python tests.py")
    monkeypatch.setenv("ASVA_APP_SECURITY_TESTS_FILE", "tests/e2e/api/test_misuse_cases.py")
    entry = code_entry({"app/routes/index.js": "x"})
    entry["batch"]["files_to_fix"][0]["findings"][0]["identifiers"]["rule_id"] = "javascript/OR"
    code_run(entry, app, make_refix({}))
    assert app["security_tests"] == ["test_unvalidated_redirect_learn"]


def test_an_app_without_security_tests_runs_none(app):
    code_run(code_entry(), app, make_refix({}))
    assert app["security_tests"] == []


def test_another_apps_own_security_tests_run_for_the_files_they_cover(app, monkeypatch):
    monkeypatch.setenv("ASVA_APP_SECURITY_COMMAND", "python tests.py")
    source = "# @a app/a.js\ndef test_any_app_case():\n    pass\n\n# @a app/other.js\ndef test_unrelated():\n    pass\n"
    monkeypatch.setattr(test_first, "_security_test_source", lambda: source)
    code_run(code_entry(), app, make_refix({}))
    assert app["security_tests"] == ["test_any_app_case"]


# -- set_version -----------------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["PyYAML", "pyyaml", "PYYAML"])
def test_set_version_compares_names_as_pip_does(name):
    assert test_first.set_version("PyYAML==5.1\n", name, "5.4") == "PyYAML==5.4\n"


def test_set_version_treats_dash_and_underscore_alike_and_leaves_other_packages():
    assert test_first.set_version("a==1\ndjango-allauth==0.52.0\n", "django_allauth", "65.13.0") == "a==1\ndjango-allauth==65.13.0\n"


# -- the misuse fix round ---------------------------------------------------------------------------

MISUSE_TESTS = ("# @a app/a.js\ndef test_attempted():\n    pass\n\n"
                "# @a app/a.js\n# @a app/other.js\ndef test_hole_one():\n    pass\n\n"
                "# @a app/third.js\ndef test_hole_two():\n    pass\n")


@pytest.fixture
def misuse(app, monkeypatch, tmp_path):
    """Security tests that fail until the files say the hole is closed."""
    monkeypatch.setenv("ASVA_MISUSE_FIX", "1")
    monkeypatch.setenv("ASVA_APP_SECURITY_COMMAND", "python tests.py")
    monkeypatch.setattr(test_first, "_security_test_source", lambda: MISUSE_TESTS)
    monkeypatch.setattr(test_first, "_security_tests", lambda batch: ["test_attempted"])
    folder = tmp_path / "target-apps" / "AnyApp" / "app"
    folder.mkdir(parents=True)
    (folder / "other.js").write_text("other original\n", encoding="utf-8")
    (folder / "third.js").write_text("third original\n", encoding="utf-8")
    state = {"runs": [], "asked": []}

    def check(files, repo_dir=".", security_tests=None):
        state["runs"].append((dict(files), list(security_tests or [])))
        holes = {"test_hole_one": "closed one", "test_hole_two": "closed two"}
        failed = [t for t in security_tests or [] if t in holes and holes[t] not in " ".join(files.values())]
        if state.get("broken_by") and any(state["broken_by"] in c for c in files.values()):
            return Result(False, "start", "the app did not start")
        return Result(False, "smoke", " | ".join(f"FAILED tests.py::{t} - still works" for t in failed)) if failed else OK

    monkeypatch.setattr(app_check, "check", check)
    return state


def misuse_run(app, misuse, answers):
    def logic_fix(files, failure):
        misuse["asked"].append((dict(files), failure))
        return answers(files)
    entry = code_entry({"app/a.js": "a fixed\n"})
    return test_first.run(entry, app["repo"], sca_upgrade_map, make_refix=make_refix({}), logic_fix=logic_fix)


def test_misuse_round_is_off_by_default(app, misuse, monkeypatch):
    monkeypatch.delenv("ASVA_MISUSE_FIX")
    result = misuse_run(app, misuse, lambda files: pytest.fail("asked the LLM"))
    assert "misuse_fixes" not in result["batch"]


def test_a_fix_that_passes_is_kept_for_its_own_commit_on_top_of_the_code_fix(app, misuse):
    def answers(files):
        return {"app/other.js": "closed one\n"} if "app/other.js" in files else {"app/third.js": "closed two"}
    result = misuse_run(app, misuse, answers)
    fixes = result["batch"]["misuse_fixes"]
    assert [f["test"] for f in fixes] == ["test_hole_one", "test_hole_two"]
    assert fixes[0]["files"] == [{"path": "app/other.js", "content": "closed one\n"}]
    assert fixes[1]["files"] == [{"path": "app/third.js", "content": "closed two\n"}]  # keeps the last newline
    assert content_of(result) == {"app/a.js": "a fixed\n"}  # the code fix itself is untouched
    assert "own commit" in result["batch"]["rag_pr_text"] and "Review these carefully" in result["batch"]["rag_pr_text"]


def test_the_llm_gets_the_files_the_test_is_linked_to_as_they_stand_and_the_failure(app, misuse):
    misuse_run(app, misuse, lambda files: {})
    files, failure = misuse["asked"][0]
    assert files == {"app/a.js": "a fixed\n", "app/other.js": "other original\n"}  # the code fix, then the repo's file
    assert "test_hole_one" in failure and "still works" in failure


def test_each_fix_is_tested_with_everything_kept_so_far(app, misuse):
    misuse_run(app, misuse, lambda files: {"app/other.js": "closed one\n"} if "app/other.js" in files else {"app/third.js": "closed two\n"})
    last_files, last_tests = misuse["runs"][-1]
    assert last_tests == ["test_attempted", "test_hole_one", "test_hole_two"]
    assert last_files["app/other.js"] == "closed one\n" and last_files["app/third.js"] == "closed two\n"


def test_a_fix_that_fails_is_dropped_and_the_next_test_is_still_tried(app, misuse):
    misuse["broken_by"] = "bad fix"

    def answers(files):
        return {"app/other.js": "closed one bad fix"} if "app/other.js" in files else {"app/third.js": "closed two\n"}
    result = misuse_run(app, misuse, answers)
    assert [f["test"] for f in result["batch"]["misuse_fixes"]] == ["test_hole_two"]
    assert "test_hole_one" in result["batch"]["rag_pr_text"] and "dropped" in result["batch"]["rag_pr_text"]


def test_a_failed_fix_gets_a_retry_with_the_fix_how_it_failed_and_the_test(app, misuse):
    misuse["broken_by"] = "bad fix"

    def answers(files):
        if "app/other.js" not in files:
            return {}
        return {"app/other.js": "closed one\n" if "bad fix" in files["app/other.js"] else "closed one bad fix\n"}
    result = misuse_run(app, misuse, answers)
    assert result["batch"]["misuse_fixes"][0]["files"] == [{"path": "app/other.js", "content": "closed one\n"}]
    assert "fixed on the retry, own commit" in result["batch"]["rag_pr_text"]
    assert misuse["asked"][0][0]["app/other.js"] == "other original\n"
    files, detail = misuse["asked"][1]
    assert files["app/other.js"] == "closed one bad fix\n"
    assert "the app did not start" in detail and "def test_hole_one" in detail and "test_hole_two" not in detail
    assert "do not special-case" in detail


def test_a_retry_that_fails_too_is_dropped_named_and_not_tried_again(app, misuse):
    misuse["broken_by"] = "bad fix"
    tries = []

    def answers(files):
        if "app/other.js" not in files:
            return {"app/third.js": "closed two\n"}
        tries.append(1)
        return {"app/other.js": f"closed one bad fix {len(tries)}\n"}
    result = misuse_run(app, misuse, answers)
    assert len(tries) == 2
    assert [f["test"] for f in result["batch"]["misuse_fixes"]] == ["test_hole_two"]
    assert result["batch"]["misuse_dropped"] == ["test_hole_one"]
    assert "first try, start" in result["batch"]["rag_pr_text"] and "retry, start" in result["batch"]["rag_pr_text"]


def test_a_retry_with_the_same_answer_is_not_tested_again(app, misuse):
    misuse["broken_by"] = "bad fix"
    result = misuse_run(app, misuse, lambda files: {"app/other.js": "closed one bad fix\n"} if "app/other.js" in files else {})
    tested = [files.get("app/other.js") for files, tests in misuse["runs"] if "test_hole_one" in tests]
    assert tested.count("closed one bad fix\n") == 1
    assert "test_hole_one" in result["batch"]["misuse_dropped"]


def test_a_fix_that_failed_gets_no_retry_once_out_of_time(app, misuse, monkeypatch):
    clock = {"now": 0}
    misuse["broken_by"] = "bad fix"
    monkeypatch.setattr(test_first.time, "monotonic", lambda: clock["now"])

    def logic_fix(files, failure):
        misuse["asked"].append(failure)
        clock["now"] = 200
        return {"app/other.js": "closed one bad fix\n"}
    entry = code_entry({"app/a.js": "a fixed\n"})
    test_first._misuse_round(entry, app["repo"], logic_fix, ["test_attempted"], 100)
    assert len(misuse["asked"]) == 1 and entry["batch"]["misuse_dropped"] == ["test_hole_one"]


def test_a_problem_in_the_retry_keeps_the_fixes_already_kept(app, misuse):
    misuse["broken_by"] = "bad fix"

    def answers(files):
        if "app/other.js" in files:
            return {"app/other.js": "closed one\n"}
        if "bad fix" in files["app/third.js"]:
            raise RuntimeError("LLM down")
        return {"app/third.js": "closed two bad fix\n"}
    result = misuse_run(app, misuse, answers)
    assert [f["test"] for f in result["batch"]["misuse_fixes"]] == ["test_hole_one"]
    assert result["batch"]["misuse_dropped"] == ["test_hole_two"]


def test_nothing_is_named_as_dropped_when_every_fix_was_kept(app, misuse):
    result = misuse_run(app, misuse, lambda files: {"app/other.js": "closed one\n"} if "app/other.js" in files else {"app/third.js": "closed two\n"})
    assert "misuse_dropped" not in result["batch"]


def test_no_change_from_the_llm_is_reported_not_kept(app, misuse):
    result = misuse_run(app, misuse, lambda files: {path: content + "\n\n" for path, content in files.items()})
    assert "misuse_fixes" not in result["batch"] and "returned no change" in result["batch"]["rag_pr_text"]


def test_a_problem_in_the_round_keeps_the_tested_code_fix(app, misuse):
    def broken(files):
        raise RuntimeError("LLM down")
    result = misuse_run(app, misuse, broken)
    assert content_of(result) == {"app/a.js": "a fixed\n"} and "misuse_fixes" not in result["batch"]
    assert "Tested before this PR" in result["batch"]["rag_pr_text"]  # not rolled back to the untested state


def test_a_code_fix_that_is_failing_gets_no_misuse_round(app, misuse, monkeypatch):
    monkeypatch.setattr(app_check, "check", lambda files, repo_dir=".", security_tests=None: BROKEN if files else OK)
    result = misuse_run(app, misuse, lambda files: pytest.fail("asked the LLM"))
    assert result["batch"].get("draft") and "misuse_fixes" not in result["batch"]


def test_dependency_and_container_batches_get_no_misuse_round(app, misuse):
    entry = code_entry({"app/a.js": "x"})
    entry["batch"]["batch_type"] = "container"
    result = test_first.run(entry, app["repo"], sca_upgrade_map, make_refix=make_refix({}), logic_fix=lambda *a: pytest.fail("asked"))
    assert "misuse_fixes" not in result["batch"]


def test_an_app_without_security_tests_skips_the_round(app, monkeypatch):
    monkeypatch.setenv("ASVA_MISUSE_FIX", "1")
    entry = code_entry({"app/a.js": "x"})
    result = test_first.run(entry, app["repo"], sca_upgrade_map, make_refix=make_refix({}), logic_fix=lambda *a: pytest.fail("asked"))
    assert "misuse_fixes" not in result["batch"]


# -- other versions when one fails --------------------------------------------------------------------

def _with_broken_pin(app, *broken):
    app["broken"] = lambda files: any(pin.lower() in (files.get("requirements.txt") or "").lower() for pin in broken)


def test_a_trial_that_fails_gets_its_other_versions_and_the_first_that_passes_is_kept(app, rag):
    rag["trials"] = [dict(trial(1, "pillow", "9.4.0", "12.3.0", ["CVE-P"]), fallbacks=[{"target": "11.0.0"}, {"target": "10.0.0"}])]
    _with_broken_pin(app, "pillow==12.3.0", "pillow==11.0.0")
    entry = run(requirements_entry(), app)
    assert "pillow==10.0.0" in entry["files"][0]["content"].lower()
    text = entry["batch"]["rag_pr_text"]
    assert "12.3.0" in text and "11.0.0" in text and "10.0.0" in text


def test_a_trial_with_nothing_passing_leaves_the_pin_alone(app, rag):
    rag["trials"] = [dict(trial(1, "pillow", "9.4.0", "12.3.0", ["CVE-P"]), fallbacks=[{"target": "11.0.0"}])]
    _with_broken_pin(app, "pillow==12.3.0", "pillow==11.0.0")
    assert "pillow==9.4.0" in run(requirements_entry(), app)["files"][0]["content"].lower()


def test_a_fallback_brings_what_it_needs_not_what_the_first_version_needed(app, rag):
    rag["trials"] = [dict(trial(1, "cryptography", "39.0.1", "50.0.0", ["CVE-C"], also_needs=[{"name": "cffi", "suggest": "2.0.0"}]),
                          fallbacks=[{"target": "49.0.0", "also_needs": []}])]
    _with_broken_pin(app, "cryptography==50.0.0")
    assert "cffi==2.0.0" not in run(requirements_entry(), app)["files"][0]["content"]


def test_a_lower_version_only_claims_the_findings_it_fixes(app, rag):
    entry = requirements_entry()
    findings = entry["batch"]["files_to_fix"][0]["findings"]
    high, low = sca("pillow@9.4.0", None, "CVE-H"), sca("pillow@9.4.0", None, "CVE-L")
    high["remediation"]["scanner_upgrade_to"], low["remediation"]["scanner_upgrade_to"] = "pillow@12.3.0", "pillow@10.0.0"
    findings += [high, low]
    rag["trials"] = [dict(trial(1, "pillow", "9.4.0", "12.3.0", ["CVE-H", "CVE-L"]), fallbacks=[{"target": "10.0.0"}])]
    _with_broken_pin(app, "pillow==12.3.0")
    run(entry, app)
    assert low["remediation"]["upgrade_to"] == "pillow@10.0.0" and high["remediation"]["upgrade_to"] is None


def test_a_safe_upgrade_that_will_not_install_tries_the_next_versions(app, rag, monkeypatch):
    answer = {"items": [], "references": [], "warnings": [], "trials": [], "upgrades": [
        {"kind": "package", "name": "pyyaml", "fallbacks": [{"target": "5.4.1"}, {"target": "6.0.3"}]}]}
    monkeypatch.setattr(rag_client, "manifest_response", lambda *a, **k: answer)
    app["broken"] = lambda files: any(pin in (files.get("requirements.txt") or "").lower() for pin in ("pyyaml==5.4\n", "pyyaml==5.4.1\n"))
    entry = run(requirements_entry(), app)
    assert "pyyaml==6.0.3" in entry["files"][0]["content"].lower()
    text = entry["batch"]["rag_pr_text"]
    assert "| `pyyaml` 5.4.1 instead of 5.4 | failed |" in text.lower() or "5.4.1 instead of 5.4" in text
    assert "6.0.3 instead of 5.4` " in text or "6.0.3 instead of 5.4" in text


def test_running_out_of_time_says_what_was_not_tried(app, rag, monkeypatch):
    rag["trials"] = [dict(trial(1, "pillow", "9.4.0", "12.3.0", ["CVE-P"]), fallbacks=[{"target": "11.0.0"}])]
    clock = {"now": 0.0}
    monkeypatch.setattr(test_first.time, "monotonic", lambda: clock["now"])

    def broken_and_slow(files):
        if "pillow==12.3.0" in (files.get("requirements.txt") or "").lower():
            clock["now"] = 1_000_000.0
            return True
        return False

    app["broken"] = broken_and_slow
    text = run(requirements_entry(), app)["batch"]["rag_pr_text"]
    assert "11.0.0 | not tried | out of time" in text


def test_npm_trials_try_their_other_versions_too(app, rag, npm):
    rag["trials"] = [dict(trial(1, "mongodb", "2.2.36", "3.1.13", ["CVE-DB"]), fallbacks=[{"target": "2.9.0"}])]
    app["broken"] = lambda files: "mongodb@3.1.13" in files.get("package.json", "")
    entry = run(npm_entry(), app)
    assert "mongodb@2.9.0" in entry["files"][0]["content"]
    text = entry["batch"]["rag_pr_text"]
    assert "| `mongodb` 2.2.36 → 3.1.13 | failed |" in text and "| `mongodb` 2.2.36 → 2.9.0 | kept |" in text


def test_npm_a_failed_trial_with_failed_fallbacks_leaves_the_findings_as_they_were(app, rag, npm):
    rag["trials"] = [dict(trial(1, "mongodb", "2.2.36", "3.1.13", ["CVE-DB"]), fallbacks=[{"target": "2.9.0"}])]
    app["broken"] = lambda files: "mongodb@" in files.get("package.json", "")
    entry = run(npm_entry(), app)
    assert "mongodb" not in entry["files"][0]["content"]
    assert all((f["remediation"].get("upgrade_to") or "").partition("@")[0] != "mongodb" for f in entry["batch"]["files_to_fix"][0]["findings"])


# -- two PRs: same major versions, or with major versions ----------------------------------------------

def test_a_kept_major_upgrade_also_offers_a_tested_same_major_pr(app, rag):
    rag["trials"] = [PILLOW]
    entry = run(requirements_entry(), app)
    other = entry["same_major"]
    assert "pillow==12.3.0" in entry["files"][0]["content"].lower()
    text = other["files"][0]["content"].lower()
    assert "pillow==9.4.0" in text and "django==4.2.28" in text
    assert other["batch"]["batch_id"] == "b_same_major" and other["batch"]["pr_choice"] == test_first.SAFE_LABEL
    assert entry["batch"]["pr_choice"] == test_first.MAJOR_LABEL
    assert app["checked"][-1] == {"requirements.txt": other["files"][0]["content"]}  # tested as it would ship


def test_each_pr_says_to_merge_only_one_and_names_the_other(app, rag):
    rag["trials"] = [PILLOW]
    entry = run(requirements_entry(), app)
    mine, other = entry["batch"]["rag_pr_text"], entry["same_major"]["batch"]["rag_pr_text"]
    assert "merge only one" in mine and "fix/b_same_major" in mine
    assert "merge only one" in other and "fix/b`" in other


def test_the_same_major_pr_only_claims_what_it_fixes(app, rag):
    rag["trials"] = [PILLOW]
    entry = run(requirements_entry(), app)
    findings = {f["identifiers"]["cve"]: f["remediation"]["upgrade_to"] for f in entry["same_major"]["batch"]["files_to_fix"][0]["findings"]}
    assert findings["CVE-P"] is None
    assert entry["batch"]["files_to_fix"][0]["findings"] is not entry["same_major"]["batch"]["files_to_fix"][0]["findings"]


def test_no_major_upgrade_kept_means_one_pr(app, rag):
    rag["trials"] = [PILLOW]
    app["broken"] = lambda files: "pillow==12.3.0" in (files.get("requirements.txt") or "").lower()
    assert "same_major" not in run(requirements_entry(), app)


def test_nothing_safe_passing_means_only_the_major_pr(app, rag):
    rag["trials"] = [PILLOW]
    app["broken"] = lambda files: "pyyaml==5.4" in (files.get("requirements.txt") or "").lower() or "django==4.2.28" in (files.get("requirements.txt") or "").lower()
    entry = run(requirements_entry(), app)
    assert "same_major" not in entry and "pillow==12.3.0" in entry["files"][0]["content"].lower()


def test_a_same_major_set_that_fails_by_itself_is_not_offered(app, rag):
    rag["trials"] = [PILLOW]
    # Safe set and trial pass; only the check of the same-major set alone fails.
    app["broken"] = lambda files: len(app["checked"]) >= 3
    entry = run(requirements_entry(), app)
    assert len(app["checked"]) == 3 and "same_major" not in entry
    assert "pillow==12.3.0" in entry["files"][0]["content"].lower()


def test_a_safe_upgrade_that_needed_the_next_major_only_goes_in_the_major_pr(app, rag, monkeypatch):
    answer = {"items": [], "references": [], "warnings": [], "trials": [], "upgrades": [
        {"kind": "package", "name": "pyyaml", "fallbacks": [{"target": "6.0.3"}]}]}
    monkeypatch.setattr(rag_client, "manifest_response", lambda *a, **k: answer)
    app["broken"] = lambda files: "pyyaml==5.4" in (files.get("requirements.txt") or "").lower()
    entry = run(requirements_entry(), app)
    assert "pyyaml==6.0.3" in entry["files"][0]["content"].lower()
    other = entry["same_major"]["files"][0]["content"].lower()
    assert "pyyaml==5.1" in other and "django==4.2.28" in other


def test_a_same_major_fallback_stays_in_the_same_major_pr(app, rag, monkeypatch):
    answer = {"items": [], "references": [], "warnings": [], "trials": [PILLOW], "upgrades": [
        {"kind": "package", "name": "pyyaml", "fallbacks": [{"target": "5.4.1"}]}]}
    monkeypatch.setattr(rag_client, "manifest_response", lambda *a, **k: answer)
    app["broken"] = lambda files: "pyyaml==5.4\n" in (files.get("requirements.txt") or "").lower()
    entry = run(requirements_entry(), app)
    assert "pyyaml==5.4.1" in entry["same_major"]["files"][0]["content"].lower()


@pytest.mark.parametrize("current, version, major", [("5.1", "5.4.1", False), ("5.1", "6.0.3", True), ("0.52.0", "0.54.0", True),
                                                     ("0.52.0", "0.52.9", False), ("", "1.0", True)])
def test_major_change_follows_semantic_versions(current, version, major):
    assert test_first._major_change(current, version) is major


def test_npm_a_kept_major_upgrade_offers_the_state_before_the_majors(app, rag, npm):
    rag["trials"] = [trial(1, "express", "4.16.4", "4.22.3", ["CVE-Q"], kind="parent_upgrade"), trial(2, "mongodb", "2.2.36", "3.1.13", ["CVE-DB"])]
    entry = run(npm_entry(), app)
    assert "mongodb@3.1.13" in entry["files"][0]["content"]
    other = entry["same_major"]
    manifest = next(f["content"] for f in other["files"] if f["path"] == "package.json")
    assert "express@4.22.3" in manifest and "mongodb" not in manifest
    assert other["batch"]["pr_choice"] == test_first.SAFE_LABEL
    assert "mongodb" not in (other["batch"].get("npm_upgrades") or {})


def test_npm_with_no_major_kept_is_one_pr(app, rag, npm):
    rag["trials"] = [trial(1, "mongodb", "2.2.36", "3.1.13", ["CVE-DB"])]
    app["broken"] = lambda files: "mongodb@3.1.13" in files.get("package.json", "")
    assert "same_major" not in run(npm_entry(), app)


# -- the scan before a PR ---------------------------------------------------------------------------

def scan_finding(flow, rule="js/Sqli", severity="high"):
    return {"finding_type": "sast", "severity": severity, "title": rule, "summary": "Flagged.", "identifiers": {"rule_id": rule},
            "location": {"file": flow[0][0], "line": flow[-1][1]}, "code_flow": [{"file": f, "line": n} for f, n in flow]}


TODAY_ROUTE = [("app/a.js", 1), ("app/a.js", 2)]
ADDED_ROUTE = [("app/a.js", 5), ("app/a.js", 9)]


@pytest.fixture
def scanner(app, monkeypatch, tmp_path):
    """The scanner, answering by the code it is given. By default nothing is new."""
    monkeypatch.setenv("ASVA_SCAN_BEFORE_PR", "1")
    path = tmp_path / "findings.json"
    path.write_text(json.dumps([scan_finding(TODAY_ROUTE)]), encoding="utf-8")
    state = {"path": str(path), "scanned": [], "adds": lambda files: []}

    def scan(files, repo_dir):
        state["scanned"].append(dict(files))
        added = state["adds"](files)
        if added is None:
            return None
        return distinct([scan_finding(TODAY_ROUTE), *added], "sast")

    monkeypatch.setattr(code_scan, "scan", scan)
    return state


def scan_run(app, scanner, factory=None, **kwargs):
    return test_first.run(code_entry(), app["repo"], sca_upgrade_map, make_refix=factory or make_refix({}), findings_path=scanner["path"], **kwargs)


def adds_until(fixed_content):
    return lambda files: [] if fixed_content in files.values() else [scan_finding(ADDED_ROUTE)]


def test_the_scan_is_off_by_default(app, scanner, monkeypatch):
    monkeypatch.delenv("ASVA_SCAN_BEFORE_PR")
    entry = scan_run(app, scanner)
    assert scanner["scanned"] == [] and "Scanned before this PR" not in entry["batch"]["rag_pr_text"]


def test_a_clean_scan_is_said_and_changes_nothing(app, scanner):
    entry = scan_run(app, scanner)
    assert scanner["scanned"] == [{"app/a.js": "a first", "app/b.js": "b first"}]
    assert "No new critical or high findings" in entry["batch"]["rag_pr_text"] and not entry["batch"].get("draft")
    assert len(app["checked"]) == 1


def test_only_code_batches_are_scanned(app, scanner):
    entry = code_entry()
    entry["batch"]["batch_type"] = "container"
    test_first.run(entry, app["repo"], sca_upgrade_map, make_refix=make_refix({}), findings_path=scanner["path"])
    assert scanner["scanned"] == []


def test_a_new_finding_goes_back_to_the_llm_and_a_retry_that_removes_it_is_kept(app, scanner):
    scanner["adds"] = adds_until("a second")
    asked = []
    entry = scan_run(app, scanner, make_refix({"app/a.js": "a second"}, asked))
    assert content_of(entry)["app/a.js"] == "a second" and not entry["batch"].get("draft")
    assert "new_before_pr" not in entry["batch"]
    assert [a[0] for a in asked] == ["app/a.js"]  # b.js is on no route, so it is left alone
    assert "security scanner" in asked[0][2] and "js/Sqli" in asked[0][2]
    assert app["checked"][-1]["app/a.js"] == "a second"  # the retry went through the app's tests too
    assert "the retry removed it" in entry["batch"]["rag_pr_text"]


def test_a_retry_that_does_not_help_leaves_a_draft_that_names_the_finding(app, scanner):
    scanner["adds"] = lambda files: [scan_finding(ADDED_ROUTE)]
    entry = scan_run(app, scanner, make_refix({"app/a.js": "a second"}))
    batch = entry["batch"]
    assert batch["draft"] is True and content_of(entry)["app/a.js"] == "a first"  # no better, so the first stays
    assert batch["new_before_pr"] == ["`app/a.js`: js/Sqli, high (1 before this fix, 2 now)"]
    assert "so this is a draft" in batch["rag_pr_text"] and "`app/a.js`: js/Sqli" in batch["rag_pr_text"]
    assert "| Retry | dropped | 1 new, no better |" in batch["rag_pr_text"]
    # Remembered for the next run, against the file on the finding's route only
    assert list(entry["check_failures"]) == ["app/a.js"] and "js/Sqli" in entry["check_failures"]["app/a.js"]


def test_there_is_only_one_retry(app, scanner):
    scanner["adds"] = lambda files: [scan_finding(ADDED_ROUTE)]
    asked = []
    scan_run(app, scanner, make_refix({"app/a.js": "a second"}, asked))
    assert len(asked) == 1 and len(scanner["scanned"]) == 2


def test_a_retry_that_breaks_the_app_is_dropped_and_not_scanned(app, scanner):
    scanner["adds"] = lambda files: [scan_finding(ADDED_ROUTE)]
    app["broken"] = lambda files: files.get("app/a.js") == "a second"
    app["result"] = Result(False, "start", "Error: broken")
    entry = scan_run(app, scanner, make_refix({"app/a.js": "a second"}))
    assert content_of(entry)["app/a.js"] == "a first" and entry["batch"]["draft"] is True
    assert len(scanner["scanned"]) == 1 and "| Retry | dropped |" in entry["batch"]["rag_pr_text"]


def test_a_retry_the_scanner_cannot_read_is_dropped(app, scanner):
    scanner["adds"] = lambda files: None if "a second" in files.values() else [scan_finding(ADDED_ROUTE)]
    entry = scan_run(app, scanner, make_refix({"app/a.js": "a second"}))
    assert content_of(entry)["app/a.js"] == "a first" and entry["batch"]["draft"] is True
    assert "the scanner could not run on it" in entry["batch"]["rag_pr_text"]


def test_a_retry_that_returns_nothing_new_leaves_a_draft(app, scanner):
    scanner["adds"] = lambda files: [scan_finding(ADDED_ROUTE)]
    entry = scan_run(app, scanner, make_refix({"app/a.js": "a first"}))
    assert entry["batch"]["draft"] is True and "the LLM returned no change" in entry["batch"]["rag_pr_text"]
    assert len(app["checked"]) == 1


def test_a_retry_that_removes_some_is_kept_and_the_rest_are_named(app, scanner):
    third = [("app/a.js", 7), ("app/a.js", 11)]
    scanner["adds"] = lambda files: [scan_finding(ADDED_ROUTE)] if "a second" in files.values() else [scan_finding(ADDED_ROUTE), scan_finding(third)]
    entry = scan_run(app, scanner, make_refix({"app/a.js": "a second"}))
    assert content_of(entry)["app/a.js"] == "a second" and entry["batch"]["draft"] is True
    assert entry["batch"]["new_before_pr"] == ["`app/a.js`: js/Sqli, high (1 before this fix, 2 now)"]


def test_a_scanner_that_cannot_run_is_said_and_stops_nothing(app, scanner):
    scanner["adds"] = lambda files: None
    asked = []
    entry = scan_run(app, scanner, make_refix({"app/a.js": "a second"}, asked))
    assert "**Not scanned:**" in entry["batch"]["rag_pr_text"] and not entry["batch"].get("draft") and asked == []
    assert content_of(entry)["app/a.js"] == "a first"


def test_no_findings_of_today_means_not_scanned_rather_than_everything_is_new(app, scanner):
    scanner["adds"] = lambda files: [scan_finding(ADDED_ROUTE)]
    entry = test_first.run(code_entry(), app["repo"], sca_upgrade_map, make_refix=make_refix({}), findings_path=None)
    assert "**Not scanned:**" in entry["batch"]["rag_pr_text"] and not entry["batch"].get("draft") and scanner["scanned"] == []


def test_an_unexpected_error_in_the_scan_keeps_the_tested_fix_and_says_so(app, scanner, monkeypatch):
    def scan(files, repo_dir):
        raise RuntimeError("scan blew up")
    monkeypatch.setattr(code_scan, "scan", scan)
    entry = scan_run(app, scanner)
    text = entry["batch"]["rag_pr_text"]
    assert content_of(entry)["app/a.js"] == "a first" and "First attempt | passed" in text
    assert "**Not scanned:**" in text and "scan blew up" in text


def test_out_of_time_skips_the_retry_and_leaves_a_draft(app, scanner, monkeypatch):
    monkeypatch.setenv("ASVA_TEST_FIRST_MINUTES", "0")
    scanner["adds"] = lambda files: [scan_finding(ADDED_ROUTE)]
    asked = []
    entry = scan_run(app, scanner, make_refix({"app/a.js": "a second"}, asked))
    assert asked == [] and entry["batch"]["draft"] is True


def test_a_fix_that_passes_only_on_a_retry_is_scanned_as_it_stands(app, scanner):
    app["broken"] = lambda files: files and files.get("app/a.js") == "a first"
    app["result"] = Result(False, "start", "Error: key not set", "at /app/app/a.js:3")
    entry = scan_run(app, scanner, make_refix({"app/a.js": "a second"}))
    assert scanner["scanned"][-1]["app/a.js"] == "a second" and content_of(entry)["app/a.js"] == "a second"


def test_a_draft_from_failing_tests_is_not_scanned(app, scanner):
    app["broken"] = lambda files: bool(files)  # the unchanged app passes
    app["result"] = Result(False, "start", "Error: key not set", "at /app/app/a.js:3")
    entry = scan_run(app, scanner)
    assert entry["batch"]["draft"] is True and scanner["scanned"] == [] and "new_before_pr" not in entry["batch"]


def misuse_scan_run(app, misuse, scanner, answers):
    entry = code_entry({"app/a.js": "a fixed\n"})
    return test_first.run(entry, app["repo"], sca_upgrade_map, make_refix=make_refix({}),
                          logic_fix=lambda files, failure: answers(files), findings_path=scanner["path"])


def close_holes(files):
    return {"app/other.js": "closed one\n"} if "app/other.js" in files else {"app/third.js": "closed two"}


def test_a_misuse_fix_that_adds_a_finding_makes_a_draft_without_a_retry(app, misuse, scanner):
    route = [("app/other.js", 1), ("app/other.js", 2)]
    scanner["adds"] = lambda files: [scan_finding(route)] if "closed one\n" in files.values() else []
    entry = misuse_scan_run(app, misuse, scanner, close_holes)
    assert entry["batch"]["draft"] is True and entry["batch"]["new_before_pr"][0].startswith("`app/other.js`")
    assert len(scanner["scanned"]) == 2 and scanner["scanned"][-1]["app/third.js"] == "closed two\n"
    assert len(entry["batch"]["misuse_fixes"]) == 2  # kept, its own commit, for a person to revert


def test_clean_misuse_fixes_stay_ready(app, misuse, scanner):
    entry = misuse_scan_run(app, misuse, scanner, close_holes)
    assert not entry["batch"].get("draft") and len(scanner["scanned"]) == 2


def test_no_misuse_fixes_means_no_second_scan(app, misuse, scanner):
    misuse_scan_run(app, misuse, scanner, lambda files: {})
    assert len(scanner["scanned"]) == 1


def test_a_finding_already_named_is_not_named_twice_after_the_misuse_fixes(app, misuse, scanner):
    scanner["adds"] = lambda files: [scan_finding(ADDED_ROUTE)]
    entry = misuse_scan_run(app, misuse, scanner, close_holes)
    assert entry["batch"]["rag_pr_text"].count("so this is a draft") == 1


def test_the_misuse_fixes_not_being_scanned_is_said(app, misuse, scanner):
    scanner["adds"] = lambda files: None if "closed one\n" in files.values() else []
    entry = misuse_scan_run(app, misuse, scanner, close_holes)
    assert "**Misuse fixes not scanned:**" in entry["batch"]["rag_pr_text"] and not entry["batch"].get("draft")

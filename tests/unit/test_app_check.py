"""The app check's own logic: nothing in it may depend on a particular app. Docker and the app are
faked: no containers, network or browser."""

from __future__ import annotations

import subprocess
import sys

import pytest

from agent import app_check
from agent.app_check import Result
from gitops import config

pytestmark = pytest.mark.unit

SETTINGS = {
    "ASVA_APP_COMPOSE_FILES": "first.yml second.yml",
    "ASVA_APP_READY_URL": "http://127.0.0.1:1234/ready",
    "ASVA_APP_SMOKE_COMMAND": "python smoke.py --at {url} --out {temp}/report.json --app {app}",
}


@pytest.fixture
def settings(monkeypatch):
    for name in ("ASVA_APP_SMOKE_RUNS", "ASVA_APP_SECURITY_COMMAND"):
        monkeypatch.delenv(name, raising=False)
    for name, value in SETTINGS.items():
        monkeypatch.setenv(name, value)


@pytest.fixture
def fake_app(tmp_path, monkeypatch, settings):
    """An app of any name, with docker and the test commands answering as the test says."""
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "target-apps/AnyApp")
    (tmp_path / "target-apps" / "AnyApp").mkdir(parents=True)
    (tmp_path / "target-apps" / "AnyApp" / "app.txt").write_text("original", encoding="utf-8")
    state = {"commands": [], "answers": [], "seen_file": None, "repo": str(tmp_path), "envs": []}

    def run(command, cwd, timeout=0, env=None):
        state["commands"].append(command)
        if command[:2] == ["docker", "compose"] and "build" in command:
            state["seen_file"] = (cwd / "app.txt").read_text(encoding="utf-8")
            return subprocess.CompletedProcess(command, state.get("up_code", 0), "", state.get("up_err", ""))
        if command[0] == sys.executable:
            state["envs"].append(env)
            return state["answers"].pop(0) if state["answers"] else subprocess.CompletedProcess(command, 0, "", "")
        return subprocess.CompletedProcess(command, 0, "abc123\n", "")

    monkeypatch.setattr(app_check, "_run", run)
    monkeypatch.setattr(app_check, "_answers", lambda url: state.get("ready", True))
    monkeypatch.setattr(app_check, "WAIT_SECONDS", 0)
    return state


def failed(text):
    return subprocess.CompletedProcess([], 1, text, "")


# -- settings --------------------------------------------------------------------------------------

@pytest.mark.parametrize("missing", list(SETTINGS))
def test_an_app_without_all_its_settings_is_not_supported(settings, monkeypatch, missing):
    assert app_check.supported()
    monkeypatch.delenv(missing)
    assert not app_check.supported()
    assert app_check.check({}).stage == "unavailable"


def test_the_code_names_no_app():
    source = (app_check.ROOT / "agent" / "app_check.py").read_text(encoding="utf-8").lower()
    for name in ("nodegoat", "pygoat", "vulnbank", "mongo"):
        assert name not in source


def test_the_compose_files_and_the_copy_come_from_the_settings(fake_app):
    assert app_check.check({"app.txt": "the fix"}, fake_app["repo"]).passed
    up = next(c for c in fake_app["commands"] if "build" in c)
    assert up[up.index("-f"):up.index("build")] == ["-f", "first.yml", "-f", "second.yml"]
    assert fake_app["seen_file"] == "the fix"  # the copy has the candidate's files


def test_placeholders_and_python_are_filled_in_and_the_address_is_passed_on(fake_app):
    app_check.check({}, fake_app["repo"])
    smoke = next(c for c in fake_app["commands"] if c[0] == sys.executable)
    assert smoke[1:4] == ["smoke.py", "--at", "http://127.0.0.1:1234"]
    assert smoke[5].endswith("report.json") and "{temp}" not in smoke[5] and "{app}" not in smoke[7]
    assert fake_app["envs"][0]["BASE_URL"] == "http://127.0.0.1:1234"


# -- what counts as passing ------------------------------------------------------------------------

def test_a_smoke_test_that_passes_by_luck_is_caught_by_the_repeat_runs(fake_app):
    fake_app["answers"] = [subprocess.CompletedProcess([], 0, "", ""), failed("FAILED login: did not reach home\n")]
    result = app_check.check({}, fake_app["repo"])
    assert result == Result(False, "smoke", "FAILED login: did not reach home", result.log)


def test_the_smoke_test_passes_only_when_every_run_does(fake_app):
    assert app_check.check({}, fake_app["repo"]).passed
    assert sum(c[0] == sys.executable for c in fake_app["commands"]) == 3


def test_an_app_can_ask_for_one_smoke_run(fake_app, monkeypatch):
    monkeypatch.setenv("ASVA_APP_SMOKE_RUNS", "1")
    app_check.check({}, fake_app["repo"])
    assert sum(c[0] == sys.executable for c in fake_app["commands"]) == 1


def test_a_failure_without_failed_lines_shows_the_end_of_the_output(fake_app):
    fake_app["answers"] = [failed("line 1\nline 2\nsomething broke\n")]
    assert "something broke" in app_check.check({}, fake_app["repo"]).detail


def test_a_failed_build_stops_there_and_names_the_package(fake_app):
    fake_app["up_code"] = 1
    fake_app["up_err"] = "#12 5.6 Collecting PyYAML==5.4\n#12 7.6   × Getting requirements to build wheel did not run successfully.\n"
    result = app_check.check({}, fake_app["repo"])
    assert result.stage == "build" and result.detail.startswith("pip failed at PyYAML==5.4")


def test_pip_not_finding_a_package_names_that_package_not_the_one_before_it(fake_app):
    fake_app["up_code"] = 1
    fake_app["up_err"] = "#12 5.6 Collecting graphene==3.3\n#12 7.6 ERROR: Could not find a version that satisfies the requirement nope==9\n"
    assert app_check.check({}, fake_app["repo"]).detail == "ERROR: Could not find a version that satisfies the requirement nope==9"


def test_a_build_that_is_not_pip_still_gives_its_error(fake_app):
    fake_app["up_code"] = 1
    fake_app["up_err"] = "#7 1.2 added 3 packages\n#7 2.1 npm error code E404\n#8 DONE 0.0s\n"
    assert app_check.check({}, fake_app["repo"]).detail == "npm error code E404"


def test_a_container_compose_gave_up_on_failed_to_start_not_to_build(fake_app, monkeypatch):
    faked = app_check._run

    def run(command, cwd, timeout=0, env=None):
        if "up" in command:
            return subprocess.CompletedProcess(command, 1, "", "dependency failed to start: container web is unhealthy\n")
        return faked(command, cwd, timeout, env)

    monkeypatch.setattr(app_check, "_run", run)
    result = app_check.check({}, fake_app["repo"])
    assert (result.stage, result.detail) == ("start", "dependency failed to start: container web is unhealthy")


def test_an_app_that_never_answers_failed_to_start(fake_app):
    fake_app["ready"] = False
    assert app_check.check({}, fake_app["repo"]).stage == "start"


def test_docker_missing_means_the_check_could_not_run_not_that_the_fix_is_bad(fake_app, monkeypatch):
    def run(*args, **kwargs):
        raise FileNotFoundError("docker")

    monkeypatch.setattr(app_check, "_run", run)
    assert app_check.check({}, fake_app["repo"]).stage == "unavailable"


# -- security tests --------------------------------------------------------------------------------

def test_security_tests_get_the_candidate_copy_and_the_names_to_run(fake_app, monkeypatch):
    monkeypatch.setenv("ASVA_APP_SMOKE_RUNS", "1")
    monkeypatch.setenv("ASVA_APP_SECURITY_COMMAND", 'python -m pytest -k "{tests}"')
    assert app_check.check({}, fake_app["repo"], ["test_a", "test_b"]).passed
    security = [c for c in fake_app["commands"] if c[0] == sys.executable][-1]
    assert security[-1] == "test_a or test_b"
    env = fake_app["envs"][-1]
    assert env["TARGET"] == "candidate" and env["ASVA_CANDIDATE_SHA"] == "abc123" and "app" in env["ASVA_APP_PATH"]


def test_smoke_and_security_failures_are_both_reported(fake_app, monkeypatch):
    monkeypatch.setenv("ASVA_APP_SMOKE_RUNS", "1")
    monkeypatch.setenv("ASVA_APP_SECURITY_COMMAND", 'python -m pytest -k "{tests}"')
    fake_app["answers"] = [failed("FAILED smoke_one\n"), failed("FAILED security_one\n")]
    assert app_check.check({}, fake_app["repo"], ["t"]).detail == "FAILED smoke_one | FAILED security_one"


def test_no_security_command_means_no_security_run_even_if_tests_are_asked_for(fake_app, monkeypatch):
    monkeypatch.setenv("ASVA_APP_SMOKE_RUNS", "1")
    assert app_check.check({}, fake_app["repo"], ["t"]).passed
    assert sum(c[0] == sys.executable for c in fake_app["commands"]) == 1

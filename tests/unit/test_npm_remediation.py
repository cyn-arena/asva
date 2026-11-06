"""Dependency generation and atomic GitOps submission; no registry, LLM or GitHub calls."""

import copy
import json
from pathlib import Path
import subprocess
from types import SimpleNamespace

import pytest

from agent import agent_loop, npm_remediation as npm
from gitops import config, git_gh_ops as ops
from gitops.dependency_validation import validate_pair

pytestmark = pytest.mark.unit


def dependency_pair(version="1.0.0"):
    manifest = {"name": "fixture", "version": "1.0.0", "dependencies": {"example": version},
                "scripts": {"postinstall": "must-not-run"}}
    lock = {"lockfileVersion": 2, "packages": {
        "": copy.deepcopy(manifest), "node_modules/example": {"version": version}}}
    return manifest, lock


def batch(spec="example@2.0.0"):
    return {"batch_id": "asva_sca_trial", "batch_type": "sca", "files_to_fix": [{
        "file": "package-lock.json", "findings": [{"finding_id": "one",
        "remediation": {"upgrade_to": spec}}]}]}


@pytest.fixture
def source(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "target-apps/NodeGoat")
    app = tmp_path / config.FIX_PATH_PREFIX
    app.mkdir(parents=True)
    for name, data in zip(("package.json", "package-lock.json"), dependency_pair()):
        (app / name).write_text(json.dumps(data), encoding="utf-8")
    return tmp_path, app


def fake_npm(monkeypatch, *, failure=False, inconsistent=False):
    calls = []
    monkeypatch.setattr(npm.shutil, "which", lambda _: "/tools/npm")
    def run(command, **kwargs):
        calls.append((command, kwargs))
        if command[-1] == "--version":
            return SimpleNamespace(returncode=0, stdout="8.19.4", stderr="")
        if failure:
            return SimpleNamespace(returncode=1, stdout="", stderr="dependency conflict")
        work = Path(kwargs["cwd"])
        manifest = json.loads((work / "package.json").read_text())
        _, lock = dependency_pair("1.0.0" if inconsistent else manifest["dependencies"]["example"])
        (work / "package-lock.json").write_text(json.dumps(lock))
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")
    monkeypatch.setattr(npm.subprocess, "run", run)
    return calls


def test_generation_isolated_and_credentials_not_forwarded(source, monkeypatch):
    root, app = source
    before = {p.name: p.read_bytes() for p in app.iterdir()}
    monkeypatch.setenv("GH_TOKEN", "private")
    monkeypatch.setenv("OLLAMA_API_KEY", "private")
    calls = fake_npm(monkeypatch)
    entry = npm.generate(batch(), str(root))
    assert entry["generation"]["status"] == "generated"
    assert {p.name: p.read_bytes() for p in app.iterdir()} == before
    assert {f["path"] for f in entry["files"]} == {"package.json", "package-lock.json"}
    assert "--ignore-scripts" in calls[1][0]
    assert "--package-lock-only" in calls[1][0]
    assert "GH_TOKEN" not in calls[1][1]["env"]
    assert "OLLAMA_API_KEY" not in calls[1][1]["env"]
    assert "--force" not in calls[1][0]


@pytest.mark.parametrize("spec", ["example@latest", "example@2.0.0;echo bad", "other@2.0.0", None])
def test_unsupported_recommendations_are_reported_without_npm(spec, source, monkeypatch):
    calls = fake_npm(monkeypatch)
    result = npm.generate(batch(spec), str(source[0]))
    assert result["generation"]["status"] == "no_candidate"
    assert result["generation"]["unresolved"]
    assert not result["files"] and not calls


def test_upgrade_plan_handles_scoped_parents_and_keeps_highest_version():
    manifest, lock = dependency_pair()
    manifest["devDependencies"] = {"@scope/parent": "1.0.0"}
    b = batch("@scope/parent@2.0.0")
    b["files_to_fix"][0]["findings"].append({"remediation": {"upgrade_to": "@scope/parent@3.0.0"}})
    upgrades, unresolved = npm.upgrade_plan(b, manifest, lock)
    assert upgrades == {"@scope/parent": {"section": "devDependencies", "from": "1.0.0", "to": "3.0.0"}}
    assert not unresolved


def test_no_downgrades():
    manifest, lock = dependency_pair("3.0.0")
    assert npm.upgrade_plan(batch(), manifest, lock) == ({}, [])


@pytest.mark.parametrize("options", [{"failure": True}, {"inconsistent": True}])
def test_failed_or_inconsistent_resolution_never_returns_partial_pair(source, monkeypatch, options):
    fake_npm(monkeypatch, **options)
    entry = npm.generate(batch(), str(source[0]))
    assert entry["generation"]["status"] == "error"
    assert entry["files"] == []


def test_npm_mode_is_opt_in_and_works_for_any_app(monkeypatch):
    monkeypatch.setenv("ASVA_SCA_FIX_MODE", "npm")
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "target-apps/AnyApp")
    assert npm.enabled(batch())
    assert not npm.enabled({"batch_type": "sast"})
    monkeypatch.setenv("ASVA_SCA_FIX_MODE", "llm")
    assert not npm.enabled(batch())


def test_agent_routes_sca_to_npm_without_llm(source, monkeypatch, tmp_path):
    monkeypatch.setenv("ASVA_SCA_FIX_MODE", "npm")
    fake_npm(monkeypatch)
    monkeypatch.setattr(agent_loop, "call_llm", lambda _: pytest.fail("SCA must not call LLM"))
    path = tmp_path / "batch.json"
    path.write_text(json.dumps(batch()))
    assert agent_loop.process_batch(path, str(source[0]))["generation"]["status"] == "generated"


def test_llm_switch_restores_whole_lockfile_request(source, monkeypatch, tmp_path):
    monkeypatch.setenv("ASVA_SCA_FIX_MODE", "llm")
    b = batch()
    b.update(total_files=1, total_findings=1)
    b["files_to_fix"][0]["fix_type"] = "version_upgrade"
    path = tmp_path / "batch.json"
    path.write_text(json.dumps(b))
    requests = []
    def prompt(file, content, findings, fix_type, **_):
        requests.append((file, content, fix_type))
        return "PROMPT"
    monkeypatch.setattr(agent_loop, "build_fix_prompt", prompt)
    monkeypatch.setattr(agent_loop, "call_llm", lambda p: "whole-file AI response")
    monkeypatch.setattr(npm, "generate", lambda *args: pytest.fail("npm must not run in llm mode"))
    entry = agent_loop.process_batch(path, str(source[0]))
    assert entry["files"] == [{"path": "package-lock.json", "content": "whole-file AI response"}]
    assert requests == [("package-lock.json", (source[1] / "package-lock.json").read_text(), "version_upgrade")]
    assert entry["generation"]["method"] == "llm"
    assert entry["generation"]["files"] == [{"path": "package-lock.json", "status": "generated"}]


@pytest.mark.parametrize("reject", [None, "secret", "validity"])
def test_gitops_dependency_pair_committed_together_or_fully_restored(source, monkeypatch, reject):
    root, app = source
    def git(*args):
        return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True).stdout.strip()
    git("init")
    git("config", "user.name", "test")
    git("config", "user.email", "test@example.test")
    git("add", ".")
    git("commit", "-m", "initial")
    original = git("rev-parse", "HEAD")
    monkeypatch.setattr(ops, "create_branch", lambda *args: git("checkout", "-b", args[0]))
    monkeypatch.setattr(ops, "gate_file", lambda path, content:
                        (False, "secret") if reject == "secret" and path == "package-lock.json" else (True, None))
    pushes = []
    monkeypatch.setattr(ops, "push", lambda *args: pushes.append(args))
    monkeypatch.setattr(ops, "open_pr", lambda *args: "https://github.test/pull/1")
    manifest, lock = dependency_pair("2.0.0")
    b = batch()
    b["remediation_method"] = "npm"
    files = [{"path": name, "content": json.dumps(data)} for name, data in
             zip(("package.json", "package-lock.json"), (manifest, lock))]
    result = ops.submit_fix_batch(b, files, repo_dir=str(root), test_fn=lambda path:
                                 not (reject == "validity" and path == "package-lock.json"))
    assert git("status", "--porcelain") == ""
    assert git("rev-parse", "HEAD") == original
    if reject:
        assert result["status"] == "no_commits" and not pushes
        assert json.loads((app / "package.json").read_text())["dependencies"]["example"] == "1.0.0"
    else:
        assert result["status"] == "pr_opened" and pushes
        assert git("rev-list", "--count", original + "..fix/asva_sca_trial") == "1"
        assert len(git("diff", "--name-only", original, "fix/asva_sca_trial").splitlines()) == 2


def test_npm_failure_does_not_block_other_candidates(monkeypatch):
    failure = {"batch": batch(), "files": [], "generation": {
        "method": "npm", "status": "error", "message": "dependency conflict"}}
    other = {"batch": {"batch_id": "sast"}, "files": [{"path": "x.js", "content": "ok"}]}
    monkeypatch.setattr(ops, "submit_fix_batch", lambda b, *args, **kw: {
        "status": "pr_opened", "batch_id": b["batch_id"], "pr_url": "https://github.test/pull/1"})
    result = ops.submit_scan_cycle([failure, other])
    assert len(result["prs"]) == 2
    assert result["prs"][0]["generation"]["message"] == "dependency conflict"
    assert result["prs"][1]["status"] == "pr_opened"


@pytest.mark.parametrize("version,ok", [(1, False), (2, True), (3, True)])
def test_lockfile_versions_with_a_packages_section_are_accepted(version, ok):
    manifest, lock = dependency_pair()
    lock["lockfileVersion"] = version
    if ok:
        validate_pair(manifest, lock)
    else:
        with pytest.raises(ValueError):
            validate_pair(manifest, lock)


def _record_npm(monkeypatch, version="8.19.4"):
    calls = []

    def run(executable, args, work, env):
        calls.append(args)
        if args == ["--version"]:
            return version
        lock_path = work / "package-lock.json"
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        lock["packages"][""]["dependencies"] = json.loads((work / "package.json").read_text(encoding="utf-8"))["dependencies"]
        lock["packages"]["node_modules/example"]["version"] = "2.0.0"
        lock_path.write_text(json.dumps(lock), encoding="utf-8")
        return ""

    monkeypatch.setattr(npm, "_run_npm", run)
    monkeypatch.setattr(npm.shutil, "which", lambda name: "npm")
    return calls


def test_the_lockfile_stays_at_the_version_the_app_uses(source, monkeypatch):
    root, app = source
    lock = json.loads((app / "package-lock.json").read_text(encoding="utf-8"))
    lock["lockfileVersion"] = 3
    (app / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    calls = _record_npm(monkeypatch)
    monkeypatch.delenv("ASVA_NPM_VERSION", raising=False)
    result = npm.generate(batch(), str(root))
    assert result["generation"]["status"] == "generated", result["generation"]
    assert "--lockfile-version=3" in next(c for c in calls if c[0] == "install")
    assert result["generation"]["npm_version"] == "8.19.4"


def test_an_app_can_pin_its_npm_version(source, monkeypatch):
    root, _ = source
    _record_npm(monkeypatch, version="10.0.0")
    monkeypatch.setenv("ASVA_NPM_VERSION", "8.19.4")
    result = npm.generate(batch(), str(root))
    assert result["generation"]["status"] == "error" and "8.19.4" in result["generation"]["message"]

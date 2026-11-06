"""Offline checks for scan provenance and fix branches when the target advances."""
import importlib.util
from pathlib import Path

import pytest

from gitops import git_gh_ops

pytestmark = pytest.mark.unit

spec = importlib.util.spec_from_file_location(
    "resolve_scan_source", Path(__file__).resolve().parents[2] / "scripts/resolve-scan-source.py")
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)
SHA = "a" * 40


def resolve(**kwargs):
    values = dict(use_current_artifacts=True, source_branch="feat/expand-app-support",
                  source_sha=SHA, scan_run_id="123", repository="example/asva", ref_type="branch")
    values.update(kwargs)
    return source.resolve_source(**values)


def test_current_scan_uses_explicit_source_without_querying_another_run():
    def unexpected_lookup(*args):
        pytest.fail("Explicit current-run inputs must not query a historical run")
    assert resolve(lookup=unexpected_lookup) == ("feat/expand-app-support", SHA)


@pytest.mark.parametrize("branch,sha", [("", SHA), ("feat/work", "")])
def test_current_scan_requires_both_inputs(branch, sha):
    with pytest.raises(ValueError, match="both"):
        resolve(source_branch=branch, source_sha=sha)


def test_historical_scan_uses_its_metadata_instead_of_caller_branch():
    calls = []
    def lookup(run_id, repository):
        calls.append((run_id, repository))
        return {"headBranch": "feat/older-scan", "headSha": "b" * 40, "event": "push"}
    assert resolve(use_current_artifacts=False, lookup=lookup) == ("feat/older-scan", "b" * 40)
    assert calls == [("123", "example/asva")]


def test_current_scan_without_inputs_uses_current_run_metadata():
    assert resolve(source_branch="", source_sha="", lookup=lambda *_: {
        "headBranch": "feat/manual", "headSha": SHA, "event": "workflow_dispatch"
    }) == ("feat/manual", SHA)


def test_pull_request_merge_artifacts_are_rejected():
    with pytest.raises(ValueError, match="branch push/manual"):
        resolve(use_current_artifacts=False, lookup=lambda *_: {
            "headBranch": "feat/work", "headSha": SHA, "event": "pull_request"})


def test_current_tag_run_is_rejected():
    with pytest.raises(ValueError, match="branch run"):
        resolve(ref_type="tag")


@pytest.mark.parametrize("sha", ["shortsha", "HEAD", "a" * 39, "a" * 40 + "\nOTHER=value"])
def test_invalid_source_sha_is_rejected(sha):
    with pytest.raises(ValueError, match="full commit SHA"):
        resolve(source_sha=sha)


def test_multiline_source_branch_is_rejected():
    with pytest.raises(ValueError, match="name a branch"):
        resolve(source_branch="feat/work\nOTHER=value")


def test_resolver_exports_target_and_revision(monkeypatch, tmp_path):
    output, environment = tmp_path / "output", tmp_path / "environment"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("GITHUB_ENV", str(environment))
    monkeypatch.setattr("sys.argv", ["resolve-scan-source.py", "--use-current-artifacts", "true",
                                   "--scan-run-id", "123", "--source-branch", "feat/work",
                                   "--source-sha", SHA, "--ref-type", "branch",
                                   "--repository", "example/asva"])
    source.main()
    assert output.read_text() == f"branch=feat/work\nsha={SHA}\n"
    assert environment.read_text() == f"GITHUB_BASE_BRANCH=feat/work\nASVA_SCANNED_SHA={SHA}\n"


def test_unconfigured_gitops_keeps_latest_base_behaviour(monkeypatch):
    monkeypatch.delenv("ASVA_SCANNED_SHA", raising=False)
    calls = []
    monkeypatch.setattr(git_gh_ops, "_run", lambda cmd, *_: calls.append(cmd) or "")
    git_gh_ops.create_branch("fix/check", "feat/work")
    assert calls == [["git", "fetch", "origin", "feat/work"],
                     ["git", "switch", "-C", "fix/check", "FETCH_HEAD"]]


def test_invalid_pin_fails_before_fetch(monkeypatch):
    monkeypatch.setenv("ASVA_SCANNED_SHA", "HEAD")
    calls = []
    monkeypatch.setattr(git_gh_ops, "_run", lambda cmd, *_: calls.append(cmd) or "")
    with pytest.raises(git_gh_ops.GitOpError, match="full Git commit SHA"):
        git_gh_ops.prepare_fix_source("feat/work")
    assert not calls


def test_unrelated_revision_cannot_create_fix_branch(monkeypatch):
    monkeypatch.setenv("ASVA_SCANNED_SHA", SHA)
    calls = []
    def run(cmd, *_):
        calls.append(cmd)
        if cmd[:2] == ["git", "merge-base"]:
            raise git_gh_ops.GitOpError("Scanned revision is not an ancestor")
        return ""
    monkeypatch.setattr(git_gh_ops, "_run", run)
    with pytest.raises(git_gh_ops.GitOpError, match="not an ancestor"):
        git_gh_ops.create_branch("fix/check", "feat/work")
    assert not any(cmd[1] == "switch" for cmd in calls)


def test_fix_branch_starts_at_scanned_commit_after_target_advances(monkeypatch, tmp_git_repo):
    repo = str(tmp_git_repo)
    run = git_gh_ops._run
    scanned_sha = run(["git", "rev-parse", "HEAD"], repo).strip()
    run(["git", "switch", "-c", "feat/work"], repo)
    (tmp_git_repo / "later.txt").write_text("newer development work\n")
    run(["git", "add", "later.txt"], repo)
    run(["git", "commit", "-m", "Target advances during AI generation"], repo)
    latest_sha = run(["git", "rev-parse", "HEAD"], repo).strip()
    monkeypatch.setenv("ASVA_SCANNED_SHA", scanned_sha)
    def local_fetch(cmd, repo_dir):
        if cmd[:3] == ["git", "fetch", "origin"]:
            # Keep transport offline; the fetch result is the advanced target commit.
            (tmp_git_repo / ".git/FETCH_HEAD").write_text(latest_sha + "\n")
            return ""
        return run(cmd, repo_dir)
    monkeypatch.setattr(git_gh_ops, "_run", local_fetch)
    git_gh_ops.create_branch("fix/check", "feat/work", repo)
    assert run(["git", "rev-parse", "HEAD"], repo).strip() == scanned_sha
    assert not (tmp_git_repo / "later.txt").exists()
    assert run(["git", "rev-parse", "feat/work"], repo).strip() == latest_sha

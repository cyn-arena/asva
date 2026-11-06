"""Source-reading validation must use the pinned candidate beside unchanged tooling."""
import json
import subprocess
from types import SimpleNamespace

import pytest

from agent.candidate_source import application_path, verify

pytestmark = pytest.mark.unit


def commit(repo):
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-qm", "fixture"], cwd=repo, check=True, capture_output=True)
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()


def test_corrected_candidate_is_checked_beside_unchanged_original(tmp_git_repo, tmp_path, monkeypatch):
    from tests.e2e.api import test_misuse_cases as checks
    original = tmp_path / "tooling/target-apps/NodeGoat/config/env/development.js"
    original.parent.mkdir(parents=True)
    original.write_text("module.exports={zapApiKey:'unchanged-literal'};", encoding="utf-8")
    candidate = tmp_git_repo / "target-apps/NodeGoat"
    config = candidate / "config/env/development.js"
    config.parent.mkdir(parents=True)
    config.write_text("module.exports={zapApiKey:process.env.ZAP_API_KEY};", encoding="utf-8")
    sha = commit(tmp_git_repo)
    monkeypatch.setenv("TARGET", "candidate")
    monkeypatch.setenv("ASVA_APP_PATH", str(candidate))
    monkeypatch.setenv("ASVA_CANDIDATE_SHA", sha)
    monkeypatch.setattr(checks, "TARGET", "candidate")
    monkeypatch.setattr(checks, "REPO_ROOT", original.parents[4])
    calls = []

    def run(args, cwd, **kwargs):
        calls.append((args, cwd))
        assert cwd == candidate.resolve()
        if args[0] == "snyk":
            report = next(a.split("=", 1)[1] for a in args if a.startswith("--sarif-file-output="))
            from pathlib import Path
            Path(report).write_text(json.dumps({"runs": [{"results": []}]}), encoding="utf-8")
        return SimpleNamespace(returncode=0, stderr="", stdout="")

    monkeypatch.setattr(checks, "subprocess", SimpleNamespace(run=run))
    checks.test_development_zap_key_uses_environment_and_rescans_clean(tmp_path)
    assert [args[0] for args, _ in calls] == ["node", "snyk"]
    assert "unchanged-literal" in original.read_text(encoding="utf-8")


def test_candidate_path_and_full_sha_are_required(tmp_git_repo, monkeypatch):
    monkeypatch.setenv("TARGET", "candidate")
    monkeypatch.delenv("ASVA_APP_PATH", raising=False)
    with pytest.raises(ValueError, match="ASVA_APP_PATH"):
        application_path(tmp_git_repo)
    with pytest.raises(ValueError, match="full expected"):
        verify(tmp_git_repo, "abc")
    with pytest.raises(ValueError, match="SHA mismatch"):
        verify(tmp_git_repo, "0" * 40)


def test_candidate_tracked_changes_are_rejected(tmp_git_repo):
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=tmp_git_repo, text=True).strip()
    (tmp_git_repo / "app/existing.js").write_text("changed", encoding="utf-8")
    with pytest.raises(ValueError, match="tracked changes"):
        verify(tmp_git_repo / "app", sha)

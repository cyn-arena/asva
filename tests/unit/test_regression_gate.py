"""Unit tests for agent/regression_gate.py — the pre-commit validity gate wired in as
submit_fix_batch's test_fn. subprocess is always mocked; no real node/python/docker
toolchain is invoked."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import pytest

from agent import regression_gate
from agent.regression_gate import check
from gitops import config

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _no_fix_path_prefix(monkeypatch):
    """These tests assert on `repo_dir`-joined paths directly, so pin FIX_PATH_PREFIX to
    empty regardless of what a local .env sets it to (see test_git_gh_ops.py for the same
    convention) -- otherwise they'd only pass by accident of environment."""
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "")


@dataclass
class FakeCompletedProcess:
    returncode: int
    stdout: str = ""
    stderr: str = ""


def _patch_run(monkeypatch, returncode: int):
    calls = []

    def fake_run(cmd, capture_output=True, text=True):
        calls.append(cmd)
        return FakeCompletedProcess(returncode=returncode)

    monkeypatch.setattr(regression_gate.subprocess, "run", fake_run)
    return calls


# --------------------------------------------------------------------------------------
# Valid / broken syntax per file type
# --------------------------------------------------------------------------------------

def test_check_js_valid_syntax_passes(monkeypatch, tmp_path):
    _patch_run(monkeypatch, returncode=0)
    (tmp_path / "x.js").write_text("const x = 1;", encoding="utf-8")
    assert check("x.js", repo_dir=str(tmp_path)) is True


def test_check_js_broken_syntax_fails(monkeypatch, tmp_path):
    _patch_run(monkeypatch, returncode=1)
    (tmp_path / "x.js").write_text("const x = (;", encoding="utf-8")
    assert check("x.js", repo_dir=str(tmp_path)) is False


def test_check_python_valid_syntax_passes(monkeypatch, tmp_path):
    _patch_run(monkeypatch, returncode=0)
    (tmp_path / "x.py").write_text("x = 1", encoding="utf-8")
    assert check("x.py", repo_dir=str(tmp_path)) is True


def test_check_python_broken_syntax_fails(monkeypatch, tmp_path):
    _patch_run(monkeypatch, returncode=1)
    (tmp_path / "x.py").write_text("def f(:", encoding="utf-8")
    assert check("x.py", repo_dir=str(tmp_path)) is False


def test_check_docker_compose_valid_passes(monkeypatch, tmp_path):
    _patch_run(monkeypatch, returncode=0)
    (tmp_path / "docker-compose.yml").write_text("services: {}", encoding="utf-8")
    assert check("docker-compose.yml", repo_dir=str(tmp_path)) is True


def test_check_docker_compose_broken_fails(monkeypatch, tmp_path):
    _patch_run(monkeypatch, returncode=1)
    (tmp_path / "docker-compose.yaml").write_text("not: [valid", encoding="utf-8")
    assert check("docker-compose.yaml", repo_dir=str(tmp_path)) is False


@pytest.mark.parametrize("name", ["compose.yml", "compose.yaml"])
def test_check_compose_default_filenames_use_the_compose_validator(monkeypatch, tmp_path, name):
    calls = _patch_run(monkeypatch, returncode=1)
    (tmp_path / name).write_text("not: [valid", encoding="utf-8")
    assert check(name, repo_dir=str(tmp_path)) is False
    assert calls[0][:2] == ["docker", "compose"]


# --------------------------------------------------------------------------------------
# Unknown file types pass through without running anything
# --------------------------------------------------------------------------------------

def test_check_unknown_extension_passes_without_running_subprocess(monkeypatch, tmp_path):
    def fail_if_called(*a, **k):
        raise AssertionError("subprocess.run should not be called for an unknown file type")

    monkeypatch.setattr(regression_gate.subprocess, "run", fail_if_called)
    (tmp_path / "README.md").write_text("docs", encoding="utf-8")
    assert check("README.md", repo_dir=str(tmp_path)) is True


# --------------------------------------------------------------------------------------
# Missing toolchain — fail-closed by default, fail-open when configured
# --------------------------------------------------------------------------------------

def test_check_missing_toolchain_fails_closed_by_default(monkeypatch, tmp_path):
    def fake_run(cmd, capture_output=True, text=True):
        raise FileNotFoundError("node not found")

    monkeypatch.setattr(regression_gate.subprocess, "run", fake_run)
    monkeypatch.setattr(regression_gate, "FAIL_OPEN", False)
    (tmp_path / "x.js").write_text("const x = 1;", encoding="utf-8")
    assert check("x.js", repo_dir=str(tmp_path)) is False


def test_check_missing_toolchain_passes_when_fail_open(monkeypatch, tmp_path):
    def fake_run(cmd, capture_output=True, text=True):
        raise FileNotFoundError("node not found")

    monkeypatch.setattr(regression_gate.subprocess, "run", fake_run)
    monkeypatch.setattr(regression_gate, "FAIL_OPEN", True)
    (tmp_path / "x.js").write_text("const x = 1;", encoding="utf-8")
    assert check("x.js", repo_dir=str(tmp_path)) is True


# --------------------------------------------------------------------------------------
# repo_dir joining — the validator receives the full on-disk path, not the bare finding path
# --------------------------------------------------------------------------------------

def test_check_invokes_validator_on_full_repo_dir_joined_path(monkeypatch, tmp_path):
    calls = _patch_run(monkeypatch, returncode=0)
    nested = tmp_path / "app" / "routes"
    nested.mkdir(parents=True)
    (nested / "x.js").write_text("const x = 1;", encoding="utf-8")

    check("app/routes/x.js", repo_dir=str(tmp_path))

    assert calls == [["node", "--check", str(tmp_path / "app" / "routes" / "x.js")]]


def test_check_applies_fix_path_prefix_like_every_other_disk_path(monkeypatch, tmp_path):
    """Check resolves app-relative paths through FIX_PATH_PREFIX."""
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "target-apps/NodeGoat")
    calls = _patch_run(monkeypatch, returncode=0)
    nested = tmp_path / "target-apps" / "NodeGoat" / "app" / "routes"
    nested.mkdir(parents=True)
    (nested / "x.js").write_text("const x = 1;", encoding="utf-8")

    result = check("app/routes/x.js", repo_dir=str(tmp_path))

    assert result is True
    assert calls == [["node", "--check", str(nested / "x.js")]]

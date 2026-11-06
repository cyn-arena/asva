"""Shared fixtures for the ASVA test suite (Section 5).

Fixture data under tests/fixtures/ is trimmed from real pipeline output (real SARIF scans,
real triage batches) rather than hand-invented — see tests/fixtures/README.md for what each
family contains and how to regenerate it.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

# Set defaults before importing agent_loop because llm_client creates its client at import time.
# setdefault lets real environment values override these unit-test values.
os.environ.setdefault("OLLAMA_HOST", "http://localhost:11434")
os.environ.setdefault("OLLAMA_API_KEY", "test-key")
os.environ.setdefault("OLLAMA_MODEL", "test-model")


@pytest.fixture(autouse=True)
def isolated_memory(tmp_path, monkeypatch):
    """Every test gets its own empty memory DB and no reviewer decisions, so results never
    depend on memory/asva_memory.db or the sample memory/decisions.json in the checkout."""
    from memory import memory_store
    monkeypatch.setattr(memory_store, "DB_PATH", tmp_path / "asva_memory.db")
    monkeypatch.setenv("ASVA_DECISIONS_PATH", str(tmp_path / "no-decisions.json"))


@pytest.fixture
def sarif_sample_path() -> dict[str, Path]:
    """scan_source -> trimmed SARIF fixture path (tests/fixtures/sarif/)."""
    d = FIXTURES_DIR / "sarif"
    return {
        "sca": d / "sca_sample.sarif.json",
        "container": d / "container_sample.sarif.json",
        "sast": d / "sast_sample.sarif.json",
    }


@pytest.fixture
def batch_sample() -> dict[str, dict]:
    """batch_type -> real triage batch dict (tests/fixtures/batches/), for git_gh_ops /
    agent_loop tests that need a realistic batch shape without re-deriving one."""
    d = FIXTURES_DIR / "batches"

    def _load(name: str) -> dict:
        return json.loads((d / name).read_text(encoding="utf-8"))

    return {
        "sast": _load("asva_sast_e6919194_1.json"),
        "sca": _load("asva_sca_e6919194.json"),
        "container": _load("asva_container_e6919194.json"),
    }


@pytest.fixture
def ranked_findings_sample() -> list[dict]:
    """The real (classified, 42-entry) ranked_findings.json — triage.build_batches' input
    shape, for testing batch naming/splitting against real data."""
    path = FIXTURES_DIR / "findings" / "ranked_findings_sample.json"
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.fixture
def fake_llm(monkeypatch):
    """Mock agent.agent_loop.call_llm so unit tests never hit a real LLM endpoint.

    Set `fake_llm.response` for a canned reply, or `fake_llm.side_effect` to an exception
    instance (to simulate an LLM failure) or a callable(prompt) -> str.
    """

    class FakeLLM:
        response = "// fixed content\n"
        side_effect = None

        def __init__(self) -> None:
            self.calls: list[str] = []

        def __call__(self, prompt: str) -> str:
            self.calls.append(prompt)
            if isinstance(self.side_effect, Exception):
                raise self.side_effect
            if callable(self.side_effect):
                return self.side_effect(prompt)
            return self.response

    fake = FakeLLM()
    monkeypatch.setattr("agent.agent_loop.call_llm", fake)
    return fake


@pytest.fixture
def tmp_git_repo(tmp_path) -> Path:
    """A throwaway git repo (one committed file under app/) for git_gh_ops / regression_gate
    tests that need real git plumbing — never touches this repo's own working tree."""
    repo = tmp_path / "repo"
    repo.mkdir()

    def run(*args: str) -> None:
        subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)

    run("init", "-q")
    run("config", "user.email", "test@example.com")
    run("config", "user.name", "Test")
    (repo / "app").mkdir()
    (repo / "app" / "existing.js").write_text("module.exports = {};\n", encoding="utf-8")
    run("add", "-A")
    run("commit", "-q", "-m", "initial")
    return repo


@pytest.fixture
def target_base_url() -> str:
    """BASE_URL of the running NodeGoat target (dvng1=blue, dvng2=green). Skips the test
    when unset so `-m unit` runs never require a live target.

    Named target_base_url (not base_url) because pytest-playwright already owns a
    session-scoped `base_url` fixture for Page.goto — reusing that name collides with it.
    """
    url = os.environ.get("BASE_URL")
    if not url:
        pytest.skip("BASE_URL not set — this test needs a running NodeGoat target")
    return url.rstrip("/")

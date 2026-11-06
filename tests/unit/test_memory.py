"""Memory (3.5): what is saved after a pass and what the next pass's prompt is given.

Memory = Decisions + Code Context, where
Code Context = remediated files committed in passes 1 to N-1 + errors from pass N-1 only.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from agent import agent_loop
from gitops import config
from memory import memory_store
from memory.memory_context import build_memory_context, previous_errors

pytestmark = pytest.mark.unit

MONGO_ERROR = "start: the app did not start: MongoDB cannot start: Linux kernel versions 6.19 and newer"


def _row(run_id, outcome, content, error=None, created_at="2026-11-01 10:00:00"):
    return {"run_id": run_id, "outcome": outcome, "fix_summary": f"{outcome} in run {run_id}",
            "fixed_content": content, "error": error, "created_at": created_at}


# -- the store ------------------------------------------------------------------------------------

def test_an_existing_db_without_the_error_column_gets_it(monkeypatch):
    with sqlite3.connect(memory_store.DB_PATH) as conn:  # the schema before errors were saved
        conn.execute("CREATE TABLE fix_history (id INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL, "
                     "file TEXT NOT NULL, finding_type TEXT, rule_id TEXT, run_id TEXT, outcome TEXT, "
                     "fix_summary TEXT, fixed_content TEXT, created_at TEXT DEFAULT (datetime('now')))")
    monkeypatch.setattr(memory_store, "_schema_ready_for", None)
    memory_store.init_db()
    with memory_store.get_connection() as conn:
        columns = {r["name"] for r in conn.execute("PRAGMA table_info(fix_history)")}
    assert "error" in columns


def test_an_error_is_saved_and_loaded_with_its_attempt():
    memory_store.save_fix("fp", "app/x.js", "sast", "r1", "run-1", "committed", "s", "v1", error=MONGO_ERROR)
    memory_store.save_fix("fp", "app/x.js", "sast", "r1", "run-2", "committed", "s", "v2")
    rows = {r["run_id"]: r for r in memory_store.load_memory("fp")}
    assert rows["run-1"]["error"] == MONGO_ERROR and rows["run-2"]["error"] is None


# -- the prompt's memory section ------------------------------------------------------------------

def test_errors_come_from_the_previous_pass_only():
    history = [_row("100", "committed", "A", "old error", "2026-11-01 10:00:00"),
               _row("200", "committed", "B", MONGO_ERROR, "2026-11-02 10:00:00")]
    assert previous_errors(history) == ("200", [MONGO_ERROR])
    text = build_memory_context({"history": history})
    assert "Errors from the previous pass (run 200)" in text and "MongoDB cannot start" in text
    assert "old error" not in text


def test_a_clean_previous_pass_means_no_errors_even_if_an_older_one_failed():
    history = [_row("100", "committed", "A", MONGO_ERROR, "2026-11-01 10:00:00"),
               _row("200", "committed", "B", None, "2026-11-02 10:00:00")]
    assert previous_errors(history) == (None, [])
    assert "Errors from the previous pass" not in build_memory_context({"history": history})


def test_only_committed_attempts_are_shown_as_code():
    history = [_row("100", "committed", "COMMITTED CODE"),
               _row("old", "pending", "PENDING CODE"),
               _row("101", "rejected", "REJECTED CODE"),
               _row("102", "dry_run", "DRY RUN CODE")]
    text = build_memory_context({"history": history})
    assert "COMMITTED CODE" in text
    assert not any(c in text for c in ("PENDING CODE", "REJECTED CODE", "DRY RUN CODE"))


def test_a_long_error_is_cut_down():
    text = build_memory_context({"history": [_row("200", "committed", "B", "x" * 5000)]})
    assert "... [truncated]" in text and "x" * 1600 not in text


# -- passes 1, 2 and 3 through process_batch -----------------------------------------------------

@pytest.fixture
def app_repo(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "")
    (tmp_path / "repo" / "app").mkdir(parents=True)
    (tmp_path / "repo" / "app" / "x.js").write_text("original", encoding="utf-8")
    batch = {"batch_id": "asva_sast_test_1", "batch_type": "sast", "total_files": 1, "total_findings": 1,
             "files_to_fix": [{"file": "app/x.js", "fix_type": "code_change", "findings": [{
                 "finding_type": "sast", "title": "t", "description": "d",
                 "identifiers": {"rule_id": "js/Ssrf"}, "location": {"file": "app/x.js", "line": 16}}]}]}
    path = tmp_path / "batch.json"
    path.write_text(json.dumps(batch), encoding="utf-8")
    return {"repo": str(tmp_path / "repo"), "batch": path}


def _pass(app_repo, monkeypatch, run_id, check_failure=None):
    """One pipeline pass: fix, (optionally) fail the pre-PR check, commit, save to memory."""
    monkeypatch.setattr(agent_loop, "RUN_ID", run_id)
    entry = agent_loop.process_batch(app_repo["batch"], app_repo["repo"], use_repo_context=False)
    if check_failure:
        entry["check_failures"] = {"app/x.js": check_failure}  # what agent/test_first.py records
    prs = [{"batch_id": "asva_sast_test_1", "status": "pr_opened", "pr_url": f"https://pr/{run_id}",
            "committed": ["app/x.js"], "blocked": [], "failed": []}]
    agent_loop.save_cycle_to_memory([entry], prs, {})
    return entry


def test_pass_n_is_told_what_pass_n_minus_1_broke(app_repo, fake_llm, monkeypatch):
    fake_llm.response = "mongo:8.0 attempt"
    _pass(app_repo, monkeypatch, "run-1", check_failure=MONGO_ERROR)          # pass 1 fails its check

    fake_llm.response = "mongo:4.4.x attempt"
    _pass(app_repo, monkeypatch, "run-2")                                      # pass 2
    prompt = fake_llm.calls[-1]
    assert "Errors from the previous pass (run run-1)" in prompt and "MongoDB cannot start" in prompt
    assert "mongo:8.0 attempt" in prompt                                        # pass 1's committed fix

    _pass(app_repo, monkeypatch, "run-3")                                      # pass 3
    prompt = fake_llm.calls[-1]
    assert "Errors from the previous pass" not in prompt                       # pass 2 broke nothing
    assert "mongo:8.0 attempt" in prompt and "mongo:4.4.x attempt" in prompt   # passes 1 to N-1


def test_a_gate_rejection_is_remembered_as_the_error(app_repo, fake_llm, monkeypatch):
    monkeypatch.setattr(agent_loop, "RUN_ID", "run-1")
    entry = agent_loop.process_batch(app_repo["batch"], app_repo["repo"], use_repo_context=False)
    prs = [{"batch_id": "asva_sast_test_1", "status": "no_commits", "committed": [], "blocked": [],
            "failed": [{"path": "app/x.js", "reason": "tests failed after 3 attempt(s)"}]}]
    agent_loop.save_cycle_to_memory([entry], prs, {})

    agent_loop.process_batch(app_repo["batch"], app_repo["repo"], use_repo_context=False)
    prompt = fake_llm.calls[-1]
    assert "Errors from the previous pass (run run-1)" in prompt and "tests failed after 3 attempt(s)" in prompt

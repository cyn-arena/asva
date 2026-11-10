"""scripts/merge_memory.py: the parallel fix jobs' memory rows end up in one database."""

import sqlite3

import pytest

from memory import memory_store
from scripts import merge_memory

pytestmark = pytest.mark.unit


def _db(path, rows):
    """A memory database like a fix job leaves: the saved rows plus its own."""
    path.parent.mkdir(parents=True, exist_ok=True)
    memory_store.DB_PATH = path
    conn = memory_store.get_connection()
    with conn:
        for fingerprint, run_id in rows:
            conn.execute("INSERT INTO fix_history (fingerprint, file, run_id, outcome) VALUES (?, ?, ?, 'committed')",
                         (fingerprint, f"{fingerprint}.js", run_id))
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.close()


def _rows(path):
    conn = sqlite3.connect(path)
    try:
        return sorted(conn.execute("SELECT fingerprint, run_id FROM fix_history").fetchall())
    finally:
        conn.close()


@pytest.fixture(autouse=True)
def _restore_db_path(monkeypatch):
    monkeypatch.setattr(memory_store, "DB_PATH", memory_store.DB_PATH)


def test_each_jobs_rows_from_this_run_are_kept(tmp_path):
    _db(tmp_path / "base.db", [("old", "1")])
    _db(tmp_path / "parts" / "fixmem-sast" / "asva_memory.db", [("old", "1"), ("a", "9")])
    _db(tmp_path / "parts" / "fixmem-sca" / "asva_memory.db", [("old", "1"), ("b", "9"), ("c", "9")])
    assert merge_memory.merge(tmp_path / "base.db", tmp_path / "parts", "9") == 3
    assert _rows(tmp_path / "base.db") == [("a", "9"), ("b", "9"), ("c", "9"), ("old", "1")]


def test_merging_the_same_run_again_does_not_double_it(tmp_path):
    _db(tmp_path / "base.db", [])
    _db(tmp_path / "parts" / "fixmem-sast" / "asva_memory.db", [("a", "9")])
    merge_memory.merge(tmp_path / "base.db", tmp_path / "parts", "9")
    merge_memory.merge(tmp_path / "base.db", tmp_path / "parts", "9")
    assert _rows(tmp_path / "base.db") == [("a", "9")]


def test_a_first_run_creates_the_database(tmp_path):
    _db(tmp_path / "parts" / "fixmem-sast" / "asva_memory.db", [("a", "9")])
    assert merge_memory.merge(tmp_path / "new.db", tmp_path / "parts", "9") == 1
    assert _rows(tmp_path / "new.db") == [("a", "9")]


def test_no_parts_leaves_the_saved_rows(tmp_path):
    _db(tmp_path / "base.db", [("old", "1")])
    assert merge_memory.merge(tmp_path / "base.db", tmp_path / "missing", "9") == 0
    assert _rows(tmp_path / "base.db") == [("old", "1")]

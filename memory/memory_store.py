"""
memory/memory_store.py
======================
SQLite-backed memory store for ASVA memory injection.

Schema:
  fix_history  — one row per fix attempt per vulnerability fingerprint
Reviewer decisions come from the dashboard's decisions.json (memory/decisions_loader.py).
"""

import sqlite3
from pathlib import Path
from datetime import datetime, timezone

# SQLite file sits alongside this module
DB_PATH = Path(__file__).parent / "asva_memory.db"


# ===========================================================================
# CONNECTION
# ===========================================================================

# DB_PATH whose schema has been ensured in this process (tests repoint DB_PATH).
_schema_ready_for = None


def get_connection() -> sqlite3.Connection:
    global _schema_ready_for
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row 
    conn.execute("PRAGMA journal_mode=WAL")  
    # Create tables on first use, so readers/writers work even if init_db() wasn't called.
    if _schema_ready_for != DB_PATH:
        _create_schema(conn)
        _schema_ready_for = DB_PATH
    return conn


# ===========================================================================
# INITIALISE
# ===========================================================================

def init_db() -> None:
    """Create tables if they don't exist. Safe to call on every run."""
    with get_connection() as conn:
        _create_schema(conn)
    print("[memory] Database initialised.")


def _create_schema(conn: sqlite3.Connection) -> None:
    with conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS fix_history (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint     TEXT    NOT NULL,
                file            TEXT    NOT NULL,
                finding_type    TEXT,
                rule_id         TEXT,
                run_id          TEXT,
                outcome         TEXT,
                fix_summary     TEXT,
                fixed_content   TEXT,
                error           TEXT,
                created_at      TEXT    DEFAULT (datetime('now'))
            );

            CREATE INDEX IF NOT EXISTS idx_fingerprint
                ON fix_history(fingerprint);

            CREATE INDEX IF NOT EXISTS idx_file
                ON fix_history(file);
        """)
        
        # Migration: add columns missing from older databases
        columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(fix_history)")
        }

        if "fixed_content" not in columns:
            conn.execute(
                "ALTER TABLE fix_history ADD COLUMN fixed_content TEXT"
            )
            print("[memory] Added missing column: fixed_content")

        if "error" not in columns:
            conn.execute(
                "ALTER TABLE fix_history ADD COLUMN error TEXT"
            )
            print("[memory] Added missing column: error")


# ===========================================================================
# FIX HISTORY
# ===========================================================================

def save_fix(
    fingerprint:   str,
    file:          str,
    finding_type:  str,
    rule_id:       str,
    run_id:        str,
    outcome:       str,
    fix_summary:   str  = "",
    fixed_content: str = "",
    error:         str = "",
) -> None:
    """Save a fix attempt. Only meaningful outcomes are worth saving.
    `error` is what this attempt broke (app check, new scanner findings, rejected by a gate)."""
    # skip no-change fixes — not useful to remember
    if outcome == "no_change":
        return

    with get_connection() as conn:
        conn.execute("""
            INSERT INTO fix_history
                (fingerprint, file, finding_type, rule_id, run_id, outcome, fix_summary, fixed_content, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (fingerprint, file, finding_type, rule_id, run_id, outcome, fix_summary, fixed_content, error or None))



def load_memory(fingerprint: str, limit: int = 5) -> list[dict]:
    """Load recent fix history for a specific vulnerability fingerprint."""
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT id, outcome, fix_summary, fixed_content, error, run_id, created_at
            FROM fix_history
            WHERE fingerprint = ?
            ORDER BY created_at DESC, id DESC
            LIMIT ?
        """, (fingerprint, limit)).fetchall()
    return [dict(r) for r in rows]


# ===========================================================================
# FINGERPRINT
# ===========================================================================

def make_fingerprint(finding: dict) -> str:
    """
    Generate a unique key for a specific vulnerability instance.
    
    SAST:      rule_id + file + line
    SCA:       cve + package + manifest
    Container: cve + image + package
    """
    finding_type = finding.get("finding_type", "unknown")

    if finding_type == "sast":
        rule_id = finding["identifiers"].get("rule_id", "unknown")
        file    = finding["location"].get("file", "unknown")
        line    = finding["location"].get("line", "0")
        return f"sast::{rule_id}::{file}::{line}"

    elif finding_type == "sca":
        cve     = finding["identifiers"].get("cve", "unknown")
        package = finding["location"].get("package", "unknown")
        file    = finding["location"].get("file", "unknown")
        return f"sca::{cve}::{package}::{file}"

    elif finding_type == "container":
        cve     = finding["identifiers"].get("cve", "unknown")
        image   = finding["location"].get("image", "unknown")
        package = finding["location"].get("package", "unknown")
        return f"container::{cve}::{image}::{package}"

    else:
        # fallback
        title = finding.get("title", "unknown")
        file  = finding.get("location", {}).get("file", "unknown")
        return f"unknown::{title}::{file}"

# ===========================================================================
# OUTCOME 
# ===========================================================================
def update_outcome(fingerprint: str, run_id: str, outcome: str) -> None:
    with get_connection() as conn:
        conn.execute("""
            UPDATE fix_history 
            SET outcome = ?
            WHERE fingerprint = ? AND run_id = ? AND outcome = 'pending'
        """, (outcome, fingerprint, run_id))

# ===========================================================================
# INSPECT (python -m memory.memory_store [--db FILE] [--run RUN_ID])
# ===========================================================================

def summarise(run_id: str | None = None) -> list[dict]:
    """Per run (or one run): how many findings and files were saved, and with which outcomes."""
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT run_id, outcome, COUNT(*) AS findings, COUNT(DISTINCT file) AS files,
                   SUM(error IS NOT NULL) AS with_error, MIN(created_at) AS saved_at
            FROM fix_history
            WHERE ? IS NULL OR run_id = ?
            GROUP BY run_id, outcome
            ORDER BY saved_at
        """, (run_id, run_id)).fetchall()
    return [dict(r) for r in rows]


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Show what the memory DB holds.")
    parser.add_argument("--db", help=f"Memory DB file (default: {DB_PATH})")
    parser.add_argument("--run", help="Only this run, with each file's outcome and error")
    args = parser.parse_args()
    if args.db:
        DB_PATH = Path(args.db)

    for r in summarise(args.run):
        print(f"run {r['run_id']}: {r['outcome']}, {r['findings']} finding(s) in {r['files']} file(s), "
              f"{r['with_error']} with an error, saved {r['saved_at']}")
    if args.run:
        with get_connection() as conn:
            for r in conn.execute("""
                SELECT file, outcome, fix_summary, error FROM fix_history
                WHERE run_id = ? GROUP BY file ORDER BY file
            """, (args.run,)):
                print(f"\n  {r['file']}: {r['outcome']} — {r['fix_summary']}")
                if r["error"]:
                    print(f"    error: {r['error'][:300]}")

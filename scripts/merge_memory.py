"""Merge the parallel fix jobs' memory rows into the saved memory database.

Each fix job reads the saved database and adds this run's fix_history rows to its own copy. Only
this run's rows are taken from each copy, so one job's rows never overwrite another's, and the
database is uploaded once afterwards. Running it again for the same run replaces that run's rows.

  python scripts/merge_memory.py --base memory/asva_memory.db --parts DIR --run-id ID
"""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from memory import memory_store  # noqa: E402


def merge(base: Path, parts: Path, run_id: str) -> int:
    """Add this run's rows from every copy under `parts` to `base`. Returns how many were added."""
    memory_store.DB_PATH = base
    conn = memory_store.get_connection()  # creates the table on a first run
    try:
        columns = [row["name"] for row in conn.execute("PRAGMA table_info(fix_history)") if row["name"] != "id"]
        added = 0
        with conn:
            conn.execute("DELETE FROM fix_history WHERE run_id = ?", (run_id,))
            for path in sorted(parts.rglob("asva_memory.db")):
                source = sqlite3.connect(path)
                try:
                    present = {row[1] for row in source.execute("PRAGMA table_info(fix_history)")}
                    names = [c for c in columns if c in present]
                    if not names:
                        continue
                    rows = source.execute(f"SELECT {', '.join(names)} FROM fix_history WHERE run_id = ? ORDER BY id",
                                          (run_id,)).fetchall()
                finally:
                    source.close()
                conn.executemany(f"INSERT INTO fix_history ({', '.join(names)}) VALUES ({', '.join('?' * len(names))})",
                                 rows)
                added += len(rows)
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        return added
    finally:
        conn.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--parts", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    added = merge(args.base, args.parts, args.run_id)
    print(f"[memory] Merged {added} fix history row(s) from this run into {args.base}")


if __name__ == "__main__":
    main()

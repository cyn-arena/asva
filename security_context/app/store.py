"""SQLite knowledge store.

Tables:
  records     exact-lookup entries keyed by an ID: CWE-94, CVE-2016-10531, KEV entries,
              plus cached online lookups (OSV package advisories, Context7 notes)
  links       relationships between IDs: CWE child_of CWE, CVE has_cwe CWE, CWE owasp_top10 category
  chunks      prose passages plus their MiniLM embedding (similarity search)
  sync_state  which version of each source is loaded (the "snapshot")
"""

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np

SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
    key        TEXT NOT NULL,
    source     TEXT NOT NULL,
    kind       TEXT NOT NULL,
    title      TEXT,
    text       TEXT NOT NULL,
    url        TEXT,
    license    TEXT,
    fetched_at TEXT NOT NULL,
    data       TEXT,
    PRIMARY KEY (key, source)
);
CREATE TABLE IF NOT EXISTS links (
    src    TEXT NOT NULL,
    rel    TEXT NOT NULL,
    dst    TEXT NOT NULL,
    source TEXT NOT NULL,
    PRIMARY KEY (src, rel, dst)
);
CREATE INDEX IF NOT EXISTS links_by_source ON links (source, src);
CREATE TABLE IF NOT EXISTS chunks (
    id          INTEGER PRIMARY KEY,
    source      TEXT NOT NULL,
    doc_id      TEXT NOT NULL,
    doc_version TEXT NOT NULL,
    doc_title   TEXT NOT NULL,
    section     TEXT,
    url         TEXT,
    license     TEXT,
    text        TEXT NOT NULL,
    embedding   BLOB NOT NULL,
    fetched_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS chunks_by_doc ON chunks (source, doc_id);
CREATE TABLE IF NOT EXISTS sync_state (
    source     TEXT PRIMARY KEY,
    version    TEXT,
    synced_at  TEXT,
    item_count INTEGER
);
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""

# Bump when a release changes what the built-in sources store (e.g. v2 added OWASP Top 10
# links and CISA KEV), so an existing data volume is re-seeded from the image's snapshot.
FORMAT = 2

ISO = "%Y-%m-%dT%H:%M:%SZ"


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime(ISO)


def parse_iso(value: str) -> datetime:
    return datetime.strptime(value, ISO).replace(tzinfo=timezone.utc)


def connect(path: Path) -> sqlite3.Connection:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    is_new = not path.exists()
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")  # readers don't block the (single) writer
    conn.executescript(SCHEMA)
    _migrate(conn)
    if is_new:
        set_format(conn, FORMAT)
        conn.commit()
    return conn


def _migrate(conn: sqlite3.Connection) -> None:
    """Databases built by the POC lack records.data."""
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(records)")}
    if "data" not in columns:
        conn.execute("ALTER TABLE records ADD COLUMN data TEXT")


def get_format(conn: sqlite3.Connection) -> int:
    row = conn.execute("SELECT value FROM meta WHERE key = 'format'").fetchone()
    return int(row["value"]) if row else 1  # no marker: built by the POC


def set_format(conn: sqlite3.Connection, value: int) -> None:
    conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('format', ?)", (str(value),))


_COPY = {
    "records": "key, source, kind, title, text, url, license, fetched_at, data",
    "links": "src, rel, dst, source",
    "chunks": "source, doc_id, doc_version, doc_title, section, url, license, text, embedding, fetched_at",
    "sync_state": "source, version, synced_at, item_count",
}


def reseed_from_snapshot(conn: sqlite3.Connection, snapshot_path: Path) -> list[str]:
    """Bring the built-in sources of an existing database up to the image's snapshot: all of them
    when the snapshot has a newer format; otherwise each source the snapshot has a newer version of
    (a different version, synced later), e.g. a newer CISA KEV catalogue after the image was rebuilt.
    A source this database synced more recently itself is left alone. Other data (cached NVD / OSV
    / Context7 lookups) is kept."""
    snapshot = sqlite3.connect(f"file:{Path(snapshot_path).as_posix()}?mode=ro&immutable=1", uri=True)
    snapshot.row_factory = sqlite3.Row
    try:
        newer_format = get_format(conn) < get_format(snapshot)
        sources = []
        for row in snapshot.execute("SELECT source, version, synced_at FROM sync_state"):
            mine = conn.execute("SELECT version, synced_at FROM sync_state WHERE source = ?", (row["source"],)).fetchone()
            if newer_format or (mine and mine[0] != row["version"] and (row["synced_at"] or "") > (mine[1] or "")):
                sources.append(row["source"])
        if not sources:
            return []
        for source in sources:
            for table, columns in _COPY.items():
                conn.execute(f"DELETE FROM {table} WHERE source = ?", (source,))
                rows = snapshot.execute(f"SELECT {columns} FROM {table} WHERE source = ?", (source,)).fetchall()
                marks = ",".join("?" * len(columns.split(",")))
                conn.executemany(f"INSERT OR REPLACE INTO {table} ({columns}) VALUES ({marks})", [tuple(r) for r in rows])
        if newer_format:
            set_format(conn, get_format(snapshot))
        conn.commit()
        return sources
    finally:
        snapshot.close()


# ---------------------------------------------------------------------------
# records / links
# ---------------------------------------------------------------------------

def _row(source: str, r: dict) -> dict:
    data = r.get("data")
    return {"key": r["key"], "source": source, "kind": r["kind"], "title": r.get("title"), "text": r["text"],
            "url": r.get("url"), "license": r.get("license"), "fetched_at": r.get("fetched_at") or now_iso(),
            "data": json.dumps(data) if data is not None else None}


_INSERT = ("INSERT OR REPLACE INTO records (key, source, kind, title, text, url, license, fetched_at, data) "
           "VALUES (:key, :source, :kind, :title, :text, :url, :license, :fetched_at, :data)")


def replace_source_records(conn: sqlite3.Connection, source: str, rows: list[dict]) -> None:
    """Swap in a full new set of records for one source (a sync replaces, never merges)."""
    conn.execute("DELETE FROM records WHERE source = ?", (source,))
    conn.executemany(_INSERT, [_row(source, r) for r in rows])


def upsert_records(conn: sqlite3.Connection, source: str, rows: list[dict]) -> None:
    conn.executemany(_INSERT, [_row(source, r) for r in rows])


def get_record(conn: sqlite3.Connection, key: str, source: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM records WHERE key = ? AND source = ?", (key, source)).fetchone()


def get_records(conn: sqlite3.Connection, keys: list[str], source: str) -> dict[str, sqlite3.Row]:
    if not keys:
        return {}
    marks = ",".join("?" * len(keys))
    rows = conn.execute(f"SELECT * FROM records WHERE source = ? AND key IN ({marks})", (source, *keys)).fetchall()
    return {r["key"]: r for r in rows}


def record_data(row: sqlite3.Row | None):
    return json.loads(row["data"]) if row is not None and row["data"] else None


def is_fresh(row: sqlite3.Row | None, max_age: timedelta) -> bool:
    return row is not None and datetime.now(timezone.utc) - parse_iso(row["fetched_at"]) < max_age


def replace_source_links(conn: sqlite3.Connection, source: str, rows: list[tuple[str, str, str]]) -> None:
    conn.execute("DELETE FROM links WHERE source = ?", (source,))
    add_links(conn, source, rows)


def replace_links_from(conn: sqlite3.Connection, source: str, src: str, rows: list[tuple[str, str, str]]) -> None:
    """Replace one ID's outgoing links from one source (e.g. a re-fetched CVE's CWEs)."""
    conn.execute("DELETE FROM links WHERE source = ? AND src = ?", (source, src))
    add_links(conn, source, rows)


def add_links(conn: sqlite3.Connection, source: str, rows: list[tuple[str, str, str]]) -> None:
    conn.executemany("INSERT OR IGNORE INTO links (src, rel, dst, source) VALUES (?, ?, ?, ?)",
                     [(src, rel, dst, source) for src, rel, dst in rows])


def linked(conn: sqlite3.Connection, src: str, rel: str) -> list[str]:
    rows = conn.execute("SELECT dst FROM links WHERE src = ? AND rel = ? ORDER BY dst", (src, rel)).fetchall()
    return [r["dst"] for r in rows]


# ---------------------------------------------------------------------------
# chunks
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ChunkMeta:
    id: int
    source: str
    doc_id: str
    doc_title: str
    section: str | None
    url: str | None
    license: str | None
    text: str
    fetched_at: str


def doc_versions(conn: sqlite3.Connection, source: str) -> dict[str, str]:
    rows = conn.execute("SELECT DISTINCT doc_id, doc_version FROM chunks WHERE source = ?", (source,)).fetchall()
    return {r["doc_id"]: r["doc_version"] for r in rows}


def replace_doc_chunks(
    conn: sqlite3.Connection, source: str, doc_id: str, doc_version: str, doc_title: str,
    url: str, license: str, chunks: list[dict], embeddings: np.ndarray,
) -> None:
    """chunks: [{"section", "text"}]; embeddings: one float32 row per chunk."""
    conn.execute("DELETE FROM chunks WHERE source = ? AND doc_id = ?", (source, doc_id))
    fetched_at = now_iso()
    conn.executemany(
        "INSERT INTO chunks (source, doc_id, doc_version, doc_title, section, url, license, "
        "text, embedding, fetched_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [(source, doc_id, doc_version, doc_title, c["section"], url, license, c["text"],
          np.asarray(vec, dtype=np.float32).tobytes(), fetched_at)
         for c, vec in zip(chunks, embeddings)],
    )


def delete_docs(conn: sqlite3.Connection, source: str, doc_ids: list[str]) -> None:
    conn.executemany("DELETE FROM chunks WHERE source = ? AND doc_id = ?", [(source, d) for d in doc_ids])


def load_chunks(conn: sqlite3.Connection) -> tuple[list[ChunkMeta], np.ndarray]:
    """All chunks plus their embeddings as one (n, dim) matrix, for in-memory search."""
    rows = conn.execute(
        "SELECT id, source, doc_id, doc_title, section, url, license, text, embedding, fetched_at "
        "FROM chunks ORDER BY id"
    ).fetchall()
    meta = [ChunkMeta(r["id"], r["source"], r["doc_id"], r["doc_title"], r["section"], r["url"],
                      r["license"], r["text"], r["fetched_at"]) for r in rows]
    if not rows:
        return meta, np.zeros((0, 0), dtype=np.float32)
    return meta, np.vstack([np.frombuffer(r["embedding"], dtype=np.float32) for r in rows])


# ---------------------------------------------------------------------------
# sync state
# ---------------------------------------------------------------------------

def set_sync_state(conn: sqlite3.Connection, source: str, version: str, item_count: int,
                   synced_at: str | None = None) -> None:
    conn.execute(
        "INSERT INTO sync_state (source, version, synced_at, item_count) VALUES (?, ?, ?, ?) "
        "ON CONFLICT (source) DO UPDATE SET version = excluded.version, "
        "synced_at = excluded.synced_at, item_count = excluded.item_count",
        (source, version, synced_at or now_iso(), item_count),
    )


def get_sync_state(conn: sqlite3.Connection, source: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM sync_state WHERE source = ?", (source,)).fetchone()


def snapshot(conn: sqlite3.Connection) -> dict[str, dict]:
    rows = conn.execute("SELECT * FROM sync_state ORDER BY source").fetchall()
    return {r["source"]: {"version": r["version"], "synced_at": r["synced_at"], "items": r["item_count"]}
            for r in rows}


def counts(conn: sqlite3.Connection) -> dict[str, int]:
    return {table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table in ("records", "links", "chunks")}

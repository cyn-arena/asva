"""OWASP Cheat Sheet Series: prose guidance on how to fix each class of issue.

The only embedded source: each cheat sheet is split into passages by heading, and each
passage is embedded with MiniLM for similarity search. Updates are incremental: a cheat
sheet is re-downloaded and re-embedded only when its file hash on GitHub changes.
"""

import hashlib
import re
from concurrent.futures import ThreadPoolExecutor

import httpx

from app import config, store
from app.text import squash

SOURCE = "OWASP Cheat Sheet Series"
LIST_URL = "https://api.github.com/repos/OWASP/CheatSheetSeries/contents/cheatsheets"
SITE_URL = "https://cheatsheetseries.owasp.org/cheatsheets/{stem}.html"
LICENSE = "CC BY-SA 4.0, OWASP Cheat Sheet Series: https://creativecommons.org/licenses/by-sa/4.0/"

MAX_CHUNK_CHARS = 1200
MIN_PROSE_CHARS = 60

# Cheat sheets written for one language/framework; down-weighted for findings in another.
DOC_LANGUAGES = {
    "Java_Security_Cheat_Sheet": "java", "Injection_Prevention_in_Java_Cheat_Sheet": "java",
    "JAAS_Cheat_Sheet": "java", "Bean_Validation_Cheat_Sheet": "java",
    "DotNet_Security_Cheat_Sheet": "csharp",
    "PHP_Configuration_Cheat_Sheet": "php", "Laravel_Cheat_Sheet": "php", "Symfony_Cheat_Sheet": "php",
    "Ruby_on_Rails_Cheat_Sheet": "ruby",
    "Django_Security_Cheat_Sheet": "python", "Django_REST_Framework_Cheat_Sheet": "python",
    "C-Based_Toolchain_Hardening_Cheat_Sheet": "cpp",
    "Nodejs_Security_Cheat_Sheet": "javascript", "NodeJS_Docker_Cheat_Sheet": "javascript",
    "NPM_Security_Cheat_Sheet": "javascript", "Nextjs_Security_Cheat_Sheet": "javascript",
    "JavaScript_and_TypeScript_Security_Cheat_Sheet": "javascript",
}

_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_FENCE = re.compile(r"^\s*(```|~~~)")
_LINK = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")
_HTML_TAG = re.compile(r"<[^>]+>")


def _inline(text: str) -> str:
    """Markdown inline text -> plain text (links to their label, tags and markers removed)."""
    text = _LINK.sub(r"\1", text)
    text = _HTML_TAG.sub(" ", text)
    return squash(text.replace("`", "").replace("**", "").replace("__", ""))


def _paragraphs(lines: list[str]) -> list[str]:
    """Split on blank lines, keeping each fenced code block intact as one paragraph."""
    paragraphs, current, in_code = [], [], False
    for line in lines:
        if _FENCE.match(line):
            in_code = not in_code
        if not line.strip() and not in_code:
            if current:
                paragraphs.append("\n".join(current))
                current = []
            continue
        current.append(line)
    if current:
        paragraphs.append("\n".join(current))
    return paragraphs


def _pack(paragraphs: list[str], max_chars: int) -> list[str]:
    """Greedily pack paragraphs into pieces of at most max_chars (splitting oversized ones)."""
    pieces, current = [], ""
    for para in paragraphs:
        while len(para) > max_chars:  # an oversized paragraph is cut into max_chars slices
            if current:
                pieces.append(current)
                current = ""
            pieces.append(para[:max_chars])
            para = para[max_chars:]
        if current and len(current) + 2 + len(para) > max_chars:
            pieces.append(current)
            current = ""
        current = f"{current}\n\n{para}" if current else para
    if current:
        pieces.append(current)
    return pieces


def _prose(piece: str) -> str:
    """The text that gets embedded: no code blocks, plain inline text."""
    kept, in_code = [], False
    for line in piece.splitlines():
        if _FENCE.match(line):
            in_code = not in_code
            continue
        if not in_code:
            kept.append(line)
    return _inline(" ".join(kept))


def chunk_markdown(md: str, fallback_title: str, max_chars: int = MAX_CHUNK_CHARS) -> tuple[str, list[dict]]:
    """Split a cheat sheet into passages: [{"section", "text", "embed_text"}].

    `section` is the heading path below the H1 (e.g. "Application Security > Avoid eval").
    `text` keeps the original markdown (including code examples) for the LLM; `embed_text`
    is the cheat sheet title + section + plain prose, which is what gets embedded.
    """
    title = None
    sections: list[tuple[str, list[str]]] = []
    path: dict[int, str] = {}
    current_section, buffer, in_code = "", [], False

    for line in md.splitlines():
        if _FENCE.match(line):
            in_code = not in_code
            buffer.append(line)
            continue
        match = None if in_code else _HEADING.match(line)
        if not match:
            buffer.append(line)
            continue
        level, heading = len(match.group(1)), _inline(match.group(2))
        sections.append((current_section, buffer))
        buffer = []
        if level == 1 and title is None:
            title = heading
            continue
        path = {lvl: h for lvl, h in path.items() if lvl < level}
        path[level] = heading
        current_section = " > ".join(path[lvl] for lvl in sorted(path) if lvl >= 2)
    sections.append((current_section, buffer))

    title = title or fallback_title
    chunks = []
    for section, lines in sections:
        for piece in _pack(_paragraphs(lines), max_chars):
            prose = _prose(piece)
            if len(prose) < MIN_PROSE_CHARS:
                continue
            heading = f"{title} > {section}" if section else title
            chunks.append({"section": section or None, "text": piece.strip(), "embed_text": f"{heading}\n{prose}"})
    return title, chunks


def _github_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    if config.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {config.GITHUB_TOKEN}"
    return headers


def list_cheatsheets(client: httpx.Client) -> list[dict]:
    response = client.get(LIST_URL, headers=_github_headers())
    response.raise_for_status()
    return [
        {"doc_id": item["name"][:-3], "sha": item["sha"], "download_url": item["download_url"]}
        for item in response.json()
        if item["type"] == "file" and item["name"].endswith(".md")
    ]


def sync(conn, client: httpx.Client, embedder, force: bool = False) -> str:
    listing = list_cheatsheets(client)
    have = store.doc_versions(conn, SOURCE)
    changed = [d for d in listing if force or have.get(d["doc_id"]) != d["sha"]]
    removed = sorted(set(have) - {d["doc_id"] for d in listing})

    def download(doc: dict) -> tuple[dict, str]:
        response = client.get(doc["download_url"])
        response.raise_for_status()
        return doc, response.text

    with ThreadPoolExecutor(max_workers=8) as pool:
        downloaded = list(pool.map(download, changed))

    for doc, md in downloaded:
        title, chunks = chunk_markdown(md, fallback_title=doc["doc_id"].replace("_", " "))
        if not chunks:
            store.delete_docs(conn, SOURCE, [doc["doc_id"]])
            continue
        vectors = embedder.embed([c["embed_text"] for c in chunks])
        store.replace_doc_chunks(
            conn, SOURCE, doc["doc_id"], doc["sha"], title,
            SITE_URL.format(stem=doc["doc_id"]), LICENSE, chunks, vectors,
        )
        conn.commit()

    store.delete_docs(conn, SOURCE, removed)
    total = conn.execute("SELECT COUNT(*) FROM chunks WHERE source = ?", (SOURCE,)).fetchone()[0]
    digest = hashlib.sha256("".join(sorted(d["sha"] for d in listing)).encode()).hexdigest()[:12]
    store.set_sync_state(conn, SOURCE, f"{len(listing)} cheat sheets @ {digest}", total)
    conn.commit()
    return (f"{SOURCE}: {len(listing)} cheat sheets, {len(changed)} (re)embedded, "
            f"{len(removed)} removed, {total} passages")

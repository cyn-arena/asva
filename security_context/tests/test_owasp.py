import httpx

from app import store
from app.sources import owasp

MD = """# Node.js Security Cheat Sheet

## Introduction

This cheat sheet lists actions developers can take to develop secure Node.js applications and services.

## Recommendations

### Do not use dangerous functions

The `eval()` function executes a string as code. Combined with [user input](https://example.com/input) this leads to remote code execution.

```js
# not a heading, this line is inside a code block
eval(userInput);
```

### Tiny

Short.
"""


def test_chunk_markdown_uses_h1_as_title():
    title, _ = owasp.chunk_markdown(MD, fallback_title="fallback")
    assert title == "Node.js Security Cheat Sheet"


def test_chunk_markdown_falls_back_to_given_title_without_h1():
    title, _ = owasp.chunk_markdown("## Section\n\n" + "Some useful guidance text. " * 5, fallback_title="Fallback Title")
    assert title == "Fallback Title"


def test_chunk_markdown_builds_heading_paths_and_skips_tiny_sections():
    _, chunks = owasp.chunk_markdown(MD, fallback_title="x")
    assert [c["section"] for c in chunks] == ["Introduction", "Recommendations > Do not use dangerous functions"]


def test_chunk_markdown_ignores_hash_lines_inside_code_blocks():
    _, chunks = owasp.chunk_markdown(MD, fallback_title="x")
    assert not any("not a heading" in (c["section"] or "") for c in chunks)


def test_chunk_text_keeps_code_but_embed_text_is_plain_prose():
    _, chunks = owasp.chunk_markdown(MD, fallback_title="x")
    chunk = chunks[1]
    assert "eval(userInput);" in chunk["text"]
    assert "eval(userInput)" not in chunk["embed_text"]
    assert "https://example.com" not in chunk["embed_text"]
    assert chunk["embed_text"].startswith("Node.js Security Cheat Sheet > Recommendations > Do not use dangerous functions")
    assert "Combined with user input this leads" in chunk["embed_text"]


def test_long_sections_are_split_within_the_size_limit():
    paragraph = "Validate every input against an allowlist before using it. " * 7  # ~420 chars
    md = "# T\n\n## Long\n\n" + "\n\n".join([paragraph] * 6)
    _, chunks = owasp.chunk_markdown(md, fallback_title="x", max_chars=1000)
    assert len(chunks) > 1
    assert all(len(c["text"]) <= 1000 for c in chunks)


def _listing(shas: dict[str, str]):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.github.com":
            return httpx.Response(200, json=[
                {"name": f"{doc}.md", "type": "file", "sha": sha, "download_url": f"https://raw.test/{doc}.md"}
                for doc, sha in shas.items()
            ] + [{"name": "assets", "type": "dir", "sha": "d", "download_url": None}])
        return httpx.Response(200, text=MD)
    return httpx.MockTransport(handler)


def test_sync_reembeds_only_changed_documents_and_removes_deleted_ones(tmp_path, fake_embedder):
    conn = store.connect(tmp_path / "t.db")
    with httpx.Client(transport=_listing({"A_Cheat_Sheet": "1", "B_Cheat_Sheet": "1"})) as client:
        first = owasp.sync(conn, client, fake_embedder)
    with httpx.Client(transport=_listing({"A_Cheat_Sheet": "1", "B_Cheat_Sheet": "1"})) as client:
        unchanged = owasp.sync(conn, client, fake_embedder)
    with httpx.Client(transport=_listing({"A_Cheat_Sheet": "2"})) as client:
        changed = owasp.sync(conn, client, fake_embedder)
    versions = store.doc_versions(conn, owasp.SOURCE)
    conn.close()

    assert "2 (re)embedded" in first
    assert "0 (re)embedded" in unchanged
    assert "1 (re)embedded, 1 removed" in changed
    assert versions == {"A_Cheat_Sheet": "2"}


def test_sync_stores_site_url_and_licence(tmp_path, fake_embedder):
    conn = store.connect(tmp_path / "t.db")
    with httpx.Client(transport=_listing({"Nodejs_Security_Cheat_Sheet": "1"})) as client:
        owasp.sync(conn, client, fake_embedder)
    chunks, matrix = store.load_chunks(conn)
    conn.close()
    assert chunks[0].url == "https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html"
    assert chunks[0].license.startswith("CC BY-SA 4.0")
    assert matrix.shape == (len(chunks), fake_embedder.dim)

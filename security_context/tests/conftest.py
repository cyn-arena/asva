"""Shared fixtures. Everything here is offline: a fake embedder instead of MiniLM, a trimmed
CWE catalogue instead of the real download, and a mock HTTP transport that answers with
trimmed real API responses saved under tests/fixtures/."""

import json
import re
import zlib
from contextlib import closing
from pathlib import Path

import httpx
import numpy as np
import pytest

from app import config, net, store
from app.sources import cwe, nvd, owasp

FIXTURES = Path(__file__).parent / "fixtures"


def fixture_json(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


class FakeAPIs:
    """Mock transport for NVD, CISA KEV, OSV.dev, Context7 (and the npm registry entry it reads), Docker Hub and
    endoflife.date.

    Answers from the saved fixtures; `calls` records every request; set `fail[host] = n`
    to make the next n requests to that host return 503."""

    def __init__(self):
        self.calls: list[httpx.Request] = []
        self.fail: dict[str, int] = {}
        self.osv: dict[str, str] = {"marked@0.3.5": "osv_marked_0.3.5.json", "mongodb@2.2.36": "osv_mongodb_2.2.36.json"}
        self.json: dict[tuple[str, str], dict] = {}  # (host, path) -> answer, set by a test (PyPI, npm metadata)

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        host, path = request.url.host, request.url.path
        if self.fail.get(host):
            self.fail[host] -= 1
            return httpx.Response(503)
        if (host, path) in self.json:
            return httpx.Response(200, json=self.json[(host, path)])
        if host == "pypi.org":
            return httpx.Response(404, json={"message": "Not Found"})
        if host == "services.nvd.nist.gov":
            cve = request.url.params.get("cveId")
            name = {"CVE-2016-10531": "nvd_cve_2016_10531.json", "CVE-2022-23219": "nvd_cve_2022_23219.json"}.get(cve)
            if name:
                return httpx.Response(200, json=fixture_json(name))
            return httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []})
        if host == "www.cisa.gov":
            return httpx.Response(200, json=fixture_json("kev_sample.json"))
        if host == "api.osv.dev":
            if request.method == "GET":  # /v1/vulns/UBUNTU-CVE-2026-8376: a distribution's data for one CVE
                saved = FIXTURES / f"osv_{path.rsplit('/', 1)[-1].lower().replace('-', '_')}.json"
                return httpx.Response(200, json=json.loads(saved.read_text(encoding="utf-8"))) if saved.exists() \
                    else httpx.Response(404, json={"code": 5, "message": "Bug not found."})
            body = json.loads(request.content)
            name = self.osv.get(f"{body['package']['name']}@{body['version']}")
            return httpx.Response(200, json=fixture_json(name) if name else {})
        if host == "registry.npmjs.org":
            if path == "/mongodb/latest":
                return httpx.Response(200, json=fixture_json("npm_mongodb_latest.json"))
            return httpx.Response(404, json={"error": "Not found"})
        if host == "auth.docker.io":
            return httpx.Response(200, json={"token": "test-registry-token"})
        if host == "registry-1.docker.io":
            return self._docker_hub(path)
        if host == "endoflife.date":
            if path == "/api/mongodb.json":
                return httpx.Response(200, json=fixture_json("endoflife_mongodb.json"))
            return httpx.Response(404, text="Not Found")
        if host == "context7.com":
            if path.endswith("/libs/search"):
                return httpx.Response(200, json=fixture_json("context7_search_mongodb.json"))
            if path.endswith("/context"):
                return httpx.Response(200, text=(FIXTURES / "context7_context_mongodb.txt").read_text(encoding="utf-8"))
        return httpx.Response(404)

    @staticmethod
    def _docker_hub(path: str) -> httpx.Response:
        """The mongo image as Docker Hub serves it: tag list, then per tag an index, a manifest
        and the image config (dockerhub_mongo.json holds the tags and the trimmed real configs)."""
        hub = fixture_json("dockerhub_mongo.json")
        if not path.startswith("/v2/library/mongo/"):
            return httpx.Response(404, json={"errors": [{"code": "NAME_UNKNOWN"}]})
        kind, _, name = path[len("/v2/library/mongo/"):].partition("/")
        if kind == "tags":
            return httpx.Response(200, json={"name": "library/mongo", "tags": hub["tags"]})
        if kind == "manifests" and name in hub["configs"]:
            return httpx.Response(200, json={"manifests": [
                {"digest": "sha256:other", "platform": {"os": "windows", "architecture": "amd64"}},
                {"digest": f"sha256:manifest-{name}", "platform": {"os": "linux", "architecture": "amd64"}}]})
        if kind == "manifests" and name.startswith("sha256:manifest-"):
            return httpx.Response(200, json={"config": {"digest": f"sha256:config-{name[len('sha256:manifest-'):]}"}})
        if kind == "blobs" and name.startswith("sha256:config-"):
            return httpx.Response(200, json=hub["configs"][name[len("sha256:config-"):]])
        return httpx.Response(404, json={"errors": [{"code": "MANIFEST_UNKNOWN"}]})

    def hosts(self) -> list[str]:
        return [c.url.host for c in self.calls]


@pytest.fixture(autouse=True)
def _offline_settings(monkeypatch):
    """Tests never depend on the developer's .env, and retries don't actually sleep. The keyword
    fallback is off unless a test asks for it: its threshold is tuned for MiniLM's scores, and
    the fake embedder scores lower."""
    monkeypatch.setattr(config, "NVD_API_KEY", "test-nvd-key")
    monkeypatch.setattr(config, "CONTEXT7_API_KEY", "test-context7-key")
    monkeypatch.setattr(config, "KEYWORD_FALLBACK_RESULTS", 0)
    monkeypatch.setattr(config, "DISABLED_SOURCES", frozenset())
    monkeypatch.setattr(net.time, "sleep", lambda seconds: None)
    # The NVD rate limit is shared by the whole process; with sleep switched off, reaching it
    # would spin until its 30-second window passes.
    monkeypatch.setattr(nvd, "_limiters", {True: net.RateLimiter(10**6, 30), False: net.RateLimiter(10**6, 30)})


@pytest.fixture
def apis():
    return FakeAPIs()


@pytest.fixture
def http_client(apis):
    with net.make_client(transport=httpx.MockTransport(apis)) as http:
        yield http


class FakeEmbedder:
    """Deterministic bag-of-words vectors: texts that share words get similar vectors."""
    dim = 512

    def __init__(self):
        self.calls = 0

    def embed(self, texts):
        self.calls += 1
        out = np.zeros((len(texts), self.dim), dtype=np.float32)
        for row, text in enumerate(texts):
            for word in re.findall(r"[a-z0-9]+", text.lower()):
                out[row, zlib.crc32(word.encode()) % self.dim] += 1
        norms = np.linalg.norm(out, axis=1, keepdims=True)
        return out / np.where(norms == 0, 1, norms)


GUIDANCE_DOCS = {
    "Nodejs_Security_Cheat_Sheet": [
        ("Do not use dangerous functions",
         "Never pass user input to the JavaScript eval function: eval executes code, which leads to code injection."),
        ("Stay away from evil regexes",
         "A vulnerable regular expression can cause a regular expression denial of service (ReDoS)."),
    ],
    "Unvalidated_Redirects_and_Forwards_Cheat_Sheet": [
        ("Introduction",
         "Unvalidated redirects occur when user input controls the redirect target, sending users to an untrusted site."),
    ],
    "Transport_Layer_Security_Cheat_Sheet": [
        ("Certificates", "Use certificates from a trusted certificate authority and configure TLS protocols."),
    ],
}


def load_cwe_fixture(conn):
    version, records, links = cwe.parse((FIXTURES / "cwe_sample.xml").read_bytes())
    store.replace_source_records(conn, cwe.SOURCE, records)
    store.replace_source_links(conn, cwe.SOURCE, links)
    store.set_sync_state(conn, cwe.SOURCE, version, len(records))


def load_guidance(conn, embedder, docs=GUIDANCE_DOCS):
    for doc_id, sections in docs.items():
        chunks = [{"section": s, "text": t} for s, t in sections]
        vectors = embedder.embed([f"{doc_id} {s} {t}" for s, t in sections])
        store.replace_doc_chunks(conn, owasp.SOURCE, doc_id, "sha1", doc_id.replace("_", " "),
                                 f"https://example.test/{doc_id}", owasp.LICENSE, chunks, vectors)
    store.set_sync_state(conn, owasp.SOURCE, "test", sum(len(s) for s in docs.values()))


@pytest.fixture
def fake_embedder():
    return FakeEmbedder()


@pytest.fixture
def db_path(tmp_path, fake_embedder):
    """A database pre-loaded with the CWE fixture and a few guidance passages."""
    path = tmp_path / "test.db"
    with closing(store.connect(path)) as conn:
        load_cwe_fixture(conn)
        load_guidance(conn, fake_embedder)
        conn.commit()
    return path


@pytest.fixture
def conn(db_path):
    with closing(store.connect(db_path)) as connection:
        yield connection

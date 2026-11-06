"""Unit tests for agent/import_map.py -- the interactive HTML map of the repo-context
import index (companion to ITP2 task 3.1). Small synthetic trees; no network."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent import agent_loop
from agent.import_map import build_map_data, main, render_html, write_import_map
from agent.repo_context import build_import_index

pytestmark = pytest.mark.unit


def _tree(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


@pytest.fixture
def py_app(tmp_path: Path) -> Path:
    return _tree(tmp_path / "app", {
        "core/models.py": "import os\nimport yaml\n\nclass User:\n    pass\n",
        "core/views.py": "from .models import User\n\ndef show():\n    return User()\n",
        "core/urls.py": "from . import views\n\nurls = [views.show]\n",
        "lonely.py": "x = 1\n",
    })


def _batch(path: str, line: int = 4) -> dict:
    return {"batch_id": "b1", "batch_type": "sast", "files_to_fix": [{
        "file": path, "fix_type": "code_change",
        "findings": [{"severity": "high", "title": "SQL Injection", "location": {"file": path, "line": line},
                      "identifiers": {"rule_id": "python/Sqli"}}],
    }]}


def test_nodes_and_edges_mirror_the_index(py_app):
    data = build_map_data(build_import_index(py_app))
    ids = {n["id"] for n in data["nodes"]}
    assert ids == {"core/models.py", "core/views.py", "core/urls.py", "lonely.py"}
    edges = {(e["s"], e["t"]) for e in data["edges"]}
    assert edges == {("core/views.py", "core/models.py"), ("core/urls.py", "core/views.py")}
    models = next(n for n in data["nodes"] if n["id"] == "core/models.py")
    assert models["fanin"] == 1 and models["group"] == "core"
    lonely = next(n for n in data["nodes"] if n["id"] == "lonely.py")
    assert (lonely["fanin"], lonely["fanout"], lonely["group"]) == (0, 0, "(root)")


def test_stdlib_is_left_out_of_packages(py_app):
    data = build_map_data(build_import_index(py_app))
    names = {p["name"] for p in data["packages"]}
    assert "yaml" in names and "os" not in names
    models = next(n for n in data["nodes"] if n["id"] == "core/models.py")
    assert models["pkgs"] == ["yaml"]


def test_batch_files_are_marked_with_findings_and_context(py_app):
    data = build_map_data(build_import_index(py_app), _batch("core/models.py"))
    models = next(n for n in data["nodes"] if n["id"] == "core/models.py")
    assert models["inBatch"] and models["fixType"] == "code_change"
    assert models["findings"][0]["rule"] == "python/Sqli"
    assert "core/views.py" in models["context"]          # same text the fix prompt gets
    assert data["meta"]["batchId"] == "b1"


def test_sca_batch_flags_upgraded_package(py_app):
    batch = {"batch_id": "s1", "batch_type": "sca", "files_to_fix": [{
        "file": "requirements.txt", "fix_type": "version_upgrade",
        "findings": [{"location": {"kind": "dependency", "package": "pyyaml@5.1"}}]}]}
    data = build_map_data(build_import_index(py_app), batch)
    assert next(p for p in data["packages"] if p["name"] == "yaml")["flagged"]
    assert data["meta"]["unindexedBatchFiles"] == ["requirements.txt"]


def test_html_is_self_contained_and_escapes_script_close(tmp_path):
    app = _tree(tmp_path / "app", {"a.py": "from b import x  # </script><b>\n", "b.py": "x = 1\n"})
    page = render_html(build_map_data(build_import_index(app)))
    for attr in ('src="http', "src='http", 'href="http', "@import", "url(http"):
        assert attr not in page                                  # opens offline, e.g. from a CI artifact
    payload = page.split('<script id="data" type="application/json">', 1)[1].split("</script>", 1)[0]
    assert "</script>" not in payload
    assert json.loads(payload)["edges"][0]["s"] == "a.py"


def test_cli_writes_file(py_app, tmp_path, capsys):
    out = tmp_path / "out" / "map.html"
    assert main(["--app-root", str(py_app), "--out", str(out)]) == 0
    assert out.read_text(encoding="utf-8").startswith("<!doctype html>")
    assert "4 file(s), 2 import edge(s)" in capsys.readouterr().out


def test_agent_loop_writes_map_per_batch(py_app, tmp_path):
    out = agent_loop.write_batch_import_map(build_import_index(py_app), _batch("core/views.py"), tmp_path / "maps")
    assert out == tmp_path / "maps" / "import_map_b1.html" and out.exists()


def test_agent_loop_map_failure_does_not_raise(py_app, tmp_path, monkeypatch, capsys):
    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(agent_loop.import_map, "write_import_map", boom)
    assert agent_loop.write_batch_import_map(build_import_index(py_app), {"batch_id": "b"}, tmp_path) is None
    assert "Could not write import map" in capsys.readouterr().out


def test_write_import_map_creates_parents(py_app, tmp_path):
    out = write_import_map(build_import_index(py_app), tmp_path / "x" / "y" / "m.html")
    assert out.exists()

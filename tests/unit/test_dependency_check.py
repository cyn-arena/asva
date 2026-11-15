"""Unit tests for agent/dependency_check.py -- a fix that imports a package the app does not
have is caught before the app is built, and every such file is sent back to the LLM at once."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent import dependency_check as dc
from agent.agent_loop import build_refix_prompt
from gitops import config

pytestmark = pytest.mark.unit


def _tree(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


@pytest.fixture
def node_app(tmp_path):
    lock = {"lockfileVersion": 2, "packages": {
        "": {"dependencies": {"express": "^4"}},
        "node_modules/express": {}, "node_modules/body-parser": {},          # indirect, hoisted
        "node_modules/express/node_modules/debug": {},                        # nested: not usable
    }}
    return _tree(tmp_path / "app", {
        "package.json": json.dumps({"dependencies": {"express": "^4"}, "devDependencies": {"mocha": "1"}}),
        "package-lock.json": json.dumps(lock),
        "routes/a.js": 'const express = require("express");\n',
        "routes/b.js": 'const helmet = require("helmet");\n',
        "lib/util.js": "module.exports = {};\n",
    })


def test_new_require_of_a_package_the_app_lacks_is_flagged(node_app):
    fixed = 'const express = require("express");\nconst rateLimit = require("express-rate-limit");\n'
    found = dc.undeclared_imports({"routes/a.js": fixed}, node_app)
    assert found["routes/a.js"]["packages"] == ["express-rate-limit"]
    assert found["routes/a.js"]["manifest"] == "package.json"
    assert "express" in found["routes/a.js"]["installed"]


@pytest.mark.parametrize("line", [
    'require("express")',                 # declared
    'require("mocha")',                   # devDependency
    'require("body-parser")',             # installed at the top of node_modules (lockfile)
    'require("fs")', 'require("node:crypto")', 'require("path/posix")',   # built in
    'require("../lib/util")',             # local module
    'require("helmet")',                  # another app file already uses it, so it is there
    'import express from "express"',      # ES module syntax
])
def test_installed_builtin_local_or_already_used_packages_pass(node_app, line):
    fixed = 'const express = require("express");\n' + line + ";\n"
    assert dc.undeclared_imports({"routes/a.js": fixed}, node_app) == {}


def test_nested_lockfile_package_is_not_usable_from_the_app(node_app):
    fixed = 'const express = require("express");\nconst debug = require("debug");\n'
    assert dc.undeclared_imports({"routes/a.js": fixed}, node_app)["routes/a.js"]["packages"] == ["debug"]


def test_only_imports_the_fix_adds_are_checked(node_app):
    _tree(node_app, {"routes/c.js": 'const legacy = require("left-pad");\n'})
    fixed = 'const legacy = require("left-pad");\nconsole.log(legacy);\n'
    assert dc.undeclared_imports({"routes/c.js": fixed}, node_app) == {}


def test_scoped_packages_and_subpaths(node_app):
    fixed = ('const express = require("express");\n'
             'const x = require("@acme/limits/memory");\nconst y = require("lodash/fp");\n')
    found = dc.undeclared_imports({"routes/a.js": fixed}, node_app)
    assert found["routes/a.js"]["packages"] == ["@acme/limits", "lodash"]


def test_commented_out_require_is_ignored(node_app):
    fixed = 'const express = require("express");\n// const r = require("express-rate-limit");\n'
    assert dc.undeclared_imports({"routes/a.js": fixed}, node_app) == {}


@pytest.fixture
def py_app(tmp_path):
    return _tree(tmp_path / "app", {
        "manage.py": "",
        "requirements.txt": "Django==4.2\nPyJWT==2.8\ndjango-crispy-forms==2.3  # forms\n",
        "shop/__init__.py": "",
        "shop/models.py": "class Order: pass\n",
        "shop/views.py": "from django.http import HttpResponse\n",
        "labs/flask_lab/requirements.txt": "Flask==3.0.0\n",
        "labs/flask_lab/main.py": "from flask import Flask\n",
    })


@pytest.mark.parametrize("line", [
    "import jwt",                                # PyJWT, by its import name
    "from crispy_forms.helper import FormHelper",
    "import os, json",                           # standard library
    "from .models import Order",                 # local, relative
    "from shop.models import Order",             # local, absolute
    "from asgiref.sync import sync_to_async",    # always installed with Django
])
def test_python_installed_stdlib_and_local_imports_pass(py_app, line):
    fixed = "from django.http import HttpResponse\n" + line + "\n"
    assert dc.undeclared_imports({"shop/views.py": fixed}, py_app) == {}


def test_python_undeclared_import_is_flagged(py_app):
    fixed = "from django.http import HttpResponse\nimport bleach\n"
    found = dc.undeclared_imports({"shop/views.py": fixed}, py_app)
    assert found["shop/views.py"]["packages"] == ["bleach"]
    assert found["shop/views.py"]["manifest"] == "requirements.txt"


def test_each_lab_is_checked_against_its_own_requirements(py_app):
    # itsdangerous comes with Flask; jwt is in the main app's requirements, not the lab's
    fixed = "from flask import Flask\nfrom itsdangerous import URLSafeSerializer\nimport jwt\n"
    found = dc.undeclared_imports({"labs/flask_lab/main.py": fixed}, py_app)
    assert found["labs/flask_lab/main.py"]["packages"] == ["jwt"]
    assert found["labs/flask_lab/main.py"]["manifest"] == "labs/flask_lab/requirements.txt"


def test_file_with_no_manifest_above_it_is_not_checked(tmp_path):
    root = _tree(tmp_path / "app", {"tool.js": ""})
    assert dc.undeclared_imports({"tool.js": 'require("anything")\n'}, root) == {}


def test_reason_names_the_package_the_manifest_and_what_is_installed(node_app):
    found = dc.undeclared_imports({"routes/a.js": 'require("express-rate-limit")\n'}, node_app)
    text = dc.reason("routes/a.js", found["routes/a.js"])
    assert "`express-rate-limit`" in text and "package.json" in text
    assert "Do not add dependencies" in text and "express" in text.split("Installed:")[1]


# --------------------------------------------------------------------------------------
# repair(): every offending file goes back to the LLM in the same round
# --------------------------------------------------------------------------------------

def _entry(files: dict[str, str]) -> dict:
    return {"batch": {"batch_id": "b1", "batch_type": "sast",
                      "files_to_fix": [{"file": p, "findings": [{"id": p}]} for p in files]},
            "files": [{"path": p, "content": c} for p, c in files.items()]}


@pytest.fixture
def in_app(node_app, monkeypatch):
    monkeypatch.setattr(config, "FIX_PATH_PREFIX", "app")
    monkeypatch.delenv("ASVA_DEPENDENCY_CHECK", raising=False)
    return str(node_app.parent)


BAD = 'const express = require("express");\nconst rateLimit = require("express-rate-limit");\n'
GOOD = 'const express = require("express");\nconst hits = new Map();\n'


def test_repair_sends_every_offending_file_back_at_once(in_app):
    calls = []

    def refix(path, findings, attempt, reason=None, source="tests"):
        calls.append((path, attempt, source, findings))
        assert "express-rate-limit" in reason
        return GOOD

    entry = _entry({"routes/a.js": BAD, "routes/b.js": BAD, "lib/util.js": "module.exports = 1;\n"})
    out = dc.repair(entry, in_app, make_refix=lambda e: refix)

    assert sorted((p, a, s) for p, a, s, _ in calls) == [
        ("routes/a.js", 1, "dependencies"), ("routes/b.js", 1, "dependencies")]
    assert calls[0][3] == [{"id": calls[0][0]}]          # the file's own findings
    assert {f["path"]: f["content"] for f in out["files"]}["routes/a.js"] == GOOD
    assert "review_notes" not in out["batch"]
    assert out["dependency_check"]["unresolved"] == {}


def test_repair_leaves_a_review_note_when_the_retries_do_not_help(in_app):
    calls = []

    def refix(path, findings, attempt, reason=None, source="tests"):
        calls.append(attempt)
        return BAD

    out = dc.repair(_entry({"routes/a.js": BAD}), in_app, make_refix=lambda e: refix)
    assert calls == [1, 2]
    assert out["dependency_check"]["unresolved"] == {"routes/a.js": ["express-rate-limit"]}
    assert "express-rate-limit" in out["batch"]["review_notes"]["routes/a.js"][0]


def test_repair_does_nothing_for_clean_fixes_or_when_switched_off(in_app, monkeypatch):
    def refix(*a, **k):
        raise AssertionError("no retry expected")

    clean = _entry({"routes/a.js": GOOD})
    assert dc.repair(clean, in_app, make_refix=lambda e: refix) is clean
    monkeypatch.setenv("ASVA_DEPENDENCY_CHECK", "0")
    assert dc.repair(_entry({"routes/a.js": BAD}), in_app, make_refix=lambda e: refix)["files"][0]["content"] == BAD


def test_repair_without_a_retry_function_still_notes_the_problem(in_app):
    out = dc.repair(_entry({"routes/a.js": BAD}), in_app, make_refix=lambda e: None)
    assert out["batch"]["review_notes"]["routes/a.js"]


def test_dependency_retry_prompt_says_it_was_a_check_before_the_build():
    prompt = build_refix_prompt("a.js", "old", [], "code_change", BAD, 1,
                                reason="a.js imports `express-rate-limit`", source="dependencies")
    assert "a check before the app was built rejected" in prompt
    assert "Do not add new dependencies" in prompt and BAD in prompt
    assert "was built and tested" not in prompt
    tests_prompt = build_refix_prompt("a.js", "old", [], "code_change", BAD, 1, reason="boom")
    assert "was built and tested" in tests_prompt

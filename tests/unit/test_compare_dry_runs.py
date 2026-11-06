"""Unit tests for scripts/compare_dry_runs.py -- mainly the cross-file seam check, since
it is the metric that shows whether 3.1/3.6 keep multi-file fixes consistent."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "compare_dry_runs.py"
_spec = importlib.util.spec_from_file_location("compare_dry_runs", _SCRIPT)
compare = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(compare)

DAO = "function DAO(db) {\n  this.getById = (id, cb) => cb(id);\n}\nmodule.exports = { DAO };\n"
ROUTE = ('const DAO = require("../data/dao").DAO;\n'
         "function Route(db) {\n  const dao = new DAO(db);\n"
         "  this.show = (req, res) => dao.getById(req.params.id, res.send);\n}\n"
         "module.exports = Route;\n")


@pytest.fixture
def app(tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "routes").mkdir()
    (tmp_path / "data" / "dao.js").write_text(DAO, encoding="utf-8")
    (tmp_path / "routes" / "route.js").write_text(ROUTE, encoding="utf-8")
    return tmp_path


def _originals(app):
    return {"data/dao.js": DAO, "routes/route.js": ROUTE}


def test_consistent_fix_has_no_broken_seams(app):
    fixed = {"routes/route.js": ROUTE.replace("req.params.id", "req.session.userId")}
    assert compare.broken_seams(app, _originals(app), fixed) == []


def test_renaming_a_method_a_caller_still_uses_is_a_broken_seam(app):
    fixed = {"data/dao.js": DAO.replace("this.getById", "this.getForUser")}
    problems = compare.broken_seams(app, _originals(app), fixed)
    assert problems == ["routes/route.js uses .getById which the fix removed from data/dao.js"]


def test_calling_a_method_the_dependency_lacks_is_a_broken_seam(app):
    fixed = {"routes/route.js": ROUTE.replace("dao.getById", "dao.getForUser")}
    problems = compare.broken_seams(app, _originals(app), fixed)
    assert problems == ["routes/route.js newly calls .getForUser, not defined in data/dao.js"]


def test_renaming_on_both_sides_together_is_consistent(app):
    fixed = {
        "data/dao.js": DAO.replace("this.getById", "this.getForUser"),
        "routes/route.js": ROUTE.replace("dao.getById", "dao.getForUser"),
    }
    assert compare.broken_seams(app, _originals(app), fixed) == []


def test_flagged_lines_kept_counts_untouched_scanner_lines():
    original = "a\neval(x)\nc\n"
    findings = [{"location": {"line": 2}}]
    assert compare._flagged_lines_kept(findings, original, "a\neval(x)\nc\n") == (1, 1)
    assert compare._flagged_lines_kept(findings, original, "a\nsafe(x)\nc\n") == (0, 1)


# --------------------------------------------------------------------------------------
# Re-scan scoring (independent scanner verdict)
# --------------------------------------------------------------------------------------

def _f(file, rule, line=1):
    return {"finding_type": "sast", "location": {"file": file, "line": line},
            "identifiers": {"rule_id": rule}}


def test_rescan_counts_match_by_rule_and_file_not_line():
    before = [_f("a.js", "CodeInjection", 10), _f("a.js", "CodeInjection", 12), _f("a.js", "Xss", 3),
              _f("other.js", "Xss", 1)]
    after = [_f("a.js", "CodeInjection", 14),                  # one left, moved by the fix
             _f("a.js", "Ssrf", 5)]                            # a new problem
    counts = compare.rescan_counts(before, after, {"a.js"})
    assert counts == {"scan_before": 3, "scan_fixed": 2, "scan_remaining": 1, "scan_new": 1}


def _fake_scanner(tree):
    """Flags every line containing 'req.params' as an IDOR-ish finding."""
    found = []
    for p in tree.rglob("*.js"):
        for n, line in enumerate(p.read_text().splitlines(), start=1):
            if "req.params" in line:
                found.append(_f(p.relative_to(tree).as_posix(), "Idor", n))
    return found


def test_compare_rescans_each_run_against_one_baseline(app, tmp_path):
    batch = {"batch_id": "exp", "files_to_fix": [
        {"file": "routes/route.js", "findings": [{"location": {"line": 4}}]}]}
    fixed_run = tmp_path / "fixed" / "exp" / "routes"
    fixed_run.mkdir(parents=True)
    (fixed_run / "route.js").write_text(ROUTE.replace("req.params.id", "req.session.userId"))
    noop_run = tmp_path / "noop" / "exp" / "routes"
    noop_run.mkdir(parents=True)
    (noop_run / "route.js").write_text(ROUTE)

    _, rows = compare.compare(
        [("fixed", tmp_path / "fixed"), ("noop", tmp_path / "noop")], [batch], app,
        scan_fn=_fake_scanner,
    )
    by_label = {r["label"]: r for r in rows}
    assert by_label["fixed"]["scan fixed"] == "100%" and by_label["fixed"]["scan new"] == "0.0"
    assert by_label["noop"]["scan fixed"] == "0%"


def test_compare_without_rescan_leaves_scan_columns_empty(app, tmp_path):
    batch = {"batch_id": "exp", "files_to_fix": [{"file": "routes/route.js", "findings": []}]}
    (tmp_path / "r" / "exp").mkdir(parents=True)
    _, rows = compare.compare([("r", tmp_path / "r")], [batch], app)
    assert rows[0]["scan fixed"] == "-" and rows[0]["scan new"] == "-"
    assert "scan fixed" in compare.format_markdown(rows)


# --------------------------------------------------------------------------------------
# Python apps (PyGoat): seams and syntax
# --------------------------------------------------------------------------------------

VIEWS = "import pickle\n\ndef buy(request):\n    return pickle.loads(request.body)\n\nclass Cart:\n    pass\n"
URLS = "from . import views\nfrom .views import Cart\nurlpatterns = [path('buy', views.buy)]\n"


@pytest.fixture
def py_app(tmp_path):
    (tmp_path / "shop").mkdir()
    (tmp_path / "shop" / "__init__.py").write_text("", encoding="utf-8")
    (tmp_path / "shop" / "views.py").write_text(VIEWS, encoding="utf-8")
    (tmp_path / "shop" / "urls.py").write_text(URLS, encoding="utf-8")
    return tmp_path


def _py_originals():
    return {"shop/views.py": VIEWS, "shop/urls.py": URLS}


def test_python_fix_that_keeps_the_view_has_no_broken_seams(py_app):
    fixed = {"shop/views.py": VIEWS.replace("pickle.loads(request.body)", "json.loads(request.body)")}
    assert compare.broken_seams(py_app, _py_originals(), fixed) == []


def test_python_renaming_a_routed_view_is_a_broken_seam(py_app):
    fixed = {"shop/views.py": VIEWS.replace("def buy(", "def buy_safe(")}
    assert compare.broken_seams(py_app, _py_originals(), fixed) == [
        "shop/urls.py uses .buy which the fix removed from shop/views.py"]


def test_python_removing_a_directly_imported_name_is_a_broken_seam(py_app):
    fixed = {"shop/views.py": VIEWS.replace("class Cart:\n    pass\n", "")}
    assert compare.broken_seams(py_app, _py_originals(), fixed) == [
        "shop/urls.py imports Cart which the fix removed from shop/views.py"]


def test_python_syntax_check(tmp_path):
    good, bad = tmp_path / "good.py", tmp_path / "bad.py"
    good.write_text("def f():\n    return 1\n", encoding="utf-8")
    bad.write_text("def f(:\n", encoding="utf-8")
    assert compare._syntax_ok(good) is True
    assert compare._syntax_ok(bad) is False

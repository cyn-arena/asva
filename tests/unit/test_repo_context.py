"""Unit tests for agent/repo_context.py -- the import index behind repo-aware fix prompts
(ITP2 task 3.1). Parser cases use small synthetic JS trees; the ground-truth cases run
against the real NodeGoat tree and skip if it isn't checked out."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent.repo_context import (
    ContextBudget,
    build_import_index,
    gather_repo_context,
    package_usage_sites,
    render_code_flow,
)

pytestmark = pytest.mark.unit

NODEGOAT = Path(__file__).resolve().parents[2] / "target-apps" / "NodeGoat"


def _tree(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


def _importers(index, path: str) -> set[str]:
    return {imp for imp, _ in index.importers.get(path, [])}


# --------------------------------------------------------------------------------------
# Parsing and resolution
# --------------------------------------------------------------------------------------

def test_multiline_destructured_require_is_an_edge_with_bindings(tmp_path):
    root = _tree(tmp_path, {
        "routes/benefits.js": 'const {\n    BenefitsDAO\n} = require("../data/benefits-dao");\n'
                              "const dao = new BenefitsDAO(db);\ndao.getAll();\n",
        "data/benefits-dao.js": "module.exports = { BenefitsDAO };\n",
    })
    index = build_import_index(root)
    assert _importers(index, "data/benefits-dao.js") == {"routes/benefits.js"}
    ref = index.importers["data/benefits-dao.js"][0][1]
    assert ref.bindings == ("BenefitsDAO",)
    assert ref.line_no == 1


def test_member_require_binds_the_declared_name(tmp_path):
    root = _tree(tmp_path, {
        "a.js": 'const UserDAO = require("./user-dao").UserDAO;\n',
        "user-dao.js": "",
    })
    index = build_import_index(root)
    assert index.importers["user-dao.js"][0][1].bindings == ("UserDAO",)


def test_extensionless_directory_and_parent_traversal_resolve(tmp_path):
    root = _tree(tmp_path, {
        "server.js": 'const routes = require("./app/routes");\n',
        "app/routes/index.js": 'const cfg = require("../../config/config");\n',
        "config/config.js": "",
    })
    index = build_import_index(root)
    assert _importers(index, "app/routes/index.js") == {"server.js"}
    assert _importers(index, "config/config.js") == {"app/routes/index.js"}


def test_packages_are_usage_not_edges(tmp_path):
    root = _tree(tmp_path, {
        "server.js": 'const MongoClient = require("mongodb").MongoClient;\n'
                     'const x = require("@scope/pkg/sub");\n',
    })
    index = build_import_index(root)
    assert index.importers == {}
    assert package_usage_sites(index, "mongodb") == ["server.js:1"]
    assert package_usage_sites(index, "@scope/pkg") == ["server.js:2"]


def test_commented_out_requires_produce_no_edges(tmp_path):
    root = _tree(tmp_path, {
        "a.js": '// const b = require("./b");\n'
                '/* old code\n   const c = require("./c");\n*/\n'
                'const url = "http://example.com//x"; const d = require("./d");\n',
        "b.js": "", "c.js": "", "d.js": "",
    })
    index = build_import_index(root)
    assert _importers(index, "b.js") == set()
    assert _importers(index, "c.js") == set()
    # `//` inside a string literal is not a comment, so the require after it still counts
    assert _importers(index, "d.js") == {"a.js"}
    # line numbers survive comment stripping
    assert index.importers["d.js"][0][1].line_no == 5


def test_computed_require_produces_no_edge(tmp_path):
    root = _tree(tmp_path, {
        "config.js": 'const all = require(path.resolve(__dirname + "/env/all.js"));\n',
        "env/all.js": "",
    })
    index = build_import_index(root)
    assert index.importers == {}


def test_excluded_directories_are_not_indexed(tmp_path):
    root = _tree(tmp_path, {
        "app.js": "",
        "node_modules/lib/index.js": 'require("../../app");\n',
        "public/vendor/jquery.js": 'require("../../app");\n',
    })
    index = build_import_index(root)
    assert set(index.files) == {"app.js"}


# --------------------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------------------

def test_context_lists_importer_require_line_and_instance_call_sites(tmp_path):
    root = _tree(tmp_path, {
        "routes/session.js": 'const UserDAO = require("../data/user-dao").UserDAO;\n'
                             "function Session(db) {\n"
                             "  const userDAO = new UserDAO(db);\n"
                             "  userDAO.validateLogin(u, p);\n"
                             "}\n",
        "data/user-dao.js": "function UserDAO(db) {}\n",
    })
    ctx = gather_repo_context("data/user-dao.js", build_import_index(root))
    assert "Imported by" in ctx
    assert "routes/session.js" in ctx
    assert 'L1: const UserDAO = require("../data/user-dao").UserDAO;' in ctx
    assert "L3: const userDAO = new UserDAO(db);" in ctx
    assert "L4: userDAO.validateLogin(u, p);" in ctx


def test_context_lists_local_imports(tmp_path):
    root = _tree(tmp_path, {
        "routes/profile.js": 'const ProfileDAO = require("../data/profile-dao").ProfileDAO;\n',
        "data/profile-dao.js": "",
    })
    ctx = gather_repo_context("routes/profile.js", build_import_index(root))
    assert "Imports (local modules" in ctx
    assert "data/profile-dao.js via L1" in ctx


def test_isolated_or_unknown_file_yields_empty_string(tmp_path):
    root = _tree(tmp_path, {"lonely.js": "module.exports = 1;\n"})
    index = build_import_index(root)
    assert gather_repo_context("lonely.js", index) == ""
    assert gather_repo_context("not/indexed.js", index) == ""
    assert gather_repo_context("lonely.js", None) == ""


def test_budget_caps_importers_call_sites_and_total_chars(tmp_path):
    files = {"core.js": ""}
    for i in range(8):
        files[f"user{i}.js"] = 'const core = require("./core");\n' + "core.run();\n" * 20
    index = build_import_index(_tree(tmp_path, files))

    ctx = gather_repo_context("core.js", index, ContextBudget(max_importers=3, max_call_sites=2))
    assert ctx.count("- user") == 3
    assert "(5 more importer(s) not shown)" in ctx
    assert "(18 more usage line(s) not shown)" in ctx

    small = gather_repo_context("core.js", index, ContextBudget(max_chars=300))
    assert len(small) <= 300
    assert small.endswith("... (truncated)")


# --------------------------------------------------------------------------------------
# Ground truth against the real NodeGoat tree
# --------------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def nodegoat_index():
    if not (NODEGOAT / "server.js").exists():
        pytest.skip("target-apps/NodeGoat not present")
    return build_import_index(NODEGOAT)


def test_nodegoat_user_dao_importers(nodegoat_index):
    assert _importers(nodegoat_index, "app/data/user-dao.js") == {
        "app/data/allocations-dao.js",
        "app/data/contributions-dao.js",
        "app/routes/session.js",
    }


def test_nodegoat_profile_route_is_registered_only_in_index(nodegoat_index):
    assert _importers(nodegoat_index, "app/routes/profile.js") == {"app/routes/index.js"}


def test_nodegoat_directory_require_resolves_to_routes_index(nodegoat_index):
    assert _importers(nodegoat_index, "app/routes/index.js") == {"server.js"}


def test_nodegoat_commented_config_require_in_profile_dao_is_ignored(nodegoat_index):
    assert "app/data/profile-dao.js" not in _importers(nodegoat_index, "config/config.js")


def test_nodegoat_mongodb_usage_is_found(nodegoat_index):
    assert "server.js:11" in package_usage_sites(nodegoat_index, "mongodb")


# --------------------------------------------------------------------------------------
# SAST code flow (Task 1: "include files in codeflow")
# --------------------------------------------------------------------------------------

def _flow(*steps, title="SQL Injection", sink=None):
    return {"title": title, "location": {"line": sink or steps[-1][1]},
            "code_flow": [{"file": f, "line": n} for f, n in steps]}


def test_code_flow_includes_code_from_other_files_on_the_path(tmp_path):
    root = _tree(tmp_path, {
        "routes/user.js": "a\nconst id = req.query.id;\nservice.find(id);\n",
        "services/user.js": "x\ny\nfunction find(id) {\n  return db.query(id);\n}\n",
    })
    index = build_import_index(root)
    text = render_code_flow("services/user.js",
                            [_flow(("routes/user.js", 2), ("services/user.js", 4))], index)
    assert "routes/user.js L2 -> L4" in text
    assert "L4: return db.query(id);" in text            # this file's step, with its code
    assert "Other files in the data flow" in text
    assert "L2: const id = req.query.id;" in text           # the other file's code is included


def test_code_flow_excludes_library_files(tmp_path):
    root = _tree(tmp_path, {"app.js": "a\nb\nc\n"})
    text = render_code_flow("app.js", [_flow(("node_modules/lib/index.js", 5), ("app.js", 2), ("app.js", 3))],
                            build_import_index(root))
    assert "node_modules" not in text
    assert "L2 -> L3" in text


def test_code_flow_that_stays_on_the_sink_line_is_skipped(tmp_path):
    root = _tree(tmp_path, {"app.js": "eval(x)\n"})
    assert render_code_flow("app.js", [_flow(("app.js", 1))], build_import_index(root)) == ""
    assert render_code_flow("app.js", [{"title": "t", "location": {"line": 1}}],
                            build_import_index(root)) == ""


def test_code_flow_is_capped(tmp_path):
    root = _tree(tmp_path, {"a.js": "x\n" * 50, "b.js": "y\n" * 50})
    findings = [_flow(("b.js", n), ("a.js", n)) for n in range(1, 40)]
    text = render_code_flow("a.js", findings, build_import_index(root), max_chars=500)
    assert len(text) <= 500 and text.endswith("... (truncated)")


# --------------------------------------------------------------------------------------
# JavaScript ES modules / TypeScript
# --------------------------------------------------------------------------------------

def test_es_module_imports_are_edges_with_bindings(tmp_path):
    root = _tree(tmp_path, {
        "src/app.ts": 'import express from "express";\n'
                      'import Svc, { find as lookup, type Opts } from "./svc";\n'
                      'import * as util from "./util/index.js";\n'
                      'export { helper } from "./helper";\n'
                      'const lazy = await import("./lazy");\n'
                      'lookup(1); util.go();\n',
        "src/svc.ts": "export default class Svc {}\nexport function find() {}\n",
        "src/util/index.ts": "export function go() {}\n",
        "src/helper.tsx": "export const helper = 1;\n",
        "src/lazy.mjs": "",
    })
    index = build_import_index(root)
    assert _importers(index, "src/svc.ts") == {"src/app.ts"}
    assert index.importers["src/svc.ts"][0][1].bindings == ("Svc", "lookup", "Opts")
    assert index.importers["src/util/index.ts"][0][1].bindings == ("util",)  # ./util/index.js -> .ts
    assert _importers(index, "src/helper.tsx") == {"src/app.ts"}
    assert _importers(index, "src/lazy.mjs") == {"src/app.ts"}
    assert package_usage_sites(index, "express") == ["src/app.ts:1"]
    ctx = gather_repo_context("src/svc.ts", index)
    assert "L6: lookup(1); util.go();" in ctx


# --------------------------------------------------------------------------------------
# Python (PyGoat-style Django tree)
# --------------------------------------------------------------------------------------

DJANGO = {
    "manage.py": "import os\n",
    "proj/__init__.py": "",
    "proj/settings.py": 'ROOT_URLCONF = "proj.urls"\nINSTALLED_APPS = ["shop"]\n',
    "proj/urls.py": "from django.urls import include, path\n"
                    "from shop import views as v\n"
                    'urlpatterns = [path("", include("shop.urls")), path("r", v.register)]\n',
    "shop/__init__.py": "",
    "shop/models.py": "class Item:\n    pass\n\n\nclass Order:\n    pass\n",
    "shop/urls.py": "from django.urls import path\n"
                    "from . import views\n"
                    "urlpatterns = [\n"
                    '    path("list", views.item_list),\n'
                    '    path("buy", views.buy, name="buy"),\n'
                    '    path("search", views.search),\n'
                    "]\n",
    "shop/views.py": "import yaml\n"
                     "from .models import (Item,\n    Order)\n"
                     "# from .legacy import old\n"
                     "\n"
                     "def item_list(request):\n"
                     "    return Item.objects.all()\n"
                     "\n"
                     "def buy(request):\n"
                     "    data = yaml.load(request.body)\n"
                     "    return Order(data)\n"
                     "\n"
                     "def search(request):\n"
                     "    pass\n"
                     "\n"
                     "def register(request):\n"
                     "    pass\n",
    "shop/legacy.py": "",
}


@pytest.fixture
def django_index(tmp_path):
    return build_import_index(_tree(tmp_path, DJANGO))


def test_python_relative_submodule_and_name_imports(django_index):
    assert _importers(django_index, "shop/views.py") == {"shop/urls.py", "proj/urls.py"}
    # `from .models import (Item, Order)` is ONE edge with both names bound
    refs = django_index.importers["shop/models.py"]
    assert [(imp, r.bindings) for imp, r in refs] == [("shop/views.py", ("Item", "Order"))]
    assert refs[0][1].line_no == 2 and refs[0][1].end_line == 3


def test_python_absolute_import_with_alias_resolves_from_manage_py_root(django_index):
    ref = [r for imp, r in django_index.importers["shop/views.py"] if imp == "proj/urls.py"][0]
    assert ref.bindings == ("v",)


def test_python_django_module_strings_are_edges(django_index):
    assert _importers(django_index, "shop/urls.py") == {"proj/urls.py"}     # include("shop.urls")
    assert _importers(django_index, "proj/urls.py") == {"proj/settings.py"}  # ROOT_URLCONF


def test_python_commented_import_and_packages(django_index):
    assert _importers(django_index, "shop/legacy.py") == set()
    assert package_usage_sites(django_index, "yaml") == ["shop/views.py:1"]
    assert "proj/urls.py:1" in package_usage_sites(django_index, "django")


def test_python_context_ranks_the_route_of_the_vulnerable_view_first(django_index):
    # finding inside buy() at line 10
    ctx = gather_repo_context("shop/views.py", django_index,
                              ContextBudget(max_other_call_sites=1),
                              findings=[{"location": {"line": 10}}])
    assert "lines using buy, which contains the findings, are listed first" in ctx
    urls = ctx[ctx.index("- shop/urls.py"):]
    assert urls.index('path("buy", views.buy') < urls.index('path("list", views.item_list)')
    assert 'path("search"' not in urls.split("- proj/urls.py")[0]   # capped: 1 other line
    assert "(1 more usage line(s) not shown)" in ctx


def test_python_string_mentions_are_not_focus_uses(tmp_path):
    root = _tree(tmp_path, {
        "a/__init__.py": "",
        "a/views.py": "def buy(r):\n    pass\n\ndef sell(r):\n    pass\n",
        "a/urls.py": "from . import views\n"
                     'x = [path("sell", views.buy)]\n'
                     'y = [path("other", views.sell)]\n',
    })
    ctx = gather_repo_context("a/views.py", build_import_index(root),
                              findings=[{"location": {"line": 5}}])     # inside sell()
    lines = ctx.splitlines()
    assert lines.index('    L3: y = [path("other", views.sell)]') < lines.index('    L2: x = [path("sell", views.buy)]')


def test_python2_file_falls_back_to_line_scanning(tmp_path):
    root = _tree(tmp_path, {
        "old.py": 'import helper\nprint "py2 only"\nhelper.go()\n',
        "helper.py": "def go(): pass\n",
    })
    index = build_import_index(root)
    assert _importers(index, "helper.py") == {"old.py"}
    assert "L3: helper.go()" in gather_repo_context("helper.py", index)


def test_python_virtualenvs_are_not_indexed(tmp_path):
    root = _tree(tmp_path, {"app.py": "", ".venv/lib/site-packages/x.py": "import app\n",
                            "venv/y.py": "import app\n"})
    assert set(build_import_index(root).files) == {"app.py"}


def test_python_import_names_for_distributions():
    from agent.repo_context import python_import_names
    assert python_import_names("PyYAML") == ("yaml",)
    assert python_import_names("Django") == ("django",)
    assert python_import_names("django_heroku") == ("django_heroku",)
    assert python_import_names("Pillow") == ("PIL",)


def test_detect_app_language(tmp_path):
    from agent.repo_context import detect_app_language
    assert detect_app_language(_tree(tmp_path / "py", {"manage.py": ""})) == "python"
    assert detect_app_language(_tree(tmp_path / "js", {"package.json": "{}"})) == "node"
    assert detect_app_language(_tree(tmp_path / "req", {"requirements.txt": ""})) == "python"
    assert detect_app_language(tmp_path / "missing") == ""


def test_javascript_focus_symbol_is_the_enclosing_handler(tmp_path):
    root = _tree(tmp_path, {
        "routes/profile.js": "function ProfileHandler(db) {\n"
                             "  this.displayProfile = (req, res) => {\n"
                             "    res.render(x);\n"
                             "  };\n"
                             "  this.handleProfileUpdate = (req, res) => {\n"
                             "    const r = new RegExp(req.body.x);\n"
                             "  };\n"
                             "}\nmodule.exports = ProfileHandler;\n",
        "routes/index.js": 'const ProfileHandler = require("./profile");\n'
                           "const profileHandler = new ProfileHandler(db);\n"
                           'app.get("/profile", profileHandler.displayProfile);\n'
                           'app.post("/profile", profileHandler.handleProfileUpdate);\n',
    })
    ctx = gather_repo_context("routes/profile.js", build_import_index(root),
                              findings=[{"location": {"line": 6}}])
    body = ctx.splitlines()
    assert body.index('    L4: app.post("/profile", profileHandler.handleProfileUpdate);') < \
        body.index("    L2: const profileHandler = new ProfileHandler(db);")


# --------------------------------------------------------------------------------------
# Ground truth against the real PyGoat tree
# --------------------------------------------------------------------------------------

PYGOAT = Path(__file__).resolve().parents[2] / "target-apps" / "PyGoat"


@pytest.fixture(scope="module")
def pygoat_index():
    if not (PYGOAT / "manage.py").exists():
        pytest.skip("target-apps/PyGoat not present")
    return build_import_index(PYGOAT)


def test_pygoat_views_importers(pygoat_index):
    assert _importers(pygoat_index, "introduction/views.py") == {
        "introduction/apis.py", "introduction/mitre.py", "introduction/urls.py", "pygoat/urls.py",
    }


def test_pygoat_urlconf_chain(pygoat_index):
    assert _importers(pygoat_index, "introduction/urls.py") == {"pygoat/urls.py"}
    assert _importers(pygoat_index, "pygoat/urls.py") == {"pygoat/settings.py"}


def test_pygoat_models_and_package_usage(pygoat_index):
    assert {"introduction/views.py", "introduction/admin.py"} <= _importers(
        pygoat_index, "introduction/models.py")
    assert "introduction/views.py:23" in package_usage_sites(pygoat_index, "yaml")


def test_pygoat_view_context_shows_its_url_route(pygoat_index):
    text = (PYGOAT / "introduction" / "views.py").read_text(encoding="utf-8").splitlines()
    line = next(i for i, l in enumerate(text, start=1) if "pickle.loads(" in l)
    ctx = gather_repo_context("introduction/views.py", pygoat_index,
                              findings=[{"location": {"line": line}}])
    assert "views.insec_des_lab" in ctx.split("- introduction/urls.py")[1].splitlines()[2]


VULNBANK = Path(__file__).resolve().parents[2] / "target-apps" / "vulnbank"


def test_vulnbank_flask_app_is_indexed():
    if not (VULNBANK / "app.py").exists():
        pytest.skip("target-apps/vulnbank not present")
    from agent.repo_context import detect_app_language, detect_python_framework
    assert detect_app_language(VULNBANK) == "python"
    assert detect_python_framework(VULNBANK) == "Flask"
    index = build_import_index(VULNBANK)
    assert {"app.py", "merchant_payments.py"} <= _importers(index, "auth.py")
    assert "app.py" in _importers(index, "database.py")


def test_file_imported_twice_by_one_importer_is_listed_once(tmp_path):
    root = _tree(tmp_path, {
        "auth.py": "SECRET = 1\n\ndef verify(t):\n    return t\n",
        "app.py": "import auth\nfrom auth import verify\nx = auth.SECRET\nverify(1)\n",
    })
    ctx = gather_repo_context("auth.py", build_import_index(root),
                              findings=[{"location": {"line": 4}}])
    assert ctx.count("- app.py") == 1
    lines = ctx.splitlines()
    # the statement that imports the vulnerable function comes first
    assert lines.index("    L2: from auth import verify") < lines.index("    L1: import auth")


def test_django_settings_module_lists_and_package_sites_are_deduplicated(tmp_path):
    root = _tree(tmp_path, {
        "manage.py": "",
        "shop/__init__.py": "",
        "proj/settings.py": "INSTALLED_APPS = [\n    'django.contrib.admin',\n    'allauth',\n    'shop',\n]\n",
        "proj/urls.py": "from PIL import Image, ImageMath\nurlpatterns = [path('a/', include('allauth.urls'))]\n",
    })
    index = build_import_index(root)
    assert package_usage_sites(index, "allauth") == ["proj/settings.py:3", "proj/urls.py:2"]
    assert package_usage_sites(index, "PIL") == ["proj/urls.py:1"]
    assert _importers(index, "shop/__init__.py") == {"proj/settings.py"}
    from agent.repo_context import python_import_names
    assert python_import_names("django-allauth") == ("allauth",)

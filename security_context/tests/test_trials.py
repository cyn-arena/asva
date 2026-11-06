"""The trial plan (app/trials.py): held-back upgrades in the order to try them, with what else
each needs. Registry answers are small hand-written PyPI and npm metadata in the shape the real
registries return."""

import json

import pytest

from app import trials
from app.sources import packages


def pypi_release(apis, name, version, requires):
    apis.json[("pypi.org", f"/pypi/{name}/{version}/json")] = {"info": {"requires_dist": requires, "requires_python": ">=3.8"}}


def pypi_project(apis, name, versions_):
    apis.json[("pypi.org", f"/pypi/{name}/json")] = {"releases": {v: [{"yanked": False}] for v in versions_}}


def npm_package(apis, name, versions_):  # {version: {dependency: range}}
    apis.json[("registry.npmjs.org", f"/{name}")] = {"versions": {v: {"dependencies": deps} for v, deps in versions_.items()}}


# -- reading versions and ranges -------------------------------------------------------------------

def test_parse_manifest_reads_pins_and_development_packages():
    pip = trials.parse_manifest({"file": "requirements.txt", "content": "Django==4.2\nPyYAML==5.1  # yaml\nrequests>=2\n"})
    assert pip["ecosystem"] == "pip" and pip["pins"] == {"django": "4.2", "pyyaml": "5.1"}
    npm = trials.parse_manifest({"file": "package.json", "dev_only": ["handlebars@4.0.5"],
                                 "content": '{"dependencies": {"express": "^4.13.4"}, "devDependencies": {"mocha": "^2"}}'})
    assert npm["ecosystem"] == "npm" and npm["dev"] == {"mocha"} and npm["dev_only"] == {"handlebars@4.0.5"}
    assert trials.parse_manifest(None)["ecosystem"] is None


@pytest.mark.parametrize("version, spec, ok", [
    ("1.15.1", ">=2.0.0", False), ("2.0.0", ">=2.0.0", True), ("2.8.0", "<1.27,>=1.21.1", False), ("1.26.19", "<1.27,>=1.21.1", True)])
def test_satisfies_reads_pip_specifiers(version, spec, ok):
    assert trials.satisfies(version, spec) is ok


@pytest.mark.parametrize("spec, lower", [("^1.20.3", "1.20.3"), ("~2.0.7", "2.0.7"), ("1.x", "1.0.0"), ("6.5.2", "6.5.2"),
                                          (">=1.0.0 <2", "1.0.0"), ("^2.0.0 || ^1.1.4", "1.1.4"), ("*", "0.0.0")])
def test_npm_lower_bound(spec, lower):
    assert trials.npm_lower_bound(spec) == lower


@pytest.mark.parametrize("spec, version, ok", [
    ("^1.20.3", "1.20.9", True), ("^1.20.3", "2.0.0", False), ("~2.0.4", "2.0.7", True), ("~2.0.4", "2.1.0", False),
    ("6.5.2", "6.5.3", False), ("^0.4.3", "0.4.9", True), ("^0.4.3", "0.5.0", False), ("1.x", "1.9.0", True),
    (">=1.2.0 <1.3.0", "1.2.5", True), ("^1.0.0 || ^2.0.0", "2.0.1", True), ("1.0.0 - 1.4.0", "1.5.0", False), ("*", "9.9.9", True)])
def test_npm_allows(spec, version, ok):
    assert trials.npm_allows(spec, version) is ok


# -- companion upgrades -----------------------------------------------------------------------------

def test_companions_find_what_the_target_needs_and_what_caps_it(conn, http_client, apis):
    pypi_release(apis, "cryptography", "49.0.0", ['cffi>=2.0.0; platform_python_implementation != "PyPy"', "pytest; extra == 'test'"])
    pypi_project(apis, "cffi", ["1.15.1", "1.17.1", "2.0.0", "2.1.0"])
    pypi_release(apis, "cffi", "1.15.1", [])
    pypi_release(apis, "requests", "2.28.2", ["urllib3<1.27,>=1.21.1"])
    found = trials.companions(conn, http_client, "cryptography", "49.0.0", {"cffi": "1.15.1", "requests": "2.28.2"}, [])
    assert found == [{"name": "cffi", "current": "1.15.1", "suggest": "2.0.0", "major_change": True,
                      "reason": "cryptography 49.0.0 requires cffi>=2.0.0"}]

    pypi_release(apis, "urllib3", "2.8.0", [])
    pypi_project(apis, "requests", ["2.28.2", "2.29.0", "2.30.0", "2.31.0"])
    pypi_release(apis, "requests", "2.29.0", ["urllib3<1.27,>=1.21.1"])
    pypi_release(apis, "requests", "2.30.0", ["urllib3<3,>=1.21.1"])
    found = trials.companions(conn, http_client, "urllib3", "2.8.0", {"requests": "2.28.2", "cffi": "1.15.1"}, [])
    assert found == [{"name": "requests", "current": "2.28.2", "suggest": "2.30.0", "major_change": False,
                      "reason": "requests 2.28.2 requires urllib3<1.27,>=1.21.1"}]


def test_registry_answers_are_cached(conn, http_client, apis):
    pypi_release(apis, "cffi", "1.15.1", [])
    packages.requirements(conn, http_client, "pip", "cffi", "1.15.1", [])
    packages.requirements(conn, http_client, "pip", "cffi", "1.15.1", [])
    assert apis.hosts().count("pypi.org") == 1


# -- the plan ----------------------------------------------------------------------------------------

def upgrade(name, current, target, fixes, compatible=None, scope=None, major=True):
    return {"kind": "package", "name": name, "current": current, "target": target, "fixes": fixes,
            "compatible_target": compatible, "compatible_scope": scope, "major_change": major,
            "status": "major_change" if major else "ok"}


def test_plan_orders_known_exploited_first_and_lists_partly_fixed_packages(conn, http_client, apis):
    upgrades = [upgrade("sqlparse", "0.3.1", "0.6.0", ["CVE-1", "CVE-2", "CVE-3"]),
                upgrade("pillow", "9.4.0", "12.3.0", ["CVE-2023-4863"]),
                upgrade("urllib3", "1.26.9", "2.8.0", ["CVE-4"], compatible="1.26.19", scope="partial"),
                upgrade("django", "4.2", "4.2.28", ["CVE-5"], compatible="4.2.28", scope="all", major=False)]
    references = [{"type": "cve", "id": "CVE-2023-4863", "kev": True}]
    plan = trials.plan(conn, http_client, [], upgrades, references, None, [], use_registries=False)
    assert [(t["order"], t["name"]) for t in plan] == [(1, "pillow"), (2, "sqlparse"), (3, "urllib3")]
    assert plan[0]["known_exploited"] == ["CVE-2023-4863"] and plan[0]["kind"] == "major_upgrade"


def test_plan_puts_development_only_upgrades_last(conn, http_client, apis):
    findings = [{"cve": "CVE-9", "package": "handlebars@4.0.5", "upgrade_to": "grunt-contrib-nodeunit@2.0.0",
                 "dependency_path": ["app@1.0.0", "grunt-contrib-nodeunit@1.0.0", "handlebars@4.0.5"]}]
    upgrades = [upgrade("grunt-contrib-nodeunit", "1.0.0", "2.0.0", ["CVE-9"] * 1),
                upgrade("mongodb", "2.2.36", "3.1.13", ["CVE-8"])]
    manifest = {"file": "package.json", "content": '{"dependencies": {"mongodb": "^2.1.18"}}', "dev_only": ["handlebars@4.0.5"]}
    plan = trials.plan(conn, http_client, findings, upgrades, [], manifest, [], use_registries=False, use_osv=False)
    assert [(t["name"], t["dev_only"]) for t in plan] == [("mongodb", False), ("grunt-contrib-nodeunit", True)]


def test_npm_plan_suggests_a_refresh_and_a_newer_parent_within_its_major(conn, http_client, apis, monkeypatch):
    nested = [{"cve": "CVE-QS", "package": "qs@6.5.2", "upgrade_to": "body-parser@1.20.4",
               "dependency_path": ["app@1.0.0", "body-parser@1.18.3", "qs@6.5.2"]},
              {"cve": "CVE-PA", "package": "proxy-addr@2.0.4", "upgrade_to": "express@4.16.4",
               "dependency_path": ["app@1.0.0", "express@4.16.4", "proxy-addr@2.0.4"]}]
    npm_package(apis, "body-parser", {"1.18.3": {"qs": "6.5.2"}, "1.20.4": {"qs": "6.14.0"}, "1.20.9": {"qs": "~6.14.1"},
                                      "2.0.0": {"qs": "^6.14.1"}})
    npm_package(apis, "express", {"4.16.4": {"proxy-addr": "~2.0.4"}, "4.22.0": {"proxy-addr": "~2.0.7"}})
    monkeypatch.setattr(trials.osv, "advisories", lambda conn, client, name, version, eco, warnings, online=True: [
        {"id": "GHSA-1", "aliases": ["CVE-QS"], "fixed": "6.14.1"} if name == "qs" else
        {"id": "GHSA-2", "aliases": ["CVE-PA"], "fixed": "2.0.7"}])
    upgrades = [upgrade("body-parser", "1.18.3", "1.20.4", ["CVE-QS"], compatible="1.20.4", scope="all", major=False)]
    manifest = {"file": "package.json", "content": '{"dependencies": {"body-parser": "^1.15.1", "express": "^4.13.4"}}'}
    plan = trials.plan(conn, http_client, nested, upgrades, [], manifest, [])
    refresh = next(t for t in plan if t["kind"] == "lockfile_refresh")
    assert refresh["fixes"] == ["CVE-PA"]             # 2.0.7 is within express 4.16.4's "~2.0.4"; qs is pinned exactly
    parent = next(t for t in plan if t["kind"] == "parent_upgrade")
    assert (parent["name"], parent["target"], parent["fixes"]) == ("body-parser", "1.20.9", ["CVE-QS"])  # 1.20.4 is not enough
    assert [t["kind"] for t in plan] == ["lockfile_refresh", "parent_upgrade", "parent_upgrade"][:len(plan)]


def test_a_parent_upgrade_the_safe_upgrade_already_covers_is_left_out(conn, http_client, apis, monkeypatch):
    nested = [{"cve": "CVE-QS", "package": "qs@6.5.2", "upgrade_to": "body-parser@1.20.4",
               "dependency_path": ["app@1.0.0", "body-parser@1.18.3", "qs@6.5.2"]}]
    npm_package(apis, "body-parser", {"1.18.3": {"qs": "6.5.2"}, "1.20.4": {"qs": "6.14.1"}, "1.20.9": {"qs": "6.14.2"}})
    monkeypatch.setattr(trials.osv, "advisories", lambda *a, **k: [{"id": "GHSA-1", "aliases": ["CVE-QS"], "fixed": "6.14.1"}])
    upgrades = [upgrade("body-parser", "1.18.3", "1.20.4", ["CVE-QS"], compatible="1.20.4", scope="all", major=False)]
    plan = trials.plan(conn, http_client, nested, upgrades, [], {"file": "package.json", "content": "{}"}, [])
    assert not [t for t in plan if t["kind"] == "parent_upgrade"]


# -- through the API and the client --------------------------------------------------------------------

def test_client_reads_development_only_packages_from_the_lockfile():
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "integration"))
    import asva_rag_client
    lock = ('{"lockfileVersion": 2, "packages": {"": {}, "node_modules/express": {"version": "4.16.4"}, '
            '"node_modules/handlebars": {"version": "4.0.5", "dev": true}}}')
    assert asva_rag_client.npm_dev_only(lock) == ["handlebars@4.0.5"]


# -- npm: every installed copy, from the lockfile ----------------------------------------------------

LOCK = json.dumps({"lockfileVersion": 2, "packages": {
    "": {"dependencies": {"express": "4.16.4", "body-parser": "1.20.4"}, "devDependencies": {"mocha": "^2"}},
    "node_modules/express": {"version": "4.16.4", "dependencies": {"body-parser": "1.18.3", "qs": "6.5.2"}},
    "node_modules/express/node_modules/body-parser": {"version": "1.18.3", "dependencies": {"qs": "6.5.2"}},
    "node_modules/qs": {"version": "6.5.2"},
    "node_modules/body-parser": {"version": "1.20.4", "dependencies": {"qs": "6.14.2"}},
    "node_modules/body-parser/node_modules/qs": {"version": "6.14.2"},
    "node_modules/mocha": {"version": "2.5.3", "dev": True, "dependencies": {"qs": "^5"}},
    "node_modules/mocha/node_modules/qs": {"version": "5.2.1", "dev": True}}})


def test_npm_copies_follows_node_s_module_resolution(monkeypatch):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "integration"))
    import asva_rag_client
    copies = asva_rag_client.npm_copies(LOCK, ["qs", "body-parser"])
    qs = {(c["version"], c["dev"], " > ".join(c["chain"])) for c in copies["qs"]}
    assert qs == {("6.5.2", False, "express@4.16.4 > qs@6.5.2"), ("6.14.2", False, "body-parser@1.20.4 > qs@6.14.2"),
                  ("5.2.1", True, "mocha@2.5.3 > qs@5.2.1")}
    assert {" > ".join(c["chain"]) for c in copies["body-parser"]} == {"body-parser@1.20.4", "express@4.16.4 > body-parser@1.18.3"}


def test_npm_plan_needs_every_copy_fixed_and_names_the_real_parent(conn, http_client, apis, monkeypatch):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "integration"))
    import asva_rag_client
    findings = [{"cve": "CVE-QS", "package": "qs@6.5.2", "upgrade_to": "body-parser@1.20.4",
                 "dependency_path": ["app@1.0.0", "body-parser@1.18.3", "qs@6.5.2"]}]
    npm_package(apis, "express", {"4.16.4": {"qs": "6.5.2", "body-parser": "1.18.3"},
                                  "4.22.3": {"qs": "~6.14.1", "body-parser": "~1.20.4"}, "5.3.0": {"qs": "^6.14.1"}})
    npm_package(apis, "body-parser", {"1.20.4": {"qs": "6.14.2"}})
    monkeypatch.setattr(trials.osv, "advisories", lambda *a, **k: [{"id": "GHSA-1", "aliases": ["CVE-QS"], "fixed": "6.14.1"}])
    manifest = {"file": "package.json", "content": '{"dependencies": {"express": "4.16.4", "body-parser": "1.20.4"}}',
                "dev_only": ["qs@5.2.1", "mocha@2.5.3"], "copies": asva_rag_client.npm_copies(LOCK, ["qs"])}
    plan = trials.plan(conn, http_client, findings, [], [], manifest, [])
    assert [(t["kind"], t["name"], t["target"], t["fixes"]) for t in plan] == [("parent_upgrade", "express", "4.22.3", ["CVE-QS"])]


# -- other versions when one fails --------------------------------------------------------------------

@pytest.fixture
def advisories(monkeypatch):
    """package@version -> how many advisories OSV.dev knows; anything else has none."""
    known = {}

    def answer(conn, client, name, version, ecosystem, warnings, *, online=True, max_age=None):
        found = known.get(f"{name}@{version}", 0)
        return None if found is None else [{"id": "X", "aliases": [], "fixed": None, "summary": "", "url": ""}] * found

    monkeypatch.setattr(trials.osv, "advisories", answer)
    return known


def test_clean_versions_take_the_newest_of_each_major_smallest_step_first(conn, http_client, apis, advisories):
    pypi_project(apis, "pyyaml", ["5.1", "5.4", "5.4.1", "6.0", "6.0.3", "7.0.0"])
    assert trials.clean_versions(conn, http_client, "pyyaml", "5.4", "pip", []) == ["5.4.1", "6.0.3"]


def test_clean_versions_skip_one_with_a_known_advisory_or_unknown_to_osv(conn, http_client, apis, advisories):
    pypi_project(apis, "pyyaml", ["5.4", "5.4.1", "6.0.3", "7.0.0"])
    advisories["pyyaml@5.4.1"] = 1
    advisories["pyyaml@6.0.3"] = None
    assert trials.clean_versions(conn, http_client, "pyyaml", "5.4", "pip", []) == ["7.0.0"]


def _plan(conn, http_client, findings, upgrades):
    return trials.plan(conn, http_client, findings, upgrades, [], {"file": "requirements.txt", "content": "unrelated==1.0\n"}, [])


def test_a_trial_whose_target_has_an_advisory_tries_a_clean_version_first(conn, http_client, apis, advisories):
    pypi_project(apis, "cryptography", ["39.0.1", "49.0.0", "50.0.2"])
    advisories["cryptography@49.0.0"] = 1
    found = _plan(conn, http_client, [], [upgrade("cryptography", "39.0.1", "49.0.0", ["C"])])
    assert found[0]["target"] == "50.0.2" and [f["target"] for f in found[0]["fallbacks"]] == ["49.0.0"]
    assert "still has a known advisory" in found[0]["note"]


def test_a_trial_falls_back_to_lower_versions_the_scanner_names_highest_first(conn, http_client, apis, advisories):
    pypi_project(apis, "lib", ["0.52.0", "0.54.0", "65.13.0"])
    findings = [{"cve": "A", "package": "lib@0.52.0", "upgrade_to": "lib@0.54.0"}, {"cve": "B", "package": "lib@0.52.0", "upgrade_to": "lib@0.53.0"},
                {"cve": "C", "package": "lib@0.52.0", "upgrade_to": "lib@65.13.0"}, {"cve": "D", "package": "other@1", "upgrade_to": "other@2.0.0"}]
    found = _plan(conn, http_client, findings, [upgrade("lib", "0.52.0", "65.13.0", ["A", "B", "C"])])
    assert found[0]["target"] == "65.13.0" and [f["target"] for f in found[0]["fallbacks"]] == ["0.54.0", "0.53.0"]


def test_a_safe_upgrade_lists_what_to_try_if_it_will_not_install(conn, http_client, apis, advisories):
    pypi_project(apis, "pyyaml", ["5.1", "5.4", "5.4.1", "6.0.3"])
    safe = upgrade("pyyaml", "5.1", "5.4", ["P"], compatible="5.4", major=False)
    _plan(conn, http_client, [], [safe])
    assert [f["target"] for f in safe["fallbacks"]] == ["5.4.1", "6.0.3"]


def test_without_the_sources_nothing_is_invented(conn, http_client, apis, advisories):
    safe = upgrade("pyyaml", "5.1", "5.4", ["P"], compatible="5.4", major=False)
    trials.plan(conn, http_client, [], [safe, upgrade("lib", "1.0.0", "2.0.0", ["L"])], [],
                {"file": "requirements.txt", "content": "unrelated==1.0\n"}, [], use_registries=False)
    assert not safe.get("fallbacks")

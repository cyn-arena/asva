"""ContextBuilder: what each fix type gets in the prompt, and the references, using real
NodeGoat findings with mocked NVD / OSV.dev / Context7 / KEV answers."""

import pytest

from datetime import date

from app import config, images, store
from app.context import ContextBuilder
from app.retrieve import Retriever
from app.sources import kev, osv
from conftest import fixture_json

EVAL = {"finding_type": "sast", "cwe": "CWE-94", "rule_id": "javascript/CodeInjection", "title": "Code Injection",
        "summary": "User input flows into eval, where it is executed as code."}


def finding(file: str, match: str) -> dict:
    """A real finding from the frozen NodeGoat sample (kept in step with the mocked API answers;
    the demo and evaluation use the current scan in nodegoat_findings.json), as request fields."""
    entry = next(e for e in fixture_json("findings_unit.json")["files"] if e["file"] == file)
    f = next(f for f in entry["findings"] if match in (f["location"].get("package") or "") + (f["identifiers"].get("cve") or "")
             + f["identifiers"]["rule_id"])
    return {"finding_type": f["finding_type"], "cve": f["identifiers"]["cve"], "cwe": f["identifiers"]["cwe"],
            "rule_id": f["identifiers"]["rule_id"], "package": f["location"]["package"], "ecosystem": f["ecosystem"],
            "upgrade_to": f["remediation"]["upgrade_to"], "fixable": f["remediation"]["fixable"],
            "dependency_path": (f.get("dependency") or {}).get("path"), "title": f["title"], "summary": f["summary"]}


MARKED = finding("package.json", "CVE-2016-10531")          # direct: marked 0.3.5 -> 0.3.6
MONGODB = finding("package.json", "SNYK-JS-MONGODB-473855")  # direct, no CVE: mongodb 2.2.36 -> 3.1.13 (major)
QS = finding("package.json", "CVE-2025-15284")              # transitive: qs via body-parser 1.18.3 -> 1.20.4
MINIMATCH = finding("package.json", "CVE-2026-27903")       # transitive via forever, already at 2.0.0
GLIBC = finding("docker-compose.yml", "CVE-2022-23219")


TODAY = date(2026, 10, 13)  # support dates in the endoflife.date fixture are judged from this day


@pytest.fixture
def builder(conn, fake_embedder, http_client):
    # the image's release lines are put into the prompt text here so the tests can read them there
    return ContextBuilder(Retriever.from_db(conn, fake_embedder, min_similarity=0.1), http_client, today=lambda: TODAY,
                          image_lines_in_prompt=True)


def build(builder, conn, findings, fix_type, max_chars=2500):
    trace = {}
    items, refs, warnings, _ = builder.build(conn, findings, fix_type, max_chars, trace)
    return items, refs, warnings, trace


def build_all(builder, conn, findings, fix_type, exclude=()):
    """Everything a request returns, as a dict (for the tests of upgrades and excluded sources)."""
    trace = {}
    items, refs, warnings, upgrades = builder.build(conn, findings, fix_type, 2500, trace, exclude=exclude)
    return {"items": items, "refs": refs, "warnings": warnings, "upgrades": upgrades, "trace": trace}


def text_of(items, kind):
    return "\n".join(i["text"] for i in items if i["kind"] == kind)


# -- code fixes ---------------------------------------------------------------------

def test_code_change_prompt_is_guidance_and_cwe_goes_to_references(builder, conn):
    items, refs, warnings, trace = build(builder, conn, [EVAL], "code_change")
    assert [i["kind"] for i in items] == ["guidance"] * len(items) and items
    cwe_ref = next(r for r in refs if r["type"] == "cwe")
    assert cwe_ref["id"] == "CWE-94"
    assert cwe_ref["owasp_top10"] == ["A03:2021 - Injection", "A05:2025 - Injection"]
    assert any(r["type"] == "guidance" for r in refs)
    assert trace["guidance_search"] == "ran" and trace["queries"]
    assert warnings == []


def test_code_change_without_matching_guidance_gets_the_compact_cwe(conn, fake_embedder, http_client):
    strict = ContextBuilder(Retriever.from_db(conn, fake_embedder, min_similarity=0.99), http_client)
    items, _, _, _ = build(strict, conn, [EVAL], "code_change")
    assert [i["kind"] for i in items] == ["cwe"]
    assert "Potential mitigations:" in items[0]["text"]


def test_sast_needs_no_online_lookups(builder, conn, apis):
    build(builder, conn, [EVAL], "code_change")
    assert apis.calls == []


# -- dependency upgrades -------------------------------------------------------------

def test_dependency_notes_cover_direct_transitive_major_and_stuck_upgrades(builder, conn):
    items, _, _, trace = build(builder, conn, [MARKED, MONGODB, QS, MINIMATCH], "version_upgrade")
    notes = text_of(items, "upgrade_notes")
    assert notes.startswith("Dependency upgrade notes (scanner targets, cross-checked with OSV.dev):")
    assert "- marked 0.3.5 → 0.3.6: fixes 1 finding(s) in marked. OSV.dev confirms 1 of these." in notes
    assert "- mongodb 2.2.36 → 3.1.13: MAJOR version change (2.x → 3.x); fixes 1 finding(s) in mongodb." in notes
    assert "CVE-" not in notes  # finding ids are in the references, not the prompt
    assert "- body-parser 1.18.3 → 1.20.4: fixes 1 finding(s) in qs." in notes
    assert "- forever 2.0.0 → 2.0.0: already at the target, so editing package.json cannot fix minimatch" in notes
    assert trace["dependency_groups"]["mongodb"] == {"installed": "2.2.36", "target": "3.1.13"}


def test_breaking_change_notes_go_to_the_references_not_the_prompt(builder, conn):
    # a major upgrade is held back for a person, so its notes are for that person, not for the LLM
    items, refs, _, trace = build(builder, conn, [MONGODB], "version_upgrade")
    assert not any(i["kind"] == "library_notes" for i in items)
    docs = [r for r in refs if r["type"] == "library_docs"]
    assert docs and all(r["source"] == "Context7" and r["package"] == "mongodb 2.x → 3.x" and r["description"] for r in docs)
    assert any("aggregate" in r["title"] for r in docs) and any(r["url"].endswith("CHANGES_3.0.0.md") for r in docs)
    assert trace["library_notes"][0] == {"package": "mongodb", "library": "/mongodb/node-mongodb-native",
                                         "snippets": len(docs), "in_prompt": False}


def test_breaking_change_notes_can_be_put_into_the_prompt_as_well(conn, fake_embedder, http_client):
    builder = ContextBuilder(Retriever.from_db(conn, fake_embedder, min_similarity=0.1), http_client,
                             library_notes_in_prompt=True)
    items, refs, _, trace = build(builder, conn, [MONGODB], "version_upgrade")
    notes = next(i for i in items if i["kind"] == "library_notes")
    assert notes["key"] == "/mongodb/node-mongodb-native"
    assert notes["text"].startswith("Breaking changes, mongodb 2.x → 3.x (from the library's own documentation via Context7):")
    assert "aggregate" in notes["text"] and len(notes["text"]) <= 800
    assert any(r["type"] == "library_docs" and r["url"].endswith("CHANGES_3.0.0.md") for r in refs)
    assert trace["library_notes"][0]["library"] == "/mongodb/node-mongodb-native"


def test_no_context7_lookup_without_a_major_upgrade(builder, conn, apis):
    build(builder, conn, [MARKED, QS], "version_upgrade")
    assert "context7.com" not in apis.hosts()


def test_osv_disagreement_is_reported(builder, conn):
    # OSV says CVE-2022-21681 is only fixed in marked 4.0.10, but this target is 0.3.6
    items, _, _, _ = build(builder, conn, [{**MARKED, "cve": "CVE-2022-21681"}], "version_upgrade")
    assert "OSV.dev disagrees: CVE-2022-21681 needs 4.0.10." in text_of(items, "upgrade_notes")


def test_already_at_target_is_explained(builder, conn):
    items, _, _, _ = build(builder, conn, [{**MARKED, "upgrade_to": "marked@0.3.5"}], "version_upgrade")
    assert "already at the target, so editing package.json cannot fix marked" in text_of(items, "upgrade_notes")


def test_advisories_beyond_the_target_are_flagged_in_references(builder, conn):
    _, refs, _, _ = build(builder, conn, [MARKED], "version_upgrade")
    advisories = {r["aliases"][0]: r for r in refs if r["type"] == "advisory" and r["aliases"]}
    assert advisories["CVE-2016-10531"]["beyond_target"] is False
    assert advisories["CVE-2022-21681"]["beyond_target"] is True
    assert advisories["CVE-2022-21681"]["fixed_in"] == "4.0.10"


def test_cves_are_enriched_from_nvd_and_linked_to_cwes(builder, conn):
    _, refs, _, trace = build(builder, conn, [MARKED], "version_upgrade")
    cve = next(r for r in refs if r["type"] == "cve")
    assert (cve["id"], cve["cvss"], cve["severity"], cve["cwes"], cve["kev"]) == ("CVE-2016-10531", 6.1, "MEDIUM", ["CWE-79"], False)
    assert any(r["type"] == "cwe" and r["id"] == "CWE-79" for r in refs)
    assert trace["cves"] == {"requested": 1, "found_in_nvd": 1, "known_exploited": []}


# -- containers and KEV ----------------------------------------------------------------

def test_container_summary_without_fix_data_falls_back_to_what_the_scanner_offers(builder, conn):
    # an older ASVA batch: no image name, and the scanner's "upgrade" is the installed version
    result = build_all(builder, conn, [GLIBC], "version_upgrade", exclude=["osv"])
    summary = text_of(result["items"], "container_summary")
    assert summary.startswith("Container image (Ubuntu 16.04): 1 CVE(s) in 1 OS package(s) (glibc).")
    assert "move the service to a newer, supported image tag" in summary
    assert "Ubuntu Pro" not in summary  # only a source may say where a fix is published
    assert next(r for r in result["refs"] if r["type"] == "cve")["cvss"] == 9.8


def test_known_exploited_cves_come_first(builder, conn):
    store.upsert_records(conn, kev.SOURCE, [{"key": "CVE-2022-23219", "kind": "kev", "title": "glibc buffer overflow",
                                             "text": "x", "url": "https://kev.test", "data": {"date_added": "2024-01-01",
                                                                                              "ransomware": "Unknown"}}])
    items, refs, _, _ = build(builder, conn, [GLIBC], "version_upgrade")
    assert items[0]["kind"] == "kev"
    assert items[0]["text"].startswith("Known exploited in the wild (CISA KEV), highest priority:\n- CVE-2022-23219")
    assert next(r for r in refs if r["type"] == "cve")["kev"] is True


# -- robustness -----------------------------------------------------------------------------

def test_offline_mode_makes_no_calls_and_still_gives_upgrade_notes(conn, fake_embedder, http_client, apis):
    offline = ContextBuilder(Retriever.from_db(conn, fake_embedder), http_client, online=False)
    items, _, warnings, _ = build(offline, conn, [MARKED, MONGODB], "version_upgrade")
    assert apis.calls == []
    assert "mongodb 2.2.36 → 3.1.13: MAJOR version change" in text_of(items, "upgrade_notes")
    assert any("online lookups are off" in w for w in warnings)


def test_nvd_outage_degrades_to_a_warning(builder, conn, apis):
    apis.fail["services.nvd.nist.gov"] = 99
    items, refs, warnings, _ = build(builder, conn, [MARKED], "version_upgrade")
    assert text_of(items, "upgrade_notes")
    assert any("NVD unavailable" in w for w in warnings)
    assert next(r for r in refs if r["type"] == "cve")["cvss"] is None


def test_prompt_items_respect_the_budget_but_references_do_not(builder, conn):
    items, refs, warnings, _ = build(builder, conn, [MARKED, MONGODB, QS, MINIMATCH], "version_upgrade", max_chars=600)
    assert sum(len(i["text"]) for i in items) <= 600
    assert len(refs) > 3


# -- container images: where the fix is published, and which line to move to --------------------

def container_finding(cve: str, package: str, fixed: str, rule: str = "SNYK-UBUNTU2004-X-1") -> dict:
    name = package.split("@")[0]
    return {"finding_type": "container", "cve": cve, "rule_id": rule, "package": package, "ecosystem": "deb",
            "upgrade_to": f"{name}@{fixed}", "fixable": True, "image_name": "mongo", "image_tag": "4.4",
            "title": f"vulnerability in {name}"}


PERL = container_finding("CVE-2026-8376", "perl@5.30.0-9ubuntu0.5", "5.30.0-9ubuntu0.5+esm2")
LIBTASN1 = container_finding("CVE-2021-46848", "libtasn1-6@4.16.0-2ubuntu0.1", "4.16.0-2ubuntu0.1+esm1")
GLIBC_FOCAL = container_finding("CVE-2022-23219", "glibc@2.31-0ubuntu9.2", "2.31-0ubuntu9.7")


def test_container_summary_quotes_the_distribution_on_subscription_only_fixes(builder, conn):
    result = build_all(builder, conn, [PERL, LIBTASN1], "version_upgrade")
    summary = text_of(result["items"], "container_summary")
    assert summary.startswith("Container image mongo:4.4 (Ubuntu 20.04): 2 CVE(s) in 2 OS package(s) (perl, libtasn1-6).")
    assert ('for Ubuntu 20.04, 2 of 2 checked fixes are published only as "Available with Ubuntu Pro (Infra-only): '
            'https://ubuntu.com/pro", not in the standard package repositories.') in summary
    assert result["trace"]["container"]["fix_data"]["subscription"] == 2


def test_container_summary_lists_supported_newer_lines_and_suggests_one(builder, conn):
    result = build_all(builder, conn, [PERL, LIBTASN1], "version_upgrade")
    summary = text_of(result["items"], "container_summary")
    assert ("Newer release lines of mongo (Docker Hub; support dates: endoflife.date; \"resolved\" = fixed in that "
            "base OS's standard packages, or not affected):") in summary
    assert "- mongo:7.0: 7.0.43 on Ubuntu 22.04, 2/2 checked CVEs resolved, supported until 2027-08-31" in summary
    assert "- mongo:8.0: 8.0.32 on Ubuntu 24.04, 2/2 checked CVEs resolved, supported until 2029-10-31" in summary
    assert "(past end of life, not listed: 5.0, 6.0)" in summary
    assert "- mongo:5.0" not in summary
    assert ("Compatible fix (same major version, 4.x): none. The lines that resolve these CVEs are new major versions "
            "of mongo: moving to one is a migration") in summary and "not a drop-in tag bump." in summary


def test_container_has_no_compatible_fix_and_names_the_nearest_supported_line_to_migrate_to(builder, conn):
    # 7.0, 8.0 and 9.0 all resolve both CVEs (libtasn1's is not listed for Ubuntu 24.04: not affected),
    # but each is a new major version: there is no compatible fix. 7.0 is the smallest supported step;
    # 8.0 is supported longest among established lines (9.0 was released two weeks before TODAY).
    result = build_all(builder, conn, [PERL, LIBTASN1], "version_upgrade")
    upgrade = result["upgrades"][0]
    assert (upgrade["kind"], upgrade["name"], upgrade["current"], upgrade["target"]) == ("image", "mongo", "4.4", "7.0")
    assert upgrade["compatible_target"] is None and upgrade["major_change"] is True
    assert upgrade["status"] == "newer_line_needed" and upgrade["note"].startswith("No compatible fix: no 4.x line of mongo")
    assert upgrade["ecosystem"] == "Ubuntu 20.04" and "latest" not in upgrade
    assert ("Migration target: mongo:7.0, the nearest supported line whose base OS resolves the checked CVEs; "
            "mongo:8.0 is supported longest (until 2029-10-31).") in text_of(result["items"], "container_summary")
    assert result["trace"]["container"]["compatible"] is None
    nine = next(c for c in upgrade["candidates"] if c["tag"] == "9.0")
    assert (nine["released"], nine["end_of_life"], nine["cves_resolved"], nine["cves_checked"]) == ("2026-09-30", False, 2, 2)


def test_container_migration_target_skips_a_line_whose_base_leaves_a_cve_open(builder, conn):
    # a CVE that Ubuntu 22.04 lists as affected with no fix yet: 7.0 (22.04) does not qualify, 8.0 (24.04) does
    store.upsert_records(conn, osv.SOURCE, [{
        "key": "distro:UBUNTU-CVE-2099-0001:zlib", "kind": "osv_distro", "title": "UBUNTU-CVE-2099-0001", "text": "x",
        "data": {"id": "UBUNTU-CVE-2099-0001", "url": "https://osv.test/UBUNTU-CVE-2099-0001", "releases": {
            "20.04": {"fixed": "1.2+esm1", "availability": "Available with Ubuntu Pro", "subscription_only": True},
            "22.04": {"fixed": None, "availability": None, "subscription_only": False},
            "24.04": {"fixed": "1.3", "availability": "No subscription required", "subscription_only": False}}}}])
    result = build_all(builder, conn, [container_finding("CVE-2099-0001", "zlib@1.2", "1.2+esm1")], "version_upgrade")
    assert result["upgrades"][0]["target"] == "8.0"
    seven = next(c for c in result["upgrades"][0]["candidates"] if c["tag"] == "7.0")
    assert (seven["cves_resolved"], seven["cves_checked"]) == (0, 1)


def test_container_fix_in_the_standard_repositories_means_a_rebuild_may_do(builder, conn):
    result = build_all(builder, conn, [GLIBC_FOCAL], "version_upgrade")
    assert result["upgrades"][0]["status"] == "rebuild_may_suffice"
    assert "publishes fixes for all 1 checked CVEs in its standard repositories" in text_of(result["items"], "container_summary")


def test_container_references_carry_the_fix_and_its_availability(builder, conn):
    refs = build_all(builder, conn, [PERL], "version_upgrade")["refs"]
    advisory = next(r for r in refs if r["type"] == "advisory")
    assert (advisory["id"], advisory["package"], advisory["fixed_in"]) == ("UBUNTU-CVE-2026-8376", "perl", "5.30.0-9ubuntu0.5+esm2")
    assert advisory["availability"] == "Available with Ubuntu Pro (Infra-only): https://ubuntu.com/pro"
    assert advisory["subscription_only"] is True
    assert {r["source"] for r in refs if r["type"] == "image"} == {"Docker Hub", "endoflife.date"}


def test_container_with_no_fix_for_this_release_names_the_newer_releases_that_have_one(builder, conn):
    store.upsert_records(conn, osv.SOURCE, [{
        "key": "distro:UBUNTU-CVE-2099-0002:zlib", "kind": "osv_distro", "title": "UBUNTU-CVE-2099-0002", "text": "x",
        "data": {"id": "UBUNTU-CVE-2099-0002", "url": "https://osv.test/UBUNTU-CVE-2099-0002", "releases": {
            "18.04": {"fixed": "1.0", "availability": None, "subscription_only": False},
            "20.04": {"fixed": None, "availability": None, "subscription_only": False},
            "22.04": {"fixed": "1.2+esm1", "availability": "Available with Ubuntu Pro", "subscription_only": True},
            "24.04": {"fixed": "1.3", "availability": "No subscription required", "subscription_only": False}}}}])
    refs = build_all(builder, conn, [container_finding("CVE-2099-0002", "zlib@1.2", None)], "version_upgrade")["refs"]
    found = next(r for r in refs if r["type"] == "os_release_fix")
    assert (found["package"], found["newer_release_fixes"]) == ("zlib", {"24.04": "1.3"})  # not older, not subscription-only
    assert (found["release_name"], found["newer_release_names"]) == ("focal", {"24.04": "noble"})
    assert not [r for r in refs if r["type"] == "advisory" and r["id"] == "UBUNTU-CVE-2099-0002"]


def test_container_without_docker_hub_lists_no_lines(builder, conn, apis):
    result = build_all(builder, conn, [PERL], "version_upgrade", exclude=["dockerhub"])
    assert "Newer release lines" not in text_of(result["items"], "container_summary")
    assert result["upgrades"][0]["target"] is None and result["upgrades"][0]["candidates"] is None
    assert "registry-1.docker.io" not in apis.hosts() and "endoflife.date" not in apis.hosts()


def test_container_without_support_dates_lists_lines_but_suggests_none(builder, conn, apis):
    result = build_all(builder, conn, [PERL], "version_upgrade", exclude=["endoflife"])
    summary = text_of(result["items"], "container_summary")
    assert "Newer release lines of mongo (Docker Hub; \"resolved\" = " in summary
    assert "- mongo:6.0: 6.0.28 on Ubuntu 22.04, 1/1 checked CVEs resolved" in summary
    assert "Migration target" not in summary and result["upgrades"][0]["target"] is None
    assert "support dates are unknown" in result["upgrades"][0]["note"]
    assert "Compatible fix (same major version, 4.x): none." in summary  # known without support dates
    assert "endoflife.date" not in apis.hosts()


def test_container_suggestion_without_fix_data_says_what_it_is_based_on(builder, conn):
    result = build_all(builder, conn, [PERL], "version_upgrade", exclude=["osv"])
    summary = text_of(result["items"], "container_summary")
    assert ("Migration target: mongo:7.0, the nearest supported line on a newer base OS than this image; "
            "mongo:8.0 is supported longest (until 2029-10-31).") in summary
    assert "Compatible fix (same major version, 4.x): none. The newer lines are new major versions of mongo" in summary
    assert "resolved" not in summary and "Ubuntu Pro" not in summary
    assert "The scanner lists fixed package versions" in summary


def test_container_image_lines_are_cached(builder, conn, apis):
    build_all(builder, conn, [PERL], "version_upgrade")
    looked_up = {"auth.docker.io", "registry-1.docker.io", "endoflife.date", "api.osv.dev"}
    calls = [host for host in apis.hosts() if host in looked_up]
    build_all(builder, conn, [PERL], "version_upgrade")
    assert [host for host in apis.hosts() if host in looked_up] == calls and calls


# -- upgrade data ----------------------------------------------------------------------------------

def test_upgrades_give_current_target_smallest_fix_and_latest_per_package(builder, conn):
    upgrades = {u["name"]: u for u in build_all(builder, conn, [MARKED, MONGODB, QS, MINIMATCH], "version_upgrade")["upgrades"]}
    assert (upgrades["marked"]["current"], upgrades["marked"]["target"], upgrades["marked"]["min_fixed"]) == ("0.3.5", "0.3.6", "0.3.6")
    assert upgrades["marked"]["status"] == "ok" and upgrades["marked"]["fixes"] == ["CVE-2016-10531"]
    assert upgrades["mongodb"]["status"] == "major_change" and upgrades["mongodb"]["major_change"] is True
    assert "latest" not in upgrades["mongodb"]  # the newest published version is not part of an answer
    assert upgrades["body-parser"]["target"] == "1.20.4" and upgrades["body-parser"]["min_fixed"] is None  # transitive fix
    assert upgrades["forever"]["status"] == "already_at_target" and "lockfile refresh" in upgrades["forever"]["note"]


def test_upgrade_status_reports_an_osv_disagreement(builder, conn):
    upgrade = build_all(builder, conn, [{**MARKED, "cve": "CVE-2022-21681"}], "version_upgrade")["upgrades"][0]
    assert upgrade["status"] == "osv_disagrees" and upgrade["min_fixed"] == "4.0.10"
    assert upgrade["note"] == "OSV.dev: CVE-2022-21681 needs 4.0.10."


def test_a_finding_without_a_scanner_target_gets_a_no_target_upgrade(builder, conn):
    upgrade = build_all(builder, conn, [{**MARKED, "upgrade_to": None}], "version_upgrade")["upgrades"][0]
    assert (upgrade["status"], upgrade["target"], upgrade["min_fixed"]) == ("no_target", None, "0.3.6")


# -- CWE: resolved for every finding type, explained in the references -----------------------------

def test_scanner_rule_tags_give_dependency_findings_their_cwes(builder, conn):
    result = build_all(builder, conn, [{**QS, "cve": None, "cwes": ["CWE-94", "cwe-601", "not-a-cwe"]}], "version_upgrade")
    assert [r["id"] for r in result["refs"] if r["type"] == "cwe"] == ["CWE-94", "CWE-601"]
    assert result["trace"]["resolved_cwes"] == ["CWE-94", "CWE-601"]


def test_osv_advisories_supply_cwes_for_the_findings_they_match(builder, conn):
    # marked's CVE-2017-16114 is not in the NVD fixtures; OSV's matching advisory names CWE-400
    result = build_all(builder, conn, [{**MARKED, "cve": "CVE-2017-16114", "upgrade_to": "marked@0.3.9"}], "version_upgrade")
    assert "CWE-400" in result["trace"]["resolved_cwes"]


def test_cwe_references_carry_the_definition_and_mitigations(builder, conn):
    refs = build_all(builder, conn, [EVAL], "code_change")["refs"]
    cwe = next(r for r in refs if r["type"] == "cwe")
    assert cwe["description"] and len(cwe["description"]) <= 400
    assert 1 <= len(cwe["mitigations"]) <= 3 and cwe["mitigations"][0].startswith("[Implementation")


def test_cwe_reference_marks_mitigations_inherited_from_a_parent(builder, conn):
    refs = build_all(builder, conn, [{**EVAL, "cwe": "CWE-95"}], "code_change")["refs"]
    cwe = next(r for r in refs if r["type"] == "cwe" and r["id"] == "CWE-95")
    assert cwe["mitigations"] and all(m.endswith("(from parent CWE-94)") for m in cwe["mitigations"])


# -- answering without a source (how results with and without it are compared) ---------------------

def test_without_nvd_cves_are_listed_but_not_enriched(builder, conn, apis):
    result = build_all(builder, conn, [MARKED], "version_upgrade", exclude=["nvd"])
    cve = next(r for r in result["refs"] if r["type"] == "cve")
    assert (cve["id"], cve["cvss"], cve["cwes"], cve["source"]) == ("CVE-2016-10531", None, None, "scanner findings")
    assert "services.nvd.nist.gov" not in apis.hosts()


def test_without_nvd_cached_cve_links_are_not_used_either(builder, conn):
    build_all(builder, conn, [MARKED], "version_upgrade")  # caches CVE-2016-10531 -> CWE-79
    result = build_all(builder, conn, [MARKED], "version_upgrade", exclude=["nvd", "osv"])
    assert result["trace"]["resolved_cwes"] == []


def test_without_osv_there_is_no_cross_check(builder, conn, apis):
    result = build_all(builder, conn, [MARKED], "version_upgrade", exclude=["osv"])
    notes = text_of(result["items"], "upgrade_notes")
    assert notes.startswith("Dependency upgrade notes (scanner targets):") and "OSV.dev" not in notes
    assert result["upgrades"][0]["min_fixed"] is None
    assert not any(r["type"] == "advisory" for r in result["refs"]) and "api.osv.dev" not in apis.hosts()


def test_without_context7_a_major_upgrade_has_no_library_notes(builder, conn, apis):
    result = build_all(builder, conn, [MONGODB], "version_upgrade", exclude=["context7"])
    assert not any(r["type"] == "library_docs" for r in result["refs"]) and "context7.com" not in apis.hosts()
    assert "MAJOR version change" in text_of(result["items"], "upgrade_notes")


def test_the_package_registry_is_only_asked_when_context7_needs_a_library(builder, conn, apis):
    build_all(builder, conn, [MARKED], "version_upgrade")                      # no major upgrade: no library lookup
    assert "registry.npmjs.org" not in apis.hosts()
    build_all(builder, conn, [MONGODB], "version_upgrade", exclude=["context7"])
    assert "registry.npmjs.org" not in apis.hosts()
    result = build_all(builder, conn, [MONGODB], "version_upgrade")           # major upgrade: once, for the repository address
    assert apis.hosts().count("registry.npmjs.org") == 1
    assert any(r["type"] == "library_docs" for r in result["refs"])


def test_without_cwe_there_are_no_cwe_references_and_the_query_has_no_cwe_name(builder, conn):
    result = build_all(builder, conn, [EVAL], "code_change", exclude=["cwe"])
    assert not any(r["type"] == "cwe" for r in result["refs"])
    assert "Improper Control of Generation of Code" not in result["trace"]["queries"][0]["text"]
    assert "Improper Control of Generation of Code" in build_all(builder, conn, [EVAL], "code_change")["trace"]["queries"][0]["text"]


def test_without_owasp_code_fixes_fall_back_to_the_cwe_entry(builder, conn):
    result = build_all(builder, conn, [EVAL], "code_change", exclude=["owasp"])
    assert [i["kind"] for i in result["items"]] == ["cwe"]
    assert result["trace"]["guidance_search"] == "skipped (source excluded)"


def test_without_kev_a_known_exploited_cve_is_not_flagged(builder, conn):
    store.upsert_records(conn, kev.SOURCE, [{"key": "CVE-2016-10531", "kind": "kev", "title": "x", "text": "x",
                                             "url": "https://kev.test", "data": {"date_added": "2024-01-01"}}])
    assert build_all(builder, conn, [MARKED], "version_upgrade")["items"][0]["kind"] == "kev"
    result = build_all(builder, conn, [MARKED], "version_upgrade", exclude=["kev"])
    assert not any(i["kind"] == "kev" for i in result["items"])
    assert next(r for r in result["refs"] if r["type"] == "cve")["kev"] is False


def test_sources_switched_off_in_the_configuration_apply_to_every_request(builder, conn, monkeypatch):
    monkeypatch.setattr(config, "DISABLED_SOURCES", frozenset({"osv"}))
    result = build_all(builder, conn, [MARKED], "version_upgrade")
    assert "OSV.dev" not in text_of(result["items"], "upgrade_notes")
    assert result["trace"]["excluded_sources"] == ["osv"]


# -- the compatible fix: a version that resolves the finding without a major version change ----

def test_a_same_major_target_is_the_compatible_fix(builder, conn):
    upgrades = {u["name"]: u for u in build_all(builder, conn, [MARKED, QS], "version_upgrade")["upgrades"]}
    assert upgrades["marked"]["compatible_target"] == "0.3.6"
    assert upgrades["body-parser"]["compatible_target"] == "1.20.4"


def test_a_major_upgrade_with_no_fix_in_the_installed_major_has_no_compatible_fix(builder, conn):
    result = build_all(builder, conn, [MONGODB], "version_upgrade")
    upgrade = result["upgrades"][0]
    assert (upgrade["target"], upgrade["compatible_target"], upgrade["status"]) == ("3.1.13", None, "major_change")
    assert upgrade["note"].startswith("No compatible fix: OSV.dev lists no fix within 2.x (first fixed in 3.1.13).")
    notes = text_of(result["items"], "upgrade_notes")
    assert "OSV.dev lists no fix within 2.x (first fixed in 3.1.13), so no compatible version bump resolves this." in notes


def seed_advisories(conn, package: str, advisories: list[dict]) -> None:
    store.upsert_records(conn, osv.SOURCE, [{"key": f"npm:{package}", "kind": "osv_package", "title": package,
                                             "text": "x", "data": advisories}])


def advisory(fixed_versions: list[str], alias: str = "CVE-2099-1") -> dict:
    return {"id": "GHSA-x", "aliases": [alias], "summary": "s", "severity": "HIGH", "cwes": [], "url": "https://osv.test/x",
            "fixed": fixed_versions[0] if fixed_versions else None, "fixed_versions": fixed_versions}


def major_finding(**overrides) -> dict:
    return {"finding_type": "sca", "cve": "CVE-2099-1", "package": "widget@1.2.0", "ecosystem": "npm",
            "upgrade_to": "widget@2.0.0", "dependency_path": ["app@1.0.0", "widget@1.2.0"], "title": "t", **overrides}


def test_a_fix_within_the_installed_major_is_offered_instead_of_the_major_upgrade(builder, conn):
    # the vulnerability is fixed in both maintained lines; the scanner points at the newer one
    seed_advisories(conn, "widget@1.2.0", [advisory(["1.2.5", "2.0.0"])])
    result = build_all(builder, conn, [major_finding()], "version_upgrade")
    upgrade = result["upgrades"][0]
    assert (upgrade["target"], upgrade["compatible_target"], upgrade["major_change"]) == ("2.0.0", "1.2.5", True)
    assert "OSV.dev lists a fix within 1.x: widget 1.2.5, a compatible alternative." in text_of(result["items"], "upgrade_notes")


def test_a_partial_compatible_fix_when_only_some_advisories_are_fixed_within_the_major(builder, conn):
    seed_advisories(conn, "widget@1.2.0", [advisory(["1.2.5", "2.0.0"]), {**advisory(["2.0.0"], alias="CVE-2099-2"), "id": "GHSA-y"}])
    result = build_all(builder, conn, [major_finding()], "version_upgrade")
    upgrade = result["upgrades"][0]
    assert (upgrade["compatible_target"], upgrade["compatible_scope"], upgrade["major_change"]) == ("1.2.5", "partial", True)
    assert "resolves 1 of the 2 vulnerabilities" in upgrade["note"] and "No fix within 1.x for CVE-2099-2 (first fixed in 2.0.0)" in upgrade["note"]
    assert ("OSV.dev lists a fix within 1.x for 1 of its 2 vulnerabilities in widget 1.2.0: widget 1.2.5 resolves those without a major version change"
            in text_of(result["items"], "upgrade_notes"))


def test_no_compatible_fix_when_no_advisory_is_fixed_within_the_major(builder, conn):
    seed_advisories(conn, "widget@1.2.0", [advisory(["2.0.0"]), {**advisory(["2.1.0"], alias="CVE-2099-2"), "id": "GHSA-y"}])
    upgrade = build_all(builder, conn, [major_finding()], "version_upgrade")["upgrades"][0]
    assert (upgrade["compatible_target"], upgrade["compatible_scope"]) == (None, None) and "fixed in 2.0.0 to 2.1.0" in upgrade["note"]


def test_four_part_versions_are_told_apart(builder, conn):
    rack = {"finding_type": "sca", "cve": "CVE-2022-30122", "package": "rack@2.2.3", "ecosystem": "rubygems",
            "upgrade_to": "rack@2.2.3.1", "title": "Denial of Service"}
    upgrade = build_all(builder, conn, [rack], "version_upgrade")["upgrades"][0]
    assert (upgrade["status"], upgrade["compatible_target"]) == ("ok", "2.2.3.1")   # not "already at the target"


def test_no_compatible_fix_is_claimed_when_the_upgrade_also_pulls_in_fixed_transitive_packages(builder, conn):
    seed_advisories(conn, "widget@1.2.0", [advisory(["1.2.5", "2.0.0"])])
    transitive = major_finding(cve="CVE-2099-9", package="gear@0.1.0", dependency_path=["app@1.0.0", "widget@1.2.0", "gear@0.1.0"])
    upgrade = build_all(builder, conn, [major_finding(), transitive], "version_upgrade")["upgrades"][0]
    assert upgrade["compatible_target"] is None  # 1.2.5 fixes widget's own advisory, but nothing says it fixes gear


def test_without_osv_a_major_upgrade_has_no_known_compatible_fix(builder, conn):
    upgrade = build_all(builder, conn, [MONGODB], "version_upgrade", exclude=["osv"])["upgrades"][0]
    assert upgrade["compatible_target"] is None and upgrade["note"].startswith("No compatible fix is known")


# -- other ecosystems ---------------------------------------------------------------------------------

def test_already_at_target_names_the_ecosystem_s_own_dependency_file(builder, conn):
    pinned = {**MINIMATCH, "ecosystem": "pip"}
    notes = build_all(builder, conn, [pinned], "version_upgrade")["items"][0]["text"]
    assert "so editing requirements.txt cannot fix minimatch; it needs its own pinned line or a constraints file" in notes
    unknown = build_all(builder, conn, [{**MINIMATCH, "ecosystem": "hex"}], "version_upgrade")["items"][0]["text"]
    assert "so editing the dependency file cannot fix minimatch" in unknown


def test_a_calendar_versioned_package_is_not_held_back_as_a_major_change(builder, conn):
    certifi = {"finding_type": "sca", "cve": "CVE-2023-37920", "package": "certifi@2022.12.7", "ecosystem": "pip",
               "upgrade_to": "certifi@2023.7.22", "title": "Improper Following of a Certificate's Chain of Trust"}
    upgrade = build_all(builder, conn, [certifi], "version_upgrade")["upgrades"][0]
    assert (upgrade["major_change"], upgrade["status"], upgrade["compatible_target"]) == (False, "ok", "2023.7.22")


# -- container images: other situations than NodeGoat's ------------------------------------------------

def test_container_summary_says_when_the_current_line_is_past_end_of_life(builder, conn):
    summary = text_of(build_all(builder, conn, [PERL], "version_upgrade")["items"], "container_summary")
    assert "mongo 4.4 is past end of life since 2024-02-29 (endoflife.date)." in summary
    without = text_of(build_all(builder, conn, [PERL], "version_upgrade", exclude=["endoflife"])["items"], "container_summary")
    assert "past end of life" not in without


def test_a_maintained_line_whose_os_publishes_the_fixes_needs_no_tag_change(builder, conn):
    # mongo:7.0 is still supported; the fix for this CVE is in the OS release's standard packages
    result = build_all(builder, conn, [{**GLIBC_FOCAL, "image_tag": "7.0"}], "version_upgrade")
    summary, upgrade = text_of(result["items"], "container_summary"), result["upgrades"][0]
    assert "No tag change is needed for these CVEs: re-pull or rebuild mongo:7.0" in summary
    assert "Migration target" not in summary and "Compatible fix" not in summary and "Newer release lines" not in summary
    assert (upgrade["status"], upgrade["target"], upgrade["compatible_target"]) == ("rebuild_may_suffice", None, None)
    assert upgrade["note"].startswith("No tag change needed")


def test_a_cve_without_a_fix_in_the_os_release_needs_a_newer_line(builder, conn, monkeypatch):
    unfixed = {"id": "UBUNTU-CVE-2099-1", "url": "u", "releases": {
        "20.04": {"fixed": None, "subscription_only": False, "availability": None},
        "22.04": {"fixed": "2", "subscription_only": False, "availability": None}}}
    monkeypatch.setattr(osv, "distro_fixes", lambda *args, **kwargs: unfixed)
    result = build_all(builder, conn, [container_finding("CVE-2099-1", "zlib@1.2", "1.2")], "version_upgrade")
    assert result["upgrades"][0]["status"] == "newer_line_needed"
    assert "0 of 1 checked CVEs have a fix in the standard repositories; 1 have no fix yet." in text_of(result["items"], "container_summary")


def test_by_default_the_image_lines_and_migration_target_are_data_not_prompt_text(conn, fake_embedder, http_client):
    default = ContextBuilder(Retriever.from_db(conn, fake_embedder, min_similarity=0.1), http_client, today=lambda: TODAY)
    result = build_all(default, conn, [PERL], "version_upgrade")
    summary, upgrade = text_of(result["items"], "container_summary"), result["upgrades"][0]
    assert "Compatible fix (same major version, 4.x): none." in summary and "not a drop-in tag bump" in summary
    assert "Newer release lines" not in summary and "Migration target" not in summary
    assert upgrade["target"] == "7.0" and [c["tag"] for c in upgrade["candidates"]] == ["5.0", "6.0", "7.0", "8.0", "9.0"]
    assert "Migration target: mongo:7.0." in upgrade["note"]


def test_two_osv_records_of_one_vulnerability_are_counted_once(builder, conn):
    # PyPI vulnerabilities have a GHSA record and a PYSEC record that share the CVE alias
    ghsa, pysec = advisory(["1.2.5", "2.0.0"]), {**advisory(["2.0.0"]), "id": "PYSEC-x"}
    seed_advisories(conn, "widget@1.2.0", [ghsa, pysec])
    result = build_all(builder, conn, [major_finding()], "version_upgrade")
    assert result["upgrades"][0]["compatible_scope"] == "all" and result["upgrades"][0]["compatible_target"] == "1.2.5"
    assert "OSV.dev confirms 1 of these." in text_of(result["items"], "upgrade_notes")


def test_a_known_exploited_cve_whose_fix_is_held_back_is_flagged_for_the_pr(builder, conn, monkeypatch):
    seed_advisories(conn, "widget@1.2.0", [advisory(["2.0.0"])])
    monkeypatch.setattr(kev, "lookup", lambda conn, ids: {"CVE-2099-1": {"name": "Widget RCE", "date_added": "2099-01-01"}})
    result = build_all(builder, conn, [major_finding()], "version_upgrade")
    upgrade = result["upgrades"][0]
    assert upgrade["compatible_target"] is None
    assert upgrade["note"].endswith("CVE-2099-1 is known to be exploited (CISA KEV) and is not fixed by a compatible bump: "
                                    "plan this migration urgently.")


@pytest.mark.parametrize("distro, release, name", [("debian", "13", "trixie"), ("Ubuntu", "24.04", "noble"), ("alpine", "3.20", "alpine3.20"),
                                                   ("debian", "99", None), ("rhel", "9", None), (None, "9", None), ("alpine", None, None)])
def test_release_names_as_used_in_image_tags(distro, release, name):
    assert images.release_name(distro, release) == name

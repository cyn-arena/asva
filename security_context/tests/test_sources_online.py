"""NVD, CISA KEV, OSV.dev and Context7, against trimmed real responses (tests/fixtures)."""

from datetime import timedelta

import httpx
import pytest

from app import net, store
from app.sources import context7, kev, nvd, osv
from conftest import FIXTURES, fixture_json

# -- NVD --------------------------------------------------------------------------


def test_nvd_parse_prefers_nvd_primary_cvss_v3_and_collects_cwes():
    record, links = nvd.parse_cve(fixture_json("nvd_cve_2022_23219.json")["vulnerabilities"][0]["cve"])
    data = record["data"]
    assert record["key"] == "CVE-2022-23219"
    assert (data["cvss"], data["severity"], data["cvss_version"]) == (9.8, "CRITICAL", "3.1")
    assert data["cwes"] == ["CWE-120"]
    assert links == [("CVE-2022-23219", "has_cwe", "CWE-120")]
    assert record["text"].startswith("CVE-2022-23219 (CVSS 9.8 CRITICAL, CWE-120): ")
    assert record["url"] == "https://nvd.nist.gov/vuln/detail/CVE-2022-23219"


def test_nvd_parse_falls_back_to_cvss_v30():
    record, _ = nvd.parse_cve(fixture_json("nvd_cve_2016_10531.json")["vulnerabilities"][0]["cve"])
    assert (record["data"]["cvss"], record["data"]["cvss_version"]) == (6.1, "3.0")


def test_nvd_parse_ignores_placeholder_cwes():
    cve = {"id": "CVE-1", "descriptions": [{"lang": "en", "value": "x"}], "metrics": {},
           "weaknesses": [{"type": "Primary", "description": [{"value": "NVD-CWE-noinfo"}, {"value": "CWE-20"}]}]}
    record, links = nvd.parse_cve(cve)
    assert record["data"]["cwes"] == ["CWE-20"] and record["data"]["cvss"] is None
    assert "no CVSS score" in record["text"]


def test_nvd_lookup_fetches_once_then_uses_the_cache(conn, http_client, apis):
    first = nvd.lookup(conn, http_client, ["CVE-2016-10531"], [])
    second = nvd.lookup(conn, http_client, ["cve-2016-10531"], [])
    assert first["CVE-2016-10531"]["cvss"] == 6.1 and second["CVE-2016-10531"]["cwes"] == ["CWE-79"]
    assert apis.hosts().count("services.nvd.nist.gov") == 1
    assert store.linked(conn, "CVE-2016-10531", "has_cwe") == ["CWE-79"]


def test_nvd_lookup_refetches_stale_entries(conn, http_client, apis):
    nvd.lookup(conn, http_client, ["CVE-2016-10531"], [])
    nvd.lookup(conn, http_client, ["CVE-2016-10531"], [], max_age=timedelta(0))
    assert apis.hosts().count("services.nvd.nist.gov") == 2


def test_nvd_lookup_retries_through_503s(conn, http_client, apis):
    apis.fail["services.nvd.nist.gov"] = 2
    warnings = []
    assert "CVE-2016-10531" in nvd.lookup(conn, http_client, ["CVE-2016-10531"], warnings)
    assert warnings == []
    assert apis.hosts().count("services.nvd.nist.gov") == 3


def test_nvd_outage_is_a_warning_and_cached_data_is_kept(conn, http_client, apis):
    nvd.lookup(conn, http_client, ["CVE-2016-10531"], [])
    apis.fail["services.nvd.nist.gov"] = 99
    warnings = []
    result = nvd.lookup(conn, http_client, ["CVE-2016-10531"], warnings, max_age=timedelta(0))
    assert result["CVE-2016-10531"]["cvss"] == 6.1
    assert any("NVD unavailable for 1 CVE(s)" in w for w in warnings)


def test_nvd_unknown_cve_is_simply_absent(conn, http_client):
    assert nvd.lookup(conn, http_client, ["CVE-1999-0000"], []) == {}


def test_nvd_offline_mode_never_calls_out(conn, http_client, apis):
    warnings = []
    assert nvd.lookup(conn, http_client, ["CVE-2016-10531"], warnings, online=False) == {}
    assert apis.calls == [] and any("online lookups are off" in w for w in warnings)


def test_nvd_full_sync_pages_and_records_progress(conn, monkeypatch):
    pages = {0: ["CVE-1", "CVE-2"], 2: ["CVE-3"]}

    def handler(request):
        start = int(request.url.params["startIndex"])
        cves = [{"cve": {"id": c, "descriptions": [{"lang": "en", "value": c}], "metrics": {}, "weaknesses": []}}
                for c in pages.get(start, [])]
        return httpx.Response(200, json={"totalResults": 3, "vulnerabilities": cves})

    monkeypatch.setattr(nvd, "PAGE_SIZE", 2)
    with net.make_client(transport=httpx.MockTransport(handler)) as client:
        message = nvd.sync(conn, client, mode="full")
    assert "full download complete (3 CVEs" in message
    assert store.get_sync_state(conn, nvd.SOURCE)["version"] == "full"


def test_nvd_incremental_sync_asks_only_for_recent_changes(conn):
    store.set_sync_state(conn, nvd.SOURCE, "full", 0, synced_at=store.now_iso())
    seen = []

    def handler(request):
        seen.append(dict(request.url.params))
        return httpx.Response(200, json={"totalResults": 0, "vulnerabilities": []})

    with net.make_client(transport=httpx.MockTransport(handler)) as client:
        message = nvd.sync(conn, client, mode="full")
    assert "incremental update" in message
    assert len(seen) == 1 and "lastModStartDate" in seen[0] and seen[0]["lastModEndDate"].endswith("+00:00")


# -- CISA KEV ------------------------------------------------------------------------


def test_kev_sync_then_lookup(conn, http_client):
    message = kev.sync(conn, http_client)
    sample = fixture_json("kev_sample.json")["vulnerabilities"][0]
    hit = kev.lookup(conn, [sample["cveID"].lower(), "CVE-2016-10531"])
    assert "2 known-exploited CVEs" in message
    assert list(hit) == [sample["cveID"]]
    assert hit[sample["cveID"]]["date_added"] == sample["dateAdded"]
    assert "unchanged" in kev.sync(conn, http_client)


# -- OSV.dev ---------------------------------------------------------------------------


def test_osv_lists_advisories_with_the_smallest_fixed_version(conn, http_client):
    advisories = osv.advisories(conn, http_client, "marked", "0.3.5", "npm", [])
    by_cve = {a["aliases"][0]: a for a in advisories if a["aliases"]}
    assert by_cve["CVE-2016-10531"]["fixed"] == "0.3.6"
    assert by_cve["CVE-2022-21681"]["fixed"] == "4.0.10"
    assert all(a["url"].startswith("https://osv.dev/vulnerability/") for a in advisories)


def test_osv_advisory_without_cve_is_kept(conn, http_client):
    advisories = osv.advisories(conn, http_client, "mongodb", "2.2.36", "npm", [])
    assert [(a["id"], a["aliases"], a["fixed"]) for a in advisories] == [("GHSA-mh5c-679w-hh4r", [], "3.1.13")]


def test_osv_is_cached(conn, http_client, apis):
    osv.advisories(conn, http_client, "marked", "0.3.5", "npm", [])
    osv.advisories(conn, http_client, "marked", "0.3.5", "npm", [])
    assert apis.hosts().count("api.osv.dev") == 1


def test_osv_outage_is_a_warning(conn, http_client, apis):
    apis.fail["api.osv.dev"] = 99
    warnings = []
    assert osv.advisories(conn, http_client, "marked", "0.3.5", "npm", warnings) is None
    assert any("OSV.dev unavailable" in w for w in warnings)


@pytest.mark.parametrize("ecosystem, expected", [("npm", "npm"), ("pip", "PyPI"), ("maven", "Maven"), ("deb", None), (None, None)])
def test_osv_ecosystem_names(ecosystem, expected):
    assert osv.osv_ecosystem(ecosystem) == expected


# -- Context7 ----------------------------------------------------------------------------


def test_context7_snippets_are_parsed_and_deduplicated():
    snippets = context7.parse_snippets((FIXTURES / "context7_context_mongodb.txt").read_text(encoding="utf-8"))
    assert snippets[0]["title"].startswith("Collection.prototype.aggregate")
    assert snippets[0]["source"].endswith("CHANGES_3.0.0.md")
    assert "Pipeline stages must now be provided as an Array" in snippets[0]["description"]
    assert len({s["title"].lower() for s in snippets}) == len(snippets)


def test_context7_keeps_only_notes_for_versions_in_the_upgrade_range():
    snippets = [{"title": t, "source": f"https://github.com/x/y/blob/main/etc/notes/{f}", "description": "d"}
                for t, f in [("a", "CHANGES_3.0.0.md"), ("b", "CHANGES_7.0.0.md"), ("c", "README.md"), ("d", "CHANGES_2.0.0.md")]]
    assert [s["title"] for s in context7.in_range(snippets, "2.2.36", "3.1.13")] == ["a", "c"]
    assert context7.in_range(snippets, "0.3.5", "0.4.0") == snippets  # same major: nothing to filter by


def test_context7_resolves_npm_packages_through_their_github_repo(conn, http_client, apis):
    notes = context7.upgrade_notes(conn, http_client, "mongodb", "npm", "2.2.36", "3.1.13", [])
    assert notes["library_id"] == "/mongodb/node-mongodb-native"
    assert notes["query"] == "breaking changes when upgrading from 2.x to 3.x"
    assert notes["snippets"]
    context_call = next(c for c in apis.calls if c.url.path.endswith("/context"))
    assert context_call.url.params["libraryId"] == "/mongodb/node-mongodb-native"
    assert context_call.headers["Authorization"] == "Bearer test-context7-key"


def test_context7_falls_back_to_search_when_npm_has_no_repo(conn, http_client):
    notes = context7.upgrade_notes(conn, http_client, "left-pad", "npm", "1.0.0", "2.0.0", [])
    assert notes["library_id"] == fixture_json("context7_search_mongodb.json")["results"][0]["id"]


def test_context7_is_cached(conn, http_client, apis):
    context7.upgrade_notes(conn, http_client, "mongodb", "npm", "2.2.36", "3.1.13", [])
    context7.upgrade_notes(conn, http_client, "mongodb", "npm", "2.2.36", "3.1.13", [])
    assert apis.hosts().count("context7.com") == 1


def test_context7_without_api_key_is_skipped(conn, http_client, apis, monkeypatch):
    monkeypatch.setattr(context7.config, "CONTEXT7_API_KEY", "")
    assert context7.upgrade_notes(conn, http_client, "mongodb", "npm", "2.2.36", "3.1.13", []) is None
    assert apis.calls == []

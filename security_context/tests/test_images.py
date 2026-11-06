"""Container images: Docker Hub lines, endoflife.date support dates, OSV.dev's per-release fix
data, and the rule that picks the line to suggest. Trimmed real API answers
(tests/fixtures) served by conftest.FakeAPIs."""

from datetime import date, timedelta

import pytest

from app import images
from app.sources import lifecycle, osv, registry
from conftest import fixture_json

TODAY = date(2026, 10, 13)

# -- Docker Hub ---------------------------------------------------------------------------------


@pytest.mark.parametrize("image, repository", [
    ("mongo", "library/mongo"), ("bitnami/mongodb", "bitnami/mongodb"),
    ("ghcr.io/acme/app", None), ("localhost:5000/app", None), ("", None)])
def test_repository_of_knows_docker_hub_images_from_other_registries(image, repository):
    assert registry.repository_of(image) == repository


@pytest.mark.parametrize("tag, line", [("4.4", (4, 4)), ("4.4.30-focal", (4, 4)), ("v8.0", (8, 0)), ("16", (16,)), ("16-alpine", (16,)),
                                       ("3.11-slim-bookworm", (3, 11)), ("latest", None), (None, None)])
def test_line_of_reads_the_release_line_from_a_tag(tag, line):
    assert registry.line_of(tag) == line


def test_newer_lines_keeps_release_line_tags_above_the_current_one():
    tags = ["latest", "4", "4.4", "4.4.30", "5.0", "5.0-focal", "10.0", "9.0", "3.6"]
    assert registry.newer_lines(tags, "4.4") == ["5.0", "9.0", "10.0"]


def test_describe_reads_version_and_base_os_from_the_image_config():
    configs = fixture_json("dockerhub_mongo.json")["configs"]
    assert registry.describe("4.4", configs["4.4"]) == {
        "tag": "4.4", "line": "4.4", "version": "4.4.30", "base_distro": "ubuntu", "base_release": "20.04", "built": "2025-12-29"}
    # newer Ubuntu base images carry only the release label; the distribution shows in the build history
    assert registry.describe("8.0", configs["8.0"])["base_distro"] == "ubuntu"
    assert registry.describe("8.0", configs["8.0"])["base_release"] == "24.04"


def test_image_lines_lists_newer_lines_and_caches_them(conn, http_client, apis):
    lines = registry.image_lines(conn, http_client, "mongo", "4.4", [])
    assert lines["current"]["version"] == "4.4.30"
    assert [(l["tag"], l["version"], l["base_release"]) for l in lines["newer"]] == [
        ("5.0", "5.0.33", "20.04"), ("6.0", "6.0.28", "22.04"), ("7.0", "7.0.43", "22.04"),
        ("8.0", "8.0.32", "24.04"), ("9.0", "9.0.2", "24.04")]
    calls = len(apis.calls)
    assert registry.image_lines(conn, http_client, "mongo", "4.4", []) == lines
    assert len(apis.calls) == calls


def test_image_lines_skips_what_it_cannot_look_up(conn, http_client, apis):
    assert registry.image_lines(conn, http_client, "ghcr.io/acme/app", "1.0", []) is None  # not on Docker Hub
    assert registry.image_lines(conn, http_client, "mongo", "latest", []) is None          # no release line
    assert apis.calls == []


def test_image_lines_outage_is_a_warning(conn, http_client, apis):
    apis.fail["auth.docker.io"] = 99
    warnings = []
    assert registry.image_lines(conn, http_client, "mongo", "4.4", warnings) is None
    assert any("Docker Hub unavailable for mongo" in w for w in warnings)


def test_image_lines_offline_answers_from_the_cache_only(conn, http_client, apis):
    assert registry.image_lines(conn, http_client, "mongo", "4.4", [], online=False) is None
    assert apis.calls == []


# -- endoflife.date -------------------------------------------------------------------------------

def test_product_of_maps_image_names_to_product_names():
    assert lifecycle.product_of("mongo") == "mongodb" and lifecycle.product_of("bitnami/postgres") == "postgresql"
    assert lifecycle.product_of("redis") == "redis"


def test_cycles_gives_release_and_end_of_life_per_line(conn, http_client, apis):
    cycles = lifecycle.cycles(conn, http_client, "mongo", [])
    assert cycles["8.0"] == {"released": "2024-10-31", "eol": "2029-10-31", "latest": "8.0.32"}
    lifecycle.cycles(conn, http_client, "mongo", [])
    assert apis.hosts().count("endoflife.date") == 1


def test_cycles_unknown_product_is_empty(conn, http_client):
    assert lifecycle.cycles(conn, http_client, "some-internal-image", []) == {}


# -- OSV.dev: where a distribution publishes an OS package fix -------------------------------------

def test_parse_distro_fixes_separates_standard_from_subscription_only():
    releases = osv.parse_distro_fixes(fixture_json("osv_ubuntu_cve_2026_8376.json"), "perl")
    assert releases["20.04"] == {"fixed": "5.30.0-9ubuntu0.5+esm2", "subscription_only": True,
                                 "availability": "Available with Ubuntu Pro (Infra-only): https://ubuntu.com/pro"}
    assert releases["22.04"] == {"fixed": "5.34.0-3ubuntu1.7", "subscription_only": False,
                                 "availability": "No subscription required"}
    assert "24.04" in releases


def test_parse_distro_fixes_prefers_a_standard_entry_and_keeps_unfixed_releases():
    vuln = {"affected": [
        {"package": {"name": "x", "ecosystem": "Ubuntu:Pro:FIPS-updates:22.04:LTS"}, "ranges": [{"events": [{"fixed": "1+fips"}]}]},
        {"package": {"name": "x", "ecosystem": "Ubuntu:22.04:LTS"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.1"}]}]},
        {"package": {"name": "x", "ecosystem": "Ubuntu:24.04:LTS"}, "ranges": [{"events": [{"introduced": "0"}]}]},
        {"package": {"name": "other", "ecosystem": "Ubuntu:26.04:LTS"}, "ranges": [{"events": [{"fixed": "9"}]}]}]}
    releases = osv.parse_distro_fixes(vuln, "x")
    assert releases["22.04"]["fixed"] == "1.1" and releases["22.04"]["subscription_only"] is False
    assert releases["24.04"]["fixed"] is None      # affected, no fix yet
    assert "26.04" not in releases                 # another package


def test_distro_fixes_fetches_once_and_knows_only_supported_distributions(conn, http_client, apis):
    fix = osv.distro_fixes(conn, http_client, "cve-2026-8376", "ubuntu", "perl", [])
    assert fix["id"] == "UBUNTU-CVE-2026-8376" and fix["releases"]["20.04"]["subscription_only"] is True
    osv.distro_fixes(conn, http_client, "CVE-2026-8376", "ubuntu", "perl", [])
    assert apis.hosts().count("api.osv.dev") == 1
    assert osv.distro_fixes(conn, http_client, "CVE-2026-8376", "rhel", "perl", []) is None


def test_distro_fixes_unknown_cve_has_no_releases(conn, http_client):
    assert osv.distro_fixes(conn, http_client, "CVE-1999-0001", "ubuntu", "perl", [])["releases"] == {}


# -- what the findings say, and the suggestion rule -------------------------------------------------

@pytest.mark.parametrize("rule_id, distro", [
    ("SNYK-UBUNTU2004-PERL-16800832", ("ubuntu", "20.04")), ("SNYK-UBUNTU1604-GLIBC-2356812", ("ubuntu", "16.04")),
    ("SNYK-DEBIAN11-OPENSSL-1", ("debian", "11")), ("SNYK-ALPINE318-ZLIB-1", ("alpine", "3.18")),
    ("javascript/CodeInjection", None)])
def test_distro_of_reads_the_base_os_from_the_scanner_rule_id(rule_id, distro):
    assert images.distro_of([{"rule_id": rule_id}]) == distro


def test_scanner_offers_nothing_newer_covers_the_three_cases():
    assert images.scanner_offers_nothing_newer({"fixable": False})
    assert images.scanner_offers_nothing_newer({"package": "glibc@2.23-0ubuntu11.3", "upgrade_to": "glibc/libc-bin@2.23-0ubuntu11.3"})
    assert not images.scanner_offers_nothing_newer({"package": "perl@5.30.0-9ubuntu0.5", "upgrade_to": "perl/perl-base@5.30.0-9ubuntu0.5+esm2"})


def fix(**releases):
    return {"id": "X", "url": "u", "releases": {
        release.replace("_", "."): {"fixed": value[0], "subscription_only": value[1], "availability": value[2] if len(value) > 2 else None}
        for release, value in releases.items()}}


def test_release_status_counts_each_way_a_cve_can_stand():
    fixes = [fix(r20_04=("1+esm1", True, "Available with Ubuntu Pro"), r22_04=("2", False)),
             fix(r20_04=("1", False), r22_04=(None, False)), fix(r20_04=("3", False)), None, {"releases": {}}]
    here = images.release_status(fixes, "r20.04")
    assert (here["checked"], here["standard"], here["subscription"], here["availability"]) == (3, 2, 1, "Available with Ubuntu Pro")
    newer = images.release_status(fixes, "r22.04")
    assert (newer["standard"], newer["unfixed"], newer["not_listed"]) == (1, 1, 1)


def line(tag, release, released, eol, resolved=1, checked=1):
    return {"tag": tag, "version": f"{tag}.1", "base_os": f"Ubuntu {release}", "base_release": release,
            "released": released, "supported_until": eol, "end_of_life": date.fromisoformat(eol) <= TODAY if eol else None,
            "cves_resolved": resolved, "cves_checked": checked}


def test_suggest_is_the_nearest_supported_line_and_longest_supported_is_reported_separately():
    found = [line("7.0", "22.04", "2023-08-31", "2027-08-31"), line("8.0", "24.04", "2024-10-31", "2029-10-31"),
             line("8.3", "24.04", "2026-05-31", "2029-10-31")]
    assert images.suggest(found, "20.04", TODAY)["tag"] == "7.0"             # the smallest step
    assert images.longest_supported(found, "20.04", TODAY)["tag"] == "8.0"   # a tie with 8.3: the longer-established


def test_compatible_is_a_line_of_the_same_major_version_that_resolves_the_cves():
    found = [line("4.6", "20.04", "2021-01-31", "2027-01-31", resolved=0),   # same major, but the same unfixed base
             line("4.8", "22.04", "2022-01-31", "2027-06-30"),               # same major, resolves
             line("5.0", "22.04", "2022-07-31", "2028-07-31")]               # resolves, but a new major version
    assert images.compatible(found, "4.4", "20.04")["tag"] == "4.8"
    assert images.compatible(found[:1] + found[2:], "4.4", "20.04") is None


def test_compatible_needs_fix_data_and_a_line_that_is_not_past_end_of_life():
    unchecked = line("4.8", "22.04", "2022-01-31", "2027-06-30", resolved=None, checked=None)
    ended = line("4.8", "22.04", "2022-01-31", "2025-06-30")
    assert images.compatible([unchecked], "4.4", "20.04") is None
    assert images.compatible([ended], "4.4", "20.04") is None


def test_suggest_skips_ended_too_new_and_unresolved_lines():
    young = (TODAY - timedelta(days=images.MIN_AGE_DAYS - 1)).isoformat()
    found = [line("6.0", "22.04", "2022-07-31", "2025-07-31"),                      # past end of life
             line("7.0", "22.04", "2023-08-31", "2027-08-31", resolved=0),          # leaves a CVE open
             line("9.0", "24.04", young, "2031-10-31")]                             # only just released
    assert images.suggest(found, "20.04", TODAY) is None
    found.append(line("8.0", "24.04", "2024-10-31", "2029-10-31"))
    assert images.suggest(found, "20.04", TODAY)["tag"] == "8.0"


def test_suggest_without_fix_data_needs_a_different_base_os():
    found = [line("5.0", "20.04", "2021-07-31", "2027-10-31", resolved=None, checked=None),
             line("7.0", "22.04", "2023-08-31", "2027-08-31", resolved=None, checked=None)]
    assert images.suggest(found, "20.04", TODAY)["tag"] == "7.0"


def test_suggest_never_goes_by_version_number_alone():
    assert images.suggest([line("9.0", "24.04", None, None)], "20.04", TODAY) is None


def test_candidates_combine_docker_hub_endoflife_and_fix_data():
    lines = {"newer": [{"tag": "5.0", "version": "5.0.33", "base_distro": "ubuntu", "base_release": "20.04"},
                       {"tag": "8.0", "version": "8.0.32", "base_distro": None, "base_release": "24.04"}]}
    cycles = lifecycle.parse(fixture_json("endoflife_mongodb.json"))
    fixes = [fix(r20_04=("1+esm1", True, "Available with Ubuntu Pro"), r24_04=("2", False))]
    fixes[0]["releases"] = {"20.04": fixes[0]["releases"]["r20.04"], "24.04": fixes[0]["releases"]["r24.04"]}
    five, eight = images.candidates(lines, cycles, fixes, "ubuntu", TODAY)
    assert (five["end_of_life"], five["cves_resolved"], five["base_os"]) == (True, 0, "Ubuntu 20.04")
    assert (eight["end_of_life"], eight["supported_until"], eight["cves_resolved"], eight["base_os"]) == (
        False, "2029-10-31", 1, "Ubuntu 24.04")


def test_package_summary_counts_cves_and_packages():
    findings = [{"cve": "CVE-1", "package": "perl@1"}, {"cve": "CVE-2", "package": "perl@1"}, {"cve": "CVE-3", "package": "zlib@2"}]
    assert images.package_summary(findings) == (3, 2, "perl ×2, zlib")


def test_image_of_takes_the_first_named_image():
    assert images.image_of([{"package": "x"}, {"image_name": "mongo", "image_tag": "4.4"}]) == ("mongo", "4.4")
    assert images.image_of([{"package": "x"}]) == (None, None)


def test_osv_parse_lists_every_fixed_version_smallest_first():
    payload = {"vulns": [{"id": "GHSA-x", "affected": [
        {"package": {"name": "widget", "ecosystem": "npm"}, "ranges": [{"events": [{"introduced": "2.0.0"}, {"fixed": "2.0.3"}]}]},
        {"package": {"name": "widget", "ecosystem": "npm"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.5"}]}]},
        {"package": {"name": "other", "ecosystem": "npm"}, "ranges": [{"events": [{"fixed": "9.9.9"}]}]}]}]}
    advisory = osv.parse(payload, "widget", "npm", "1.2.0")[0]
    assert advisory["fixed"] == "1.2.5" and advisory["fixed_versions"] == ["1.2.5", "2.0.3"] and advisory["aliases"] == []


# -- other stacks: tag styles, Debian and Alpine -----------------------------------------------------

@pytest.mark.parametrize("current, tags, newer", [
    ("16", ["16", "18", "20", "20.1", "22-alpine", "18-alpine", "latest"], ["18", "20"]),          # a line per major version
    ("16-alpine", ["18", "20", "22-alpine", "18-alpine", "18-slim"], ["18-alpine", "22-alpine"]),  # the variant is kept
    ("3.11-slim-bookworm", ["3.12-slim-bookworm", "3.12-slim", "3.13-slim", "3.12", "3.13-alpine"],
     ["3.12-slim-bookworm", "3.13-slim"]),                                                         # ... without its OS name if need be
    ("4.4.30-focal", ["5.0-focal", "5.0", "6.0", "6.0-jammy", "4.4-focal"], ["5.0-focal", "6.0"]),
    ("18.04", ["18.04", "20.04", "22.04", "24.04", "24.10", "noble"], ["20.04", "22.04", "24.04", "24.10"]),  # written as tagged
    ("latest", ["1.0", "2.0"], []),
])
def test_newer_lines_follow_the_way_the_current_tag_is_written(current, tags, newer):
    assert registry.newer_lines(tags, current) == newer


def test_describe_reads_debian_and_alpine_from_the_build_history():
    debian = {"config": {"Env": ["NODE_VERSION=22.23.3", "YARN_VERSION=1.22.22"]},
              "history": [{"created_by": "# debian.sh --arch 'amd64' out/ 'bookworm' '@1791158400'"}], "created": "2026-10-06T01:00:00Z"}
    assert registry.describe("22", debian) == {"tag": "22", "line": "22", "version": "22.23.3", "base_distro": "debian",
                                              "base_release": "12", "built": "2026-10-06"}
    alpine = {"config": {"Env": ["REDIS_VERSION=7.4.11"]},
              "history": [{"created_by": "ADD alpine-minirootfs-3.21.8-x86_64.tar.gz / # buildkit"}]}
    facts = registry.describe("7.4-alpine", alpine)
    assert (facts["line"], facts["version"], facts["base_distro"], facts["base_release"]) == ("7.4", "7.4.11", "alpine", "3.21")
    unknown = registry.describe("16", {"config": {"Env": ["NODE_VERSION=16.20.2"]}, "history": [{"created_by": "ADD file:d9c3 in /"}]})
    assert (unknown["base_distro"], unknown["base_release"]) == (None, None)


def test_parse_distro_fixes_reads_debian_and_alpine_releases():
    debian = {"affected": [
        {"package": {"name": "zlib", "ecosystem": "Debian:12"}, "ranges": [{"events": [{"introduced": "0"}]}]},
        {"package": {"name": "zlib", "ecosystem": "Debian:13"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1:1.3.dfsg-2"}]}]}]}
    releases = osv.parse_distro_fixes(debian, "zlib")
    assert releases["12"]["fixed"] is None and releases["12"]["subscription_only"] is False   # affected, no fix
    assert releases["13"]["fixed"] == "1:1.3.dfsg-2"
    alpine = {"affected": [{"package": {"name": "openssl", "ecosystem": "Alpine:v3.20"}, "ranges": [{"events": [{"fixed": "3.1.4-r0"}]}]}]}
    assert osv.parse_distro_fixes(alpine, "openssl") == {"3.20": {"fixed": "3.1.4-r0", "availability": None, "subscription_only": False}}


def test_distro_fixes_ask_for_the_distribution_s_own_record(conn, http_client, apis):
    for distro, record in (("debian", "DEBIAN-CVE-2023-45853"), ("alpine", "ALPINE-CVE-2023-45853")):
        assert osv.distro_fixes(conn, http_client, "CVE-2023-45853", distro, "zlib", [])["id"] == record
    assert [call.url.path.rsplit("/", 1)[-1] for call in apis.calls] == ["DEBIAN-CVE-2023-45853", "ALPINE-CVE-2023-45853"]


def test_release_status_counts_nothing_for_a_release_the_data_does_not_track():
    fixes = [fix(r12=("1", False), r13=("2", False)), fix(r13=("3", False))]
    assert images.release_status(fixes, "r12")["not_listed"] == 1          # tracked: listed for the first CVE only
    untracked = images.release_status(fixes, "r11")
    assert (untracked["checked"], untracked["not_listed"]) == (0, 0)       # never listed: unknown, not "not affected"


def test_candidates_take_support_dates_by_the_release_line_not_the_tag():
    lines = {"newer": [{"tag": "3.12-slim", "line": "3.12", "version": "3.12.15", "base_distro": "debian", "base_release": "13"}]}
    found = images.candidates(lines, {"3.12": {"released": "2023-10-02", "eol": "2028-10-31"}}, [], "debian", TODAY)
    assert (found[0]["tag"], found[0]["base_os"], found[0]["supported_until"]) == ("3.12-slim", "Debian 13", "2028-10-31")


def test_suggest_skips_a_line_that_leaves_support_soon():
    soon = (TODAY + timedelta(days=images.MIN_SUPPORT_LEFT_DAYS - 1)).isoformat()
    found = [line("14", "13", "2021-09-30", soon), line("15", "13", "2022-10-13", "2027-11-11")]
    assert images.suggest(found, "12", TODAY)["tag"] == "15"


def test_ended_on_tells_a_line_past_end_of_life_from_a_supported_or_unknown_one():
    assert images.ended_on({"eol": "2024-02-29"}, TODAY) == "2024-02-29"
    assert images.ended_on({"eol": "2027-08-31"}, TODAY) is False
    assert images.ended_on({"eol": True}, TODAY) is True and images.ended_on({"eol": False}, TODAY) is False
    assert images.ended_on(None, TODAY) is None and images.ended_on({}, TODAY) is None

"""Unit tests for normaliser/normaliser.py. Pure functions + one full
process_sarif_file -> build_ranked_unified pass against the schema in
docs/unified-findings-format.md.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from normaliser.normaliser import (
    assign_priorities,
    build_ranked_unified,
    deduplicate,
    extract_code_flow,
    extract_cve,
    extract_cwe,
    get_severity_from_level,
    make_dedup_key,
    parse_container_image,
    parse_cvss,
    parse_fix_version,
    parse_package,
    process_sarif_file,
    promote_to_critical,
    sort_findings,
)

pytestmark = pytest.mark.unit


# --------------------------------------------------------------------------------------
# extract_cve
# --------------------------------------------------------------------------------------

def test_extract_cve_finds_first_match():
    text = "See CVE-2022-23219 and also CVE-2016-10531 for details."
    assert extract_cve(text) == "CVE-2022-23219"


def test_extract_cve_no_match_returns_none():
    assert extract_cve("no identifiers here") is None


def test_extract_cve_none_input_returns_none():
    assert extract_cve(None) is None


# --------------------------------------------------------------------------------------
# extract_cwe
# --------------------------------------------------------------------------------------

def test_extract_cwe_returns_first_entry():
    assert extract_cwe({"cwe": ["CWE-94", "CWE-95"]}) == "CWE-94"


def test_extract_cwe_missing_key_returns_none():
    assert extract_cwe({}) is None


def test_extract_cwe_empty_list_returns_none():
    assert extract_cwe({"cwe": []}) is None


# --------------------------------------------------------------------------------------
# parse_cvss
# --------------------------------------------------------------------------------------

def test_parse_cvss_prefers_cvssv3_basescore():
    assert parse_cvss({"cvssv3_baseScore": 8.8, "security-severity": "5.0"}) == 8.8


def test_parse_cvss_falls_back_to_security_severity():
    assert parse_cvss({"security-severity": "9.8"}) == 9.8


def test_parse_cvss_skips_literal_null_string():
    assert parse_cvss({"cvssv3_baseScore": "null", "security-severity": "7.5"}) == 7.5


def test_parse_cvss_rejects_out_of_range_score():
    assert parse_cvss({"cvssv3_baseScore": 11.0}) is None


def test_parse_cvss_rejects_non_numeric():
    assert parse_cvss({"cvssv3_baseScore": "not-a-number"}) is None


def test_parse_cvss_missing_both_keys_returns_none():
    assert parse_cvss({}) is None


# --------------------------------------------------------------------------------------
# get_severity_from_level
# --------------------------------------------------------------------------------------

@pytest.mark.parametrize(
    "level,expected",
    [("error", "high"), ("warning", "medium"), ("note", "low"), ("none", "info")],
)
def test_get_severity_from_level_known(level, expected):
    assert get_severity_from_level(level) == expected


def test_get_severity_from_level_none_is_unknown():
    assert get_severity_from_level(None) == "unknown"


def test_get_severity_from_level_unrecognised_is_unknown():
    assert get_severity_from_level("something-else") == "unknown"


# --------------------------------------------------------------------------------------
# promote_to_critical
# --------------------------------------------------------------------------------------

def test_promote_to_critical_promotes_at_9_0_boundary():
    assert promote_to_critical("medium", 9.0) == "critical"


def test_promote_to_critical_does_not_promote_just_below_boundary():
    assert promote_to_critical("medium", 8.99) == "medium"


def test_promote_to_critical_none_score_unchanged():
    assert promote_to_critical("high", None) == "high"


def test_promote_to_critical_above_boundary():
    assert promote_to_critical("low", 9.8) == "critical"


# --------------------------------------------------------------------------------------
# parse_package
# --------------------------------------------------------------------------------------

def test_parse_package_simple():
    assert parse_package("marked@0.3.5") == ("marked", "0.3.5")


def test_parse_package_scoped_uses_last_at():
    assert parse_package("@types/node@14.0.0") == ("@types/node", "14.0.0")


def test_parse_package_none_input():
    assert parse_package(None) == (None, None)


def test_parse_package_no_version():
    assert parse_package("marked") == ("marked", None)


# --------------------------------------------------------------------------------------
# parse_fix_version
# --------------------------------------------------------------------------------------

def test_parse_fix_version_no_fixes():
    assert parse_fix_version(None, "marked") == (False, None)
    assert parse_fix_version([], "marked") == (False, None)


def test_parse_fix_version_explicit_no_fixed_version():
    fixes = [{"description": {"text": "There is no fixed version for this vulnerability"}}]
    assert parse_fix_version(fixes, "marked") == (False, None)


def test_parse_fix_version_upgrade_to_pattern():
    fixes = [{"description": {"text": "Upgrade to marked@0.3.6 to fix this issue"}}]
    assert parse_fix_version(fixes, "marked") == (True, "marked@0.3.6")


def test_parse_fix_version_bare_version_fallback_uses_package_name():
    fixes = [{"description": {"text": "Fixed @1.20.3, see changelog"}}]
    assert parse_fix_version(fixes, "body-parser") == (True, "body-parser@1.20.3")


def test_parse_fix_version_no_match_returns_false():
    fixes = [{"description": {"text": "See advisory for details"}}]
    assert parse_fix_version(fixes, "marked") == (False, None)


@pytest.mark.parametrize("target", [
    "perl/perl-base@5.30.0-9ubuntu0.5+esm2",              # "+" suffix
    "bzip2@1.0.8-2ubuntu0.1~esm1",                         # "~" suffix
    "attr/libattr1@1:2.4.48-5ubuntu0.1~esm1",              # epoch
    "gcc-10/libstdc++6@10.5.0-1ubuntu1~20.04.1+esm1",      # "+" in the package name
    "@types/node@14.0.0",                                  # scoped npm package
])
def test_parse_fix_version_keeps_the_whole_upgrade_target(target):
    # An OS package fix cut off at "+esm2" names the version that is already installed.
    fixes = [{"description": {"text": f"Upgrade to {target}"}}]
    assert parse_fix_version(fixes, "ignored") == (True, target)


# --------------------------------------------------------------------------------------
# parse_container_image
# --------------------------------------------------------------------------------------

def test_parse_container_image_splits_name_and_tag_using_the_run_id():
    run_id = "Snyk/Container/docker-image|mongo/0/2026-10-11T08:42:46.495Z"
    assert parse_container_image("mongo_4.4", run_id) == ("mongo", "4.4")


def test_parse_container_image_handles_registry_paths_and_underscores_in_the_name():
    run_id = "Snyk/Container/docker-image|ghcr.io/acme/my_app/0/2026-10-11T08:42:46.495Z"
    assert parse_container_image("ghcr.io/acme/my_app_1.2.0", run_id) == ("ghcr.io/acme/my_app", "1.2.0")


def test_parse_container_image_untagged_image_has_no_tag():
    run_id = "Snyk/Container/docker-image|mongo/0/2026-10-11T08:42:46.495Z"
    assert parse_container_image("mongo", run_id) == ("mongo", None)


def test_parse_container_image_without_a_run_id_does_not_guess_the_tag():
    assert parse_container_image("mongo_4.4", None) == ("mongo_4.4", None)
    assert parse_container_image("my_app", "Snyk/Container/go-distribution@x/1/2026") == ("my_app", None)


def test_parse_container_image_no_artifact_returns_none():
    assert parse_container_image(None, "Snyk/Container/docker-image|mongo/0/2026") == (None, None)


# --------------------------------------------------------------------------------------
# make_dedup_key
# --------------------------------------------------------------------------------------

def test_make_dedup_key_sast_uses_rule_file_line():
    key = make_dedup_key("sast", None, "javascript/CodeInjection", None,
                          "app/routes/contributions.js", 32)
    assert key == "javascript/CodeInjection|app/routes/contributions.js|32"


def test_make_dedup_key_sast_missing_line_uses_question_mark():
    key = make_dedup_key("sast", None, "javascript/Ssrf", None, "app/routes/research.js", None)
    assert key.endswith("|?")


def test_make_dedup_key_sca_retains_cve_and_rule():
    key = make_dedup_key("sca", "CVE-2016-10531", "npm:marked:20150520", "marked", None, None)
    assert '"CVE-2016-10531"' in key and '"npm:marked:20150520"' in key


def test_distinct_django_rules_sharing_cve_are_preserved():
    keys = [make_dedup_key("sca", "CVE-2024-56374", rule, "django", None, None)
            for rule in ("SNYK-PYTHON-DJANGO-8623541", "SNYK-PYTHON-DJANGO-8623542")]
    assert keys[0] != keys[1]


def test_make_dedup_key_sca_falls_back_to_rule_id_without_cve():
    key = make_dedup_key("sca", None, "npm:marked:20150520", "marked", None, None)
    assert '"npm:marked:20150520"' in key


# --------------------------------------------------------------------------------------
# deduplicate
# --------------------------------------------------------------------------------------

def test_deduplicate_keeps_higher_score_on_collision():
    findings = [
        {"dedup_key": "k1", "score": 5.0},
        {"dedup_key": "k1", "score": 8.0},
    ]
    result = deduplicate(findings)
    assert len(result) == 1
    assert result[0]["score"] == 8.0


def test_deduplicate_keeps_distinct_keys_separate():
    findings = [{"dedup_key": "k1", "score": 5.0}, {"dedup_key": "k2", "score": 5.0}]
    assert len(deduplicate(findings)) == 2


# --------------------------------------------------------------------------------------
# sort_findings / assign_priorities
# --------------------------------------------------------------------------------------

def test_sort_findings_orders_by_severity_then_real_score_then_score_desc():
    findings = [
        {"severity": "high", "has_real_score": True, "score": 7.0, "title": "b"},
        {"severity": "critical", "has_real_score": True, "score": 9.5, "title": "a"},
        {"severity": "high", "has_real_score": False, "score": 8.5, "title": "c"},
        {"severity": "high", "has_real_score": True, "score": 8.0, "title": "d"},
    ]
    ordered = sort_findings(findings)
    assert [f["title"] for f in ordered] == ["a", "d", "b", "c"]


def test_assign_priorities_is_1_based_and_sequential():
    findings = [{}, {}, {}]
    result = assign_priorities(findings)
    assert [f["priority"] for f in result] == [1, 2, 3]


# --------------------------------------------------------------------------------------
# Full pipeline: process_sarif_file -> build_ranked_unified, schema per
# docs/unified-findings-format.md
# --------------------------------------------------------------------------------------

REQUIRED_TOP_LEVEL_FIELDS = {
    "finding_id", "finding_type", "severity", "score", "has_real_score",
    "identifiers", "title", "summary", "location", "dependency", "remediation",
    "priority", "is_node_modules", "description", "ecosystem",
}


def test_full_pipeline_schema_and_content(sarif_sample_path):
    all_findings = []
    for path in sarif_sample_path.values():
        all_findings.extend(process_sarif_file(Path(path)))

    deduped = assign_priorities(sort_findings(deduplicate(all_findings)))
    ranked_unified = build_ranked_unified(deduped)

    assert ranked_unified, "expected at least one finding from the trimmed fixtures"

    for finding in ranked_unified:
        assert REQUIRED_TOP_LEVEL_FIELDS <= finding.keys()
        assert "dedup_key" not in finding
        assert set(finding["identifiers"].keys()) == {"cve", "cwe", "rule_id"}
        assert set(finding["location"].keys()) == {
            "kind", "file", "line", "package", "display", "image_name", "image_tag"}
        assert set(finding["remediation"].keys()) == {"type", "fixable", "upgrade_to"}

    # priorities are a contiguous 1..N ranking with no gaps or repeats
    assert [f["priority"] for f in ranked_unified] == list(range(1, len(ranked_unified) + 1))

    # Preserve Snyk's explicit low rating even when CVSS is 9.8.
    container_findings = [f for f in ranked_unified if f["finding_type"] == "container"]
    assert any(f["severity"] == "low" and f["score"] == 9.8 for f in container_findings)

    # container findings name the scanned image; no other finding type does
    assert all((f["location"]["image_name"], f["location"]["image_tag"]) == ("mongo", "4.0")
               for f in container_findings)
    assert all(f["location"]["image_name"] is None and f["location"]["image_tag"] is None
               for f in ranked_unified if f["finding_type"] != "container")

    # an OS package fix keeps its full version -- without "+esm1" it is the installed version
    glibc = next(f for f in container_findings if f["location"]["package"].startswith("glibc@"))
    assert glibc["remediation"]["upgrade_to"] == "glibc/libc-bin@2.23-0ubuntu11.3+esm1"

    # the node_modules SAST hit must be flagged (triage's filter relies on this)
    sast_findings = [f for f in ranked_unified if f["finding_type"] == "sast"]
    assert any(f["is_node_modules"] for f in sast_findings)
    assert any(not f["is_node_modules"] for f in sast_findings)

    # sca dependency chain: at least one direct and one transitive dependency present
    sca_findings = [f for f in ranked_unified if f["finding_type"] == "sca"]
    assert any(f["dependency"] and f["dependency"]["is_direct"] for f in sca_findings)
    assert any(f["dependency"] and f["dependency"]["is_direct"] is False for f in sca_findings)


# --------------------------------------------------------------------------------------
# extract_code_flow (ITP2 3.1)
# --------------------------------------------------------------------------------------

def _step(uri, line):
    return {"location": {"physicalLocation": {
        "artifactLocation": {"uri": uri}, "region": {"startLine": line}}}}


def test_extract_code_flow_keeps_source_to_sink_order_across_files_and_dedupes():
    result = {"codeFlows": [{"threadFlows": [{"locations": [
        _step("routes/user.js", 10), _step("services/user.js", 25),
        _step("services/user.js", 25), _step("db/query.js", 42),
    ]}]}]}
    assert extract_code_flow(result) == [
        {"file": "routes/user.js", "line": 10},
        {"file": "services/user.js", "line": 25},
        {"file": "db/query.js", "line": 42},
    ]


def test_extract_code_flow_empty_without_code_flows():
    assert extract_code_flow({}) == []
    assert extract_code_flow({"codeFlows": [{"threadFlows": [{"locations": [{}]}]}]}) == []


def test_sast_findings_carry_code_flow_and_others_an_empty_list(sarif_sample_path):
    sast = process_sarif_file(sarif_sample_path["sast"])
    assert any(f["code_flow"] for f in sast)
    for f in sast:
        for step in f["code_flow"]:
            assert set(step) == {"file", "line"}
    sca = process_sarif_file(sarif_sample_path["sca"])
    assert all(f["code_flow"] == [] for f in sca)

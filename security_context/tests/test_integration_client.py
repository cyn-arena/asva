"""The drop-in ASVA client (integration/asva_rag_client.py), with HTTP mocked."""

import io
import json
import sys
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "integration"))
import asva_rag_client as client  # noqa: E402

ASVA_FINDING = {
    "finding_type": "sca", "title": "XSS in marked", "summary": "s", "description": "d", "ecosystem": "npm",
    "identifiers": {"cve": "CVE-2016-10531", "cwe": None, "rule_id": "npm:marked:20150520"},
    "location": {"file": "package.json", "package": "marked@0.3.5", "image_name": None, "image_tag": None},
    "remediation": {"upgrade_to": "marked@0.3.6", "fixable": True},
    "dependency": {"path": ["owasp-nodejs-goat@1.3.0", "marked@0.3.5"], "is_direct": True},
    "priority": 24,
}
RESPONSE = {
    "items": [{"source": "OSV.dev", "key": "dependency-upgrades", "kind": "upgrade_notes", "title": "Upgrade notes",
               "section": None, "text": "- marked 0.3.5 → 0.3.6"},
              {"source": "OWASP Cheat Sheet Series", "key": "Nodejs_Security_Cheat_Sheet", "kind": "guidance",
               "title": "NodeJS Security Cheat Sheet", "section": "Do not use dangerous functions", "text": "Avoid eval."}],
    "references": [
        {"type": "cve", "id": "CVE-2016-10531", "url": "https://nvd/x", "source": "NVD", "cvss": 6.1, "severity": "MEDIUM",
         "cwes": ["CWE-79"], "kev": False},
        {"type": "cve", "id": "CVE-2021-44228", "url": "https://nvd/y", "source": "NVD", "cvss": 10.0, "severity": "CRITICAL",
         "cwes": ["CWE-502"], "kev": True, "kev_date": "2021-12-10"},
        {"type": "cwe", "id": "CWE-79", "url": "https://cwe/79", "source": "MITRE CWE", "title": "XSS",
         "owasp_top10": ["A03:2021 - Injection"], "description": "The product does not neutralize input.",
         "mitigations": ["[Implementation] Encode output.", "[Design] Use a vetted library.", "[Operation] Use a firewall."]},
        {"type": "advisory", "id": "UBUNTU-CVE-2026-8376", "url": "https://osv/u", "source": "OSV.dev", "package": "perl",
         "fixed_in": "5.30.0-9ubuntu0.5+esm2", "availability": "Available with Ubuntu Pro (Infra-only): https://ubuntu.com/pro"},
        {"type": "image", "id": "mongo:4.4", "title": "mongo: release lines and base images", "url": "https://hub/mongo",
         "source": "Docker Hub"},
        {"type": "advisory", "id": "GHSA-1", "url": "https://osv/1", "source": "OSV.dev", "package": "marked",
         "fixed_in": "4.0.10", "aliases": ["CVE-2022-21681"], "beyond_target": True},
        {"type": "advisory", "id": "GHSA-2", "url": "https://osv/2", "source": "OSV.dev", "package": "marked",
         "fixed_in": "0.3.6", "aliases": ["CVE-2016-10531"], "beyond_target": False},
        {"type": "guidance", "id": "Nodejs#x", "title": "NodeJS Security › Do not use dangerous functions",
         "url": "https://owasp/x", "source": "OWASP Cheat Sheet Series"},
        {"type": "library_docs", "id": "https://docs/changes#aggregate", "title": "aggregate: 2.x vs 3.x syntax",
         "url": "https://docs/changes", "source": "Context7", "package": "mongodb 2.x → 3.x",
         "description": "Pipeline stages must now be provided as an Array."},
    ],
    "upgrades": [
        {"kind": "package", "name": "marked", "current": "0.3.5", "target": "0.3.6", "compatible_target": "0.3.6",
         "min_fixed": "0.3.6", "major_change": False, "status": "ok", "note": None},
        {"kind": "package", "name": "mongodb", "current": "2.2.36", "target": "3.1.13", "compatible_target": None,
         "min_fixed": None, "major_change": True, "status": "major_change",
         "note": "No compatible fix: OSV.dev lists no fix within 2.x."},
        {"kind": "image", "name": "mongo", "ecosystem": "Ubuntu 20.04", "current": "4.4", "target": "7.0",
         "compatible_target": None, "major_change": True, "note": "No compatible fix: no 4.x line of mongo resolves these findings.",
         "status": "newer_line_needed", "candidates": [
             {"tag": "6.0", "version": "6.0.28", "base_os": "Ubuntu 22.04", "end_of_life": True, "supported_until": "2025-07-31",
              "cves_resolved": 7, "cves_checked": 7},
             {"tag": "8.0", "version": "8.0.32", "base_os": "Ubuntu 24.04", "end_of_life": False, "supported_until": "2029-10-31",
              "cves_resolved": 7, "cves_checked": 7}]},
    ],
}
CONTAINER_FINDING = {
    "finding_type": "container", "title": "t", "summary": "s", "description": "d", "ecosystem": "deb",
    "identifiers": {"cve": "CVE-2026-8376", "cwe": "CWE-680", "cwes": ["CWE-680"], "rule_id": "SNYK-UBUNTU2004-PERL-16800832"},
    "location": {"file": "docker-compose.yml", "package": "perl@5.30.0-9ubuntu0.5", "image_name": "mongo", "image_tag": "4.4"},
    "remediation": {"upgrade_to": "perl/perl-base@5.30.0-9ubuntu0.5+esm2", "fixable": True}, "dependency": None,
}


@pytest.fixture(autouse=True)
def service_url(monkeypatch):
    monkeypatch.setenv("ASVA_RAG_URL", "http://rag.test:8000/")
    client._memo.clear()


def fake_urlopen(responses: list, calls: list):
    def urlopen(request, timeout):
        calls.append((request.full_url, request.get_method(), request.data and json.loads(request.data)))
        result = responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return io.BytesIO(json.dumps(result).encode())
    return urlopen


def test_maps_normalised_asva_findings_to_the_service_fields():
    assert client.to_request_finding(ASVA_FINDING) == {
        "finding_type": "sca", "cve": "CVE-2016-10531", "cwe": None, "cwes": None, "rule_id": "npm:marked:20150520",
        "package": "marked@0.3.5", "ecosystem": "npm", "upgrade_to": "marked@0.3.6", "fixable": True,
        "dependency_path": ["owasp-nodejs-goat@1.3.0", "marked@0.3.5"], "image_name": None, "image_tag": None,
        "title": "XSS in marked", "summary": "s", "description": "d"}


def test_container_findings_carry_the_image_and_every_rule_cwe():
    request = client.to_request_finding(CONTAINER_FINDING)
    assert (request["image_name"], request["image_tag"], request["cwes"]) == ("mongo", "4.4", ["CWE-680"])


def test_fetch_context_posts_once_per_distinct_request(monkeypatch):
    calls = []
    monkeypatch.setattr(client.urllib.request, "urlopen", fake_urlopen([RESPONSE], calls))
    assert client.fetch_context([ASVA_FINDING], "version_upgrade") == RESPONSE
    assert client.fetch_context([ASVA_FINDING], "version_upgrade") == RESPONSE  # memoised
    assert len(calls) == 1
    url, method, body = calls[0]
    assert (url, method, body["fix_type"]) == ("http://rag.test:8000/v1/context", "POST", "version_upgrade")


def test_not_configured_is_unavailable(monkeypatch):
    monkeypatch.setenv("ASVA_RAG_URL", "")
    assert not client.enabled()
    with pytest.raises(client.RAGUnavailableError, match="not set"):
        client.fetch_context([ASVA_FINDING], "version_upgrade")


@pytest.mark.parametrize("error", [
    urllib.error.HTTPError("u", 503, "down", {}, None), urllib.error.URLError("refused"), TimeoutError("slow")])
def test_service_errors_become_rag_unavailable(monkeypatch, error):
    monkeypatch.setattr(client.urllib.request, "urlopen", fake_urlopen([error], []))
    with pytest.raises(client.RAGUnavailableError):
        client.check_health()


def test_prompt_block_is_delimited_numbered_and_marked_as_data():
    block = client.prompt_block(RESPONSE)
    assert block.startswith("===REFERENCE MATERIAL===\n\n" + client.PROMPT_HEADER)
    assert "[1] OSV.dev: Upgrade notes\n- marked 0.3.5 → 0.3.6" in block
    assert "[2] OWASP Cheat Sheet Series: NodeJS Security Cheat Sheet › Do not use dangerous functions\nAvoid eval." in block
    assert block.endswith("===END REFERENCE MATERIAL===")


def test_prompt_block_is_empty_without_items():
    assert client.prompt_block({"items": []}) == "" and client.prompt_block(None) == ""


def test_pr_references_table_lists_cves_by_cvss_and_flags_exploited_ones():
    md = client.pr_references(RESPONSE)
    assert md.startswith("### References consulted")
    log4j, marked = md.index("CVE-2021-44228"), md.index("CVE-2016-10531")
    assert log4j < marked
    assert "| [CVE-2021-44228](https://nvd/y) | 10.0 CRITICAL | CWE-502 | **yes** (since 2021-12-10) |" in md
    assert "- [CWE-79](https://cwe/79): XSS (OWASP Top 10: A03:2021 - Injection)" in md
    assert "- [CVE-2022-21681](https://osv/1) in marked: fixed in 4.0.10" in md
    assert "GHSA-2" not in md  # advisories fixed by the upgrade aren't listed
    assert "not endorsed or certified by the NVD" in md


def test_pr_references_merge_files_without_duplicates():
    md = client.pr_references(RESPONSE, RESPONSE, None)
    assert md.count("CVE-2021-44228](") == 1


def test_pr_references_explain_each_cwe_and_say_where_os_fixes_are_published():
    md = client.pr_references(RESPONSE)
    assert "  - The product does not neutralize input.\n  - Mitigation: [Implementation] Encode output." in md
    assert "[Operation] Use a firewall." not in md  # two mitigations per CWE are enough for a PR body
    assert ("- [UBUNTU-CVE-2026-8376](https://osv/u) perl: fixed in 5.30.0-9ubuntu0.5+esm2 "
            "(Available with Ubuntu Pro (Infra-only): https://ubuntu.com/pro)") in md
    assert "- [mongo: release lines and base images](https://hub/mongo) (Docker Hub)" in md


def test_pr_upgrades_tabulates_packages_and_image_lines():
    md = client.pr_upgrades(RESPONSE, RESPONSE)
    assert md.startswith("### Upgrade summary")
    assert "| marked | 0.3.5 | 0.3.6 | 0.3.6 | 0.3.6 |  |" in md
    assert ("| mongodb | 2.2.36 | 3.1.13 | **none** | - | **major version change**. No compatible fix: OSV.dev lists "
            "no fix within 2.x. |") in md
    assert ("**Image `mongo:4.4`** (Ubuntu 20.04): **no compatible fix**; migration target `mongo:7.0`, "
            "a **major version change**.") in md
    assert "| mongo:6.0 | 6.0.28 | Ubuntu 22.04 | 7 of 7 | past end of life |" in md
    assert "| mongo:8.0 | 8.0.32 | Ubuntu 24.04 | 7 of 7 | until 2029-10-31 |" in md
    assert md.count("| marked |") == 1  # merged across files without duplicates


def test_pr_upgrades_is_empty_without_upgrade_data():
    assert client.pr_upgrades({"upgrades": []}, None) == ""


def test_compatible_upgrades_is_the_map_to_apply_and_held_back_lists_the_rest_with_reasons():
    assert client.compatible_upgrades(RESPONSE) == {"marked": "0.3.6"}
    assert client.held_back(RESPONSE) == [
        "mongodb 2.2.36: No compatible fix: OSV.dev lists no fix within 2.x.",
        "mongo 4.4: No compatible fix: no 4.x line of mongo resolves these findings."]
    assert client.compatible_upgrades(None) == {} and client.held_back({"upgrades": []}) == []


def test_pr_references_give_the_breaking_changes_of_a_held_back_major_upgrade():
    md = client.pr_references(RESPONSE)
    assert "**Breaking changes to expect in a held-back major upgrade** (the library's documentation, via Context7):" in md
    assert ("- [aggregate: 2.x vs 3.x syntax](https://docs/changes) (mongodb 2.x → 3.x): "
            "Pipeline stages must now be provided as an Array.") in md

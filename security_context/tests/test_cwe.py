import io
import zipfile

import httpx

from app import store
from app.sources import cwe
from conftest import FIXTURES

XML = (FIXTURES / "cwe_sample.xml").read_bytes()


def _zip(xml: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("cwec_v9.9.xml", xml)
    return buffer.getvalue()


def test_parse_reads_catalogue_version():
    version, _, _ = cwe.parse(XML)
    assert version == "9.9 (2026-01-01)"


def test_parse_skips_deprecated_weaknesses():
    _, records, _ = cwe.parse(XML)
    assert {r["key"] for r in records} == {"CWE-74", "CWE-94", "CWE-95", "CWE-913"}


def test_parse_builds_definition_url_and_licence():
    _, records, _ = cwe.parse(XML)
    record = next(r for r in records if r["key"] == "CWE-94")
    assert record["url"] == "https://cwe.mitre.org/data/definitions/94.html"
    assert record["title"] == "Improper Control of Generation of Code ('Code Injection')"
    assert "Terms of Use" in record["license"]


def test_parse_lists_implementation_mitigations_first_and_flattens_xhtml():
    _, records, _ = cwe.parse(XML)
    text = next(r for r in records if r["key"] == "CWE-94")["text"]
    implementation = text.index("[Implementation; Input Validation] Assume all input is malicious. Reject any input")
    design = text.index("[Architecture and Design; Refactoring]")
    assert implementation < design


def test_parse_weakness_without_mitigations_has_no_mitigation_section():
    _, records, _ = cwe.parse(XML)
    text = next(r for r in records if r["key"] == "CWE-95")["text"]
    assert cwe.MITIGATIONS_HEADER not in text


def test_parse_keeps_only_research_view_child_of_links_without_duplicates():
    _, _, links = cwe.parse(XML)
    assert [l for l in links if l[1] == "child_of"] == [
        ("CWE-94", "child_of", "CWE-74"),
        ("CWE-94", "child_of", "CWE-913"),
        ("CWE-95", "child_of", "CWE-94"),
    ]


def test_parse_maps_cwes_to_owasp_top10_categories_of_both_editions():
    _, _, links = cwe.parse(XML)
    assert sorted(l for l in links if l[1] == cwe.TOP10_REL) == [
        ("CWE-74", "owasp_top10", "A03:2021 - Injection"),
        ("CWE-94", "owasp_top10", "A03:2021 - Injection"),
        ("CWE-94", "owasp_top10", "A05:2025 - Injection"),
    ]


def test_parse_maps_owasp_top10_from_groupings_of_cwe_5():
    # CWE 5.0 renamed <Categories>/<Category> to <Groupings>/<Grouping>; names and members are unchanged
    grouped = XML.replace(b"Categories>", b"Groupings>").replace(b"<Category ", b"<Grouping ").replace(b"</Category>", b"</Grouping>")
    _, _, links = cwe.parse(grouped)
    assert sorted(l for l in links if l[1] == cwe.TOP10_REL) == [
        ("CWE-74", "owasp_top10", "A03:2021 - Injection"),
        ("CWE-94", "owasp_top10", "A03:2021 - Injection"),
        ("CWE-94", "owasp_top10", "A05:2025 - Injection"),
    ]


def test_top10_lookup(tmp_path):
    conn = store.connect(tmp_path / "t.db")
    _, records, links = cwe.parse(XML)
    store.replace_source_links(conn, cwe.SOURCE, links)
    assert cwe.top10(conn, "CWE-94") == ["A03:2021 - Injection", "A05:2025 - Injection"]
    assert cwe.top10(conn, "CWE-95") == []
    conn.close()


def test_extract_xml_reads_the_catalogue_from_the_zip():
    assert cwe.extract_xml(_zip(XML)) == XML


def test_sync_loads_then_skips_an_unchanged_catalogue(tmp_path):
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=_zip(XML)))
    with httpx.Client(transport=transport) as client:
        conn = store.connect(tmp_path / "t.db")
        first = cwe.sync(conn, client)
        second = cwe.sync(conn, client)
        conn.close()
    assert "loaded 9.9" in first and "4 weaknesses" in first and "3 OWASP Top 10 memberships" in first
    assert "unchanged" in second


def test_sync_force_reloads_an_unchanged_catalogue(tmp_path):
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=_zip(XML)))
    with httpx.Client(transport=transport) as client:
        conn = store.connect(tmp_path / "t.db")
        cwe.sync(conn, client)
        forced = cwe.sync(conn, client, force=True)
        conn.close()
    assert "loaded" in forced

"""MITRE CWE: weakness definitions, potential mitigations, the parent/child hierarchy and the
OWASP Top 10 categories each CWE belongs to.

Looked up by exact CWE ID. CWE is the hub key: every finding is resolved to CWEs, and the
CWE then links to the other sources.
"""

import io
import re
import xml.etree.ElementTree as ET
import zipfile

import httpx

from app import store
from app.text import squash, truncate

SOURCE = "MITRE CWE"
DOWNLOAD_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
DEFINITION_URL = "https://cwe.mitre.org/data/definitions/{id}.html"
LICENSE = "MITRE CWE Terms of Use: https://cwe.mitre.org/about/termsofuse.html"

# The Research Concepts view (1000) is CWE's canonical parent/child tree.
HIERARCHY_VIEW = "1000"
MITIGATIONS_HEADER = "Potential mitigations"
MAX_MITIGATION_CHARS = 600
# MITRE groups CWEs into OWASP Top Ten categories, e.g.
# "OWASP Top Ten 2021 Category A03:2021 - Injection" (view 1344) and the 2025 edition (view 1450).
TOP10_CATEGORY = re.compile(r"^OWASP Top Ten (2021|2025) Category (A\d\d:\d{4} - .+)$")
TOP10_REL = "owasp_top10"


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(el: ET.Element, name: str) -> ET.Element | None:
    return next((c for c in el if _local(c.tag) == name), None)


def _children(el: ET.Element, name: str) -> list[ET.Element]:
    return [c for c in el if _local(c.tag) == name]


def _text(el: ET.Element | None) -> str:
    return squash(" ".join(el.itertext())) if el is not None else ""


def _mitigations(weakness: ET.Element) -> list[str]:
    """Mitigation lines, Implementation-phase first: those are the ones a code fix can apply."""
    container = _child(weakness, "Potential_Mitigations")
    if container is None:
        return []
    found = []
    for m in _children(container, "Mitigation"):
        description = _text(_child(m, "Description"))
        if not description:
            continue
        phases = [_text(p) for p in _children(m, "Phase")]
        strategy = _text(_child(m, "Strategy"))
        label = "; ".join(phases + ([strategy] if strategy else []))
        line = f"- [{label}] " if label else "- "
        found.append(("Implementation" not in phases, line + truncate(description, MAX_MITIGATION_CHARS)))
    found.sort(key=lambda pair: pair[0])  # stable sort keeps catalogue order within each group
    return [line for _, line in found]


def parse(xml_bytes: bytes) -> tuple[str, list[dict], list[tuple[str, str, str]]]:
    """Return (catalogue version, records, links) from the CWE XML catalogue.

    Links: (CWE, "child_of", parent CWE) and (CWE, "owasp_top10", "A03:2021 - Injection").
    """
    version = "unknown"
    records: list[dict] = []
    links: set[tuple[str, str, str]] = set()
    fetched_at = store.now_iso()

    for event, el in ET.iterparse(io.BytesIO(xml_bytes), events=("start", "end")):
        tag = _local(el.tag)
        if event == "start":
            if tag == "Weakness_Catalog":
                version = f"{el.get('Version')} ({el.get('Date')})"
            continue
        if tag in ("Category", "Grouping"):  # CWE 5.0 (Oct 2026) renamed categories to groupings
            if match := TOP10_CATEGORY.match(el.get("Name", "")):
                for member in el.iter():
                    if _local(member.tag) == "Has_Member" and member.get("CWE_ID"):
                        links.add((f"CWE-{member.get('CWE_ID')}", TOP10_REL, match.group(2)))
            el.clear()
            continue
        if tag != "Weakness":
            continue
        if el.get("Status") == "Deprecated":
            el.clear()
            continue

        cwe_id = el.get("ID")
        key = f"CWE-{cwe_id}"
        name = el.get("Name", "")
        text = f"{key}: {name}\n{_text(_child(el, 'Description'))}"
        mitigations = _mitigations(el)
        if mitigations:
            text += f"\n{MITIGATIONS_HEADER}:\n" + "\n".join(mitigations)
        records.append({
            "key": key, "kind": "cwe", "title": name, "text": text,
            "url": DEFINITION_URL.format(id=cwe_id), "license": LICENSE, "fetched_at": fetched_at,
        })

        related = _child(el, "Related_Weaknesses")
        for rw in _children(related, "Related_Weakness") if related is not None else []:
            if rw.get("Nature") == "ChildOf" and rw.get("View_ID") == HIERARCHY_VIEW:
                links.add((key, "child_of", f"CWE-{rw.get('CWE_ID')}"))
        el.clear()

    return version, records, sorted(links)


def extract_xml(zip_bytes: bytes) -> bytes:
    archive = zipfile.ZipFile(io.BytesIO(zip_bytes))
    name = next(n for n in archive.namelist() if n.endswith(".xml"))
    return archive.read(name)


def sync(conn, client: httpx.Client, force: bool = False) -> str:
    response = client.get(DOWNLOAD_URL)
    response.raise_for_status()
    version, records, links = parse(extract_xml(response.content))

    state = store.get_sync_state(conn, SOURCE)
    if state and state["version"] == version and not force:
        return f"{SOURCE}: unchanged ({version}, {state['item_count']} weaknesses)"

    store.replace_source_records(conn, SOURCE, records)
    store.replace_source_links(conn, SOURCE, links)
    store.set_sync_state(conn, SOURCE, version, len(records))
    conn.commit()
    top10 = sum(1 for link in links if link[1] == TOP10_REL)
    return (f"{SOURCE}: loaded {version}: {len(records)} weaknesses, "
            f"{len(links) - top10} parent links, {top10} OWASP Top 10 memberships")


def top10(conn, cwe: str) -> list[str]:
    """OWASP Top 10 categories (2021 and 2025 editions) a CWE belongs to."""
    return store.linked(conn, cwe, TOP10_REL)

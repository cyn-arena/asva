"""CISA Known Exploited Vulnerabilities (KEV): CVEs confirmed as exploited in the wild.

Synced in bulk (one small JSON file); looked up by exact CVE ID. A KEV hit raises the
urgency of a fix and is flagged in both the prompt and the references.
"""

import httpx

from app import net, store
from app.text import squash, truncate

SOURCE = "CISA KEV"
FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
ENTRY_URL = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}"
LICENSE = "CISA Known Exploited Vulnerabilities Catalog (public U.S. Government data)"


def parse(payload: dict) -> tuple[str, list[dict]]:
    version = f"{payload.get('catalogVersion')} ({payload.get('dateReleased', '')[:10]})"
    fetched_at = store.now_iso()
    records = []
    for v in payload.get("vulnerabilities", []):
        cve = v["cveID"].upper()
        records.append({
            "key": cve, "kind": "kev", "title": v.get("vulnerabilityName"),
            "text": truncate(squash(f"{cve}: {v.get('vulnerabilityName', '')}. {v.get('shortDescription', '')}"), 400),
            "url": ENTRY_URL.format(cve=cve), "license": LICENSE, "fetched_at": fetched_at,
            "data": {"date_added": v.get("dateAdded"), "due_date": v.get("dueDate"),
                     "ransomware": v.get("knownRansomwareCampaignUse"), "vendor": v.get("vendorProject"),
                     "product": v.get("product"), "cwes": v.get("cwes", [])},
        })
    return version, records


def sync(conn, client: httpx.Client, force: bool = False) -> str:
    version, records = parse(net.request(client, "GET", FEED_URL).json())
    state = store.get_sync_state(conn, SOURCE)
    if state and state["version"] == version and not force:
        return f"{SOURCE}: unchanged ({version}, {state['item_count']} CVEs)"
    store.replace_source_records(conn, SOURCE, records)
    store.set_sync_state(conn, SOURCE, version, len(records))
    conn.commit()
    return f"{SOURCE}: loaded catalog {version}: {len(records)} known-exploited CVEs"


def lookup(conn, cve_ids: list[str]) -> dict[str, dict]:
    """CVE -> KEV details, for the CVEs that are in the catalogue."""
    rows = store.get_records(conn, [c.upper() for c in cve_ids], SOURCE)
    return {cve: {**(store.record_data(row) or {}), "name": row["title"], "url": row["url"]} for cve, row in rows.items()}

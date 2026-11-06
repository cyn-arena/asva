"""NVD (National Vulnerability Database): CVE descriptions, CVSS scores, CWE links, references.

Two modes (NVD_SYNC_MODE):
  lazy  CVEs are fetched when a request needs them and cached for NVD_CACHE_DAYS
        (local development, per-run CI containers). A sync only refreshes stale cached CVEs.
  full  a sync downloads the whole NVD once (resumable), then only CVEs modified since the
        last sync (Kubernetes, always-on). Requests still fetch any CVE that is missing.

The API has outages (HTTP 503), so every call retries with backoff; a CVE that still can't be
fetched becomes a warning and cached data is used where available.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import httpx

from app import config, net, store
from app.text import squash, truncate

SOURCE = "NVD"
API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DETAIL_URL = "https://nvd.nist.gov/vuln/detail/{cve}"
LICENSE = "This product uses the NVD API but is not endorsed or certified by the NVD."
PAGE_SIZE = 2000
MAX_WINDOW_DAYS = 120  # NVD's limit for lastModStartDate..lastModEndDate
METRIC_PREFERENCE = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2")

# NVD allows 50 requests per 30 s with an API key, 5 without.
_limiters = {True: net.RateLimiter(45, 30), False: net.RateLimiter(5, 30)}


def _limiter() -> net.RateLimiter:
    return _limiters[bool(config.NVD_API_KEY)]


def _headers() -> dict[str, str]:
    return {"apiKey": config.NVD_API_KEY} if config.NVD_API_KEY else {}


def parse_cve(cve: dict) -> tuple[dict, list[tuple[str, str, str]]]:
    """One NVD CVE object -> (record, CVE->CWE links)."""
    cve_id = cve["id"].upper()
    description = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")

    score = severity = vector = cvss_version = None
    metrics = cve.get("metrics", {})
    for key in METRIC_PREFERENCE:
        entries = [m for m in metrics.get(key, []) if m.get("cvssData")]
        if entries:
            best = next((m for m in entries if m.get("type") == "Primary"), entries[0])
            data = best["cvssData"]
            score, vector = data.get("baseScore"), data.get("vectorString")
            severity = data.get("baseSeverity") or best.get("baseSeverity")
            cvss_version = data.get("version")
            break

    cwes: list[str] = []
    for weakness in sorted(cve.get("weaknesses", []), key=lambda w: w.get("type") != "Primary"):
        for d in weakness.get("description", []):
            value = d.get("value", "")
            if value.startswith("CWE-") and value not in cwes:
                cwes.append(value)

    head = f"CVSS {score} {severity}" if score is not None else "no CVSS score"
    if cwes:
        head += ", " + ", ".join(cwes)
    record = {
        "key": cve_id, "kind": "cve", "title": truncate(squash(description), 160),
        "text": f"{cve_id} ({head}): {squash(description)}",
        "url": DETAIL_URL.format(cve=cve_id), "license": LICENSE, "fetched_at": store.now_iso(),
        "data": {"cvss": score, "severity": severity, "vector": vector, "cvss_version": cvss_version, "cwes": cwes,
                 "published": cve.get("published"), "last_modified": cve.get("lastModified"),
                 "status": cve.get("vulnStatus"), "references": [r["url"] for r in cve.get("references", [])[:5]]},
    }
    return record, [(cve_id, "has_cwe", cwe) for cwe in cwes]


def fetch(client: httpx.Client, cve_id: str) -> dict | None:
    """One CVE from the API (None if NVD doesn't know it). Raises net.LookupFailed."""
    response = net.request(client, "GET", API_URL, params={"cveId": cve_id}, headers=_headers(),
                           limiter=_limiter(), ok_statuses=(404,))
    if response.status_code == 404:
        return None
    vulnerabilities = response.json().get("vulnerabilities", [])
    return vulnerabilities[0]["cve"] if vulnerabilities else None


def _store(conn, cves: list[dict]) -> None:
    for cve in cves:
        record, links = parse_cve(cve)
        store.upsert_records(conn, SOURCE, [record])
        store.replace_links_from(conn, SOURCE, record["key"], links)


def lookup(conn, client: httpx.Client | None, cve_ids: list[str], warnings: list[str], *,
           online: bool = True, max_age: timedelta | None = None) -> dict[str, dict]:
    """CVE -> parsed record data (plus text/url), fetching missing or stale CVEs when online."""
    ids = list(dict.fromkeys(c.upper() for c in cve_ids if c))
    max_age = timedelta(days=config.NVD_CACHE_DAYS) if max_age is None else max_age
    rows = store.get_records(conn, ids, SOURCE)
    to_fetch = [i for i in ids if not store.is_fresh(rows.get(i), max_age)]

    if to_fetch and online and client is not None:
        def safe_fetch(cve_id):
            try:
                return cve_id, fetch(client, cve_id), None
            except net.LookupFailed as error:
                return cve_id, None, str(error)

        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(safe_fetch, to_fetch))
        _store(conn, [cve for _, cve, _ in results if cve])
        conn.commit()
        failed = [cve_id for cve_id, _, error in results if error]
        if failed:
            warnings.append(f"NVD unavailable for {len(failed)} CVE(s) (e.g. {failed[0]}); cached data used where available")
        rows = store.get_records(conn, ids, SOURCE)
    elif to_fetch:
        missing = [i for i in to_fetch if i not in rows]
        if missing:
            warnings.append(f"{len(missing)} CVE(s) not in the local NVD data and online lookups are off (e.g. {missing[0]})")

    return {cve_id: {**(store.record_data(row) or {}), "id": cve_id, "text": row["text"], "title": row["title"],
                     "url": row["url"], "license": row["license"]} for cve_id, row in rows.items()}


# ---------------------------------------------------------------------------
# sync
# ---------------------------------------------------------------------------

def _nvd_time(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%S.000") + "+00:00"


def _download(conn, client: httpx.Client, params: dict, start_index: int = 0, progress_source: str | None = None) -> int:
    """Page through an NVD query, storing every CVE. Returns how many were stored."""
    stored, total = 0, None
    while total is None or start_index < total:
        page = net.request(client, "GET", API_URL, params={**params, "resultsPerPage": PAGE_SIZE, "startIndex": start_index},
                           headers=_headers(), limiter=_limiter(), retries=5).json()
        total = page.get("totalResults", 0)
        cves = [v["cve"] for v in page.get("vulnerabilities", [])]
        _store(conn, cves)
        stored += len(cves)
        start_index += PAGE_SIZE
        if progress_source:  # resumable full download
            store.set_sync_state(conn, progress_source, f"partial {min(start_index, total)}/{total}", stored)
        conn.commit()
        if not cves:
            break
    return stored


def sync(conn, client: httpx.Client, mode: str = config.NVD_SYNC_MODE, force: bool = False) -> str:
    started = datetime.now(timezone.utc)
    if mode == "lazy":
        max_age = timedelta(days=config.NVD_CACHE_DAYS)
        rows = conn.execute("SELECT key, fetched_at FROM records WHERE source = ?", (SOURCE,)).fetchall()
        stale = [r["key"] for r in rows if force or not store.is_fresh(r, max_age)]
        warnings: list[str] = []
        lookup(conn, client, stale, warnings, max_age=timedelta(0))
        store.set_sync_state(conn, SOURCE, "lazy (on demand)", len(rows))
        conn.commit()
        note = f"; {warnings[0]}" if warnings else ""
        return f"{SOURCE}: lazy mode, {len(rows)} cached CVEs, {len(stale)} refreshed{note}"

    state = store.get_sync_state(conn, SOURCE)
    if force or not state or not (state["version"] or "").startswith("full"):
        resume = 0
        if state and not force and (state["version"] or "").startswith("partial "):
            resume = int(state["version"].split()[1].split("/")[0])
        stored = _download(conn, client, {}, start_index=resume, progress_source=SOURCE)
        total = conn.execute("SELECT COUNT(*) FROM records WHERE source = ?", (SOURCE,)).fetchone()[0]
        store.set_sync_state(conn, SOURCE, "full", total, synced_at=started.strftime(store.ISO))
        conn.commit()
        return f"{SOURCE}: full download complete ({stored} CVEs this run, {total} stored)"

    since = store.parse_iso(state["synced_at"]) - timedelta(hours=2)  # overlap for safety
    stored = 0
    while since < started:
        until = min(since + timedelta(days=MAX_WINDOW_DAYS), started)
        stored += _download(conn, client, {"lastModStartDate": _nvd_time(since), "lastModEndDate": _nvd_time(until)})
        since = until
    total = conn.execute("SELECT COUNT(*) FROM records WHERE source = ?", (SOURCE,)).fetchone()[0]
    store.set_sync_state(conn, SOURCE, "full", total, synced_at=started.strftime(store.ISO))
    conn.commit()
    return f"{SOURCE}: incremental update, {stored} CVEs added or modified since the last sync ({total} stored)"

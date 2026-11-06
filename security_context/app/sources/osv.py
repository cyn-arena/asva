"""OSV.dev: affected and fixed version ranges per package (it includes the GitHub Advisory Database
and the Linux distributions' own security data).

Queried when a request needs it, cached for OSV_CACHE_HOURS. Used to cross-check Snyk's upgrade
targets, to list advisories a target version still leaves open, and, for OS packages in a
container image, to say in which release of the distribution a fix is published (and whether
only to paying subscribers).
"""

import re
from datetime import timedelta

import httpx

from app import config, net, store, versions
from app.text import squash, truncate

SOURCE = "OSV.dev"
QUERY_URL = "https://api.osv.dev/v1/query"
VULN_URL = "https://osv.dev/vulnerability/{id}"
LICENSE = "OSV.dev data; licence per upstream source (GitHub advisories: CC BY 4.0)"

# ASVA/Snyk ecosystem names -> OSV ecosystem names
ECOSYSTEMS = {"npm": "npm", "pip": "PyPI", "pypi": "PyPI", "maven": "Maven", "nuget": "NuGet",
              "rubygems": "RubyGems", "gem": "RubyGems", "go": "Go", "golang": "Go",
              "cargo": "crates.io", "composer": "Packagist"}


def osv_ecosystem(ecosystem: str | None) -> str | None:
    return ECOSYSTEMS.get((ecosystem or "").lower())


def _fixed_versions(vuln: dict, name: str, ecosystem: str, current: str) -> list[str]:
    """Every version listed as fixing `vuln` for name@current, smallest first (a vulnerability
    is often fixed separately in each maintained major version)."""
    candidates = []
    for affected in vuln.get("affected", []):
        package = affected.get("package", {})
        if package.get("name") != name or package.get("ecosystem") != ecosystem:
            continue
        for rng in affected.get("ranges", []):
            for event in rng.get("events", []):
                fixed = event.get("fixed")
                if fixed and versions.is_newer(fixed, current):
                    candidates.append(fixed)
    parsed = sorted({(versions.parse(v), v) for v in candidates if versions.parse(v)})
    return [v for _, v in parsed]


def parse(payload: dict, name: str, ecosystem: str, current: str) -> list[dict]:
    advisories = []
    for vuln in payload.get("vulns", []):
        specific = vuln.get("database_specific") or {}
        fixed_versions = _fixed_versions(vuln, name, ecosystem, current)
        advisories.append({
            "id": vuln["id"], "aliases": vuln.get("aliases") or [],
            "summary": truncate(squash(vuln.get("summary") or vuln.get("details") or ""), 160),
            "severity": specific.get("severity"), "cwes": specific.get("cwe_ids", []),
            "fixed": fixed_versions[0] if fixed_versions else None,  # the smallest version that fixes it
            "fixed_versions": fixed_versions,
            "url": VULN_URL.format(id=vuln["id"]),
        })
    return advisories


def advisories(conn, client: httpx.Client | None, name: str, version: str, ecosystem: str, warnings: list[str], *,
               online: bool = True, max_age: timedelta | None = None) -> list[dict] | None:
    """Known advisories for name@version, or None if OSV couldn't be asked."""
    max_age = timedelta(hours=config.OSV_CACHE_HOURS) if max_age is None else max_age
    key = f"{ecosystem}:{name}@{version}"
    row = store.get_record(conn, key, SOURCE)
    if store.is_fresh(row, max_age) or not online or client is None:
        return store.record_data(row)
    try:
        payload = net.request(client, "POST", QUERY_URL,
                              json={"package": {"name": name, "ecosystem": ecosystem}, "version": version}).json()
    except net.LookupFailed:
        warnings.append(f"OSV.dev unavailable for {name}@{version}; cached data used where available")
        return store.record_data(row)
    found = parse(payload, name, ecosystem, version)
    store.upsert_records(conn, SOURCE, [{
        "key": key, "kind": "osv_package", "title": f"{name}@{version}",
        "text": f"{len(found)} advisories for {name}@{version}", "url": f"https://osv.dev/list?q={name}",
        "license": LICENSE, "data": found,
    }])
    conn.commit()
    return found


# ---------------------------------------------------------------------------
# Distribution advisories: where an OS package fix is published
# ---------------------------------------------------------------------------

VULN_API_URL = "https://api.osv.dev/v1/vulns/{id}"
# OSV republishes each distribution's own security data per CVE under these ids.
DISTRO_ADVISORY_PREFIX = {"ubuntu": "UBUNTU-", "debian": "DEBIAN-", "alpine": "ALPINE-"}
_RELEASE = re.compile(r"^v?(\d+(?:\.\d+)*)$")  # "20.04" (Ubuntu), "12" (Debian), "v3.20" (Alpine)


def parse_distro_fixes(vuln: dict, package: str | None = None) -> dict[str, dict]:
    """A distribution advisory -> {release: {"fixed", "availability", "subscription_only"}}.

    Ubuntu's data lists a fix per release ("Ubuntu:22.04:LTS") and, when it is published only
    to Ubuntu Pro subscribers (ESM), under "Ubuntu:Pro:20.04:LTS" with the availability text
    "Available with Ubuntu Pro ...". A release's standard entry wins over its Pro entries.
    Debian ("Debian:12") and Alpine ("Alpine:v3.20") list one entry per release.
    `fixed` is None for a release that is listed as affected but has no fix yet; a release
    that is not affected at all is simply absent."""
    releases: dict[str, tuple[int, dict]] = {}
    for affected in vuln.get("affected", []):
        details = affected.get("package", {})
        if package and details.get("name") != package:
            continue
        parts = details.get("ecosystem", "").split(":")
        named = next((p for p in parts[1:] if _RELEASE.match(p)), None)
        fixed = next((e["fixed"] for r in affected.get("ranges", []) for e in r.get("events", []) if e.get("fixed")), None)
        if not named:
            continue
        release = _RELEASE.match(named).group(1)
        flavour = [p for p in parts[1:] if p != named and p != "LTS"]
        rank = 0 if not flavour else 1 if flavour == ["Pro"] else 2  # standard, Ubuntu Pro, other Pro variants
        entry = {"fixed": fixed, "availability": (affected.get("ecosystem_specific") or {}).get("availability"),
                 "subscription_only": rank > 0}
        if release not in releases or rank < releases[release][0]:
            releases[release] = (rank, entry)
    return {release: entry for release, (_, entry) in releases.items()}


def newer_release_fixes(releases: dict[str, dict], release: str | None) -> dict[str, str]:
    """Fixes in the standard packages of releases newer than `release`: {release: fixed version}."""
    def number(name: str) -> tuple[int, ...]:
        return tuple(int(part) for part in name.split("."))

    current = _RELEASE.match(release or "")
    if not current:
        return {}
    return {name: entry["fixed"] for name, entry in sorted(releases.items(), key=lambda kv: number(kv[0]))
            if number(name) > number(current.group(1)) and entry["fixed"] and not entry["subscription_only"]}


def distro_fixes(conn, client: httpx.Client | None, cve: str, distro: str, package: str | None, warnings: list[str], *,
                 online: bool = True, max_age: timedelta | None = None) -> dict | None:
    """Where the fix for `cve` in `package` is published, per release of `distro`:
    {"id", "url", "releases": {...}}; None if the distribution isn't covered or OSV couldn't be asked."""
    prefix = DISTRO_ADVISORY_PREFIX.get((distro or "").lower())
    if not prefix or not cve:
        return None
    max_age = timedelta(hours=config.OSV_CACHE_HOURS) if max_age is None else max_age
    advisory_id = f"{prefix}{cve.upper()}"
    key = f"distro:{advisory_id}:{package or '*'}"
    row = store.get_record(conn, key, SOURCE)
    if store.is_fresh(row, max_age) or not online or client is None:
        return store.record_data(row)
    try:
        response = net.request(client, "GET", VULN_API_URL.format(id=advisory_id), ok_statuses=(404,))
    except net.LookupFailed:
        warnings.append(f"OSV.dev unavailable for {advisory_id}; cached data used where available")
        return store.record_data(row)
    data = {"id": advisory_id, "url": VULN_URL.format(id=advisory_id),
            "releases": parse_distro_fixes(response.json(), package) if response.status_code == 200 else {}}
    store.upsert_records(conn, SOURCE, [{
        "key": key, "kind": "osv_distro", "title": advisory_id,
        "text": f"{advisory_id}: fixes listed for {len(data['releases'])} release(s)", "url": data["url"],
        "license": LICENSE, "data": data}])
    conn.commit()
    return data

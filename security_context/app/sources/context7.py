"""Context7: current library documentation, used for breaking changes in major upgrades.

Compatibility context only, not a security authority. A package is resolved to a Context7
library, then Context7 is asked for the breaking changes between the two versions. Both answers
are cached (CONTEXT7_CACHE_DAYS). Without CONTEXT7_API_KEY this source is skipped.

Finding the library: Context7's own name search picks another project for some packages
(measured on 14 Oct 2026: 3 of 8, e.g. "mongodb" gives the MongoDB server manual, not the
Node.js driver; evaluation/context7_library_lookup_without_npm.txt). So for an npm package the
library is taken from the repository address in the package's registry entry, and the name
search is the fallback. That address is a lookup key only: nothing from the registry goes
into an answer.
"""

import hashlib
import re
from datetime import timedelta

import httpx

from app import config, net, store, versions
from app.text import squash

SOURCE = "Context7"
SEARCH_URL = "https://context7.com/api/v2/libs/search"
CONTEXT_URL = "https://context7.com/api/v2/context"
NPM_PACKAGE_URL = "https://registry.npmjs.org/{name}/latest"  # read for its "repository" address only
LICENSE = "Library documentation via Context7 (https://context7.com); see each source link"
SEPARATOR = re.compile(r"\n-{10,}\n")
_GITHUB = re.compile(r"github\.com[/:]([^/]+)/([^/#]+?)(?:\.git)?(?:[#/].*)?$")
# A version-specific changelog/migration file, e.g. ".../etc/notes/CHANGES_7.0.0.md" -> 7
_VERSIONED_NOTES = re.compile(r"(?:changes|changelog|migrat\w*|upgrad\w*|releases?|history|breaking)[\w-]*?[_-]v?(\d+)\.\d+",
                              re.IGNORECASE)


def in_range(snippets: list[dict], current: str, target: str) -> list[dict]:
    """Drop snippets from changelogs of versions outside (current, target] (e.g. 7.0 notes for a 2.x -> 3.x upgrade)."""
    low, high = versions.parse(current), versions.parse(target)
    if not low or not high or low[0] == high[0]:
        return snippets
    kept = []
    for snippet in snippets:
        match = _VERSIONED_NOTES.search(snippet["source"].rsplit("/", 1)[-1])
        if not match or low[0] < int(match.group(1)) <= high[0]:
            kept.append(snippet)
    return kept


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {config.CONTEXT7_API_KEY}"}


def parse_snippets(text: str) -> list[dict]:
    """Context7 text -> [{"title", "source", "description"}], one per snippet, deduplicated."""
    snippets, seen = [], set()
    for block in SEPARATOR.split(text):
        lines = block.strip().splitlines()
        title = next((l[4:].strip() for l in lines if l.startswith("### ")), "")
        source = next((l[len("Source:"):].strip() for l in lines if l.startswith("Source:")), "")
        prose, started = [], False
        for line in lines:
            if line.startswith("Source:"):
                started = True
                continue
            if not started or not line.strip():
                if prose:
                    break
                continue
            if line.startswith(("```", "#")):
                break
            prose.append(line.strip())
        description = squash(" ".join(prose))
        if title and description and title.lower() not in seen:
            seen.add(title.lower())
            snippets.append({"title": title, "source": source, "description": description})
    return snippets


def _library_from_repository(client: httpx.Client, package: str) -> str | None:
    """An npm package's library: "/owner/repository" from the repository address in its registry
    entry, or None (unknown package, no GitHub repository, or the registry couldn't be asked)."""
    try:
        response = net.request(client, "GET", NPM_PACKAGE_URL.format(name=package), ok_statuses=(404,), retries=1)
    except net.LookupFailed:
        return None
    repository = (response.json() if response.status_code == 200 else {}).get("repository")
    address = repository.get("url", "") if isinstance(repository, dict) else (repository or "")
    match = _GITHUB.search(address)
    return f"/{match.group(1)}/{match.group(2)}" if match else None


def _library_from_search(client: httpx.Client, package: str) -> str | None:
    results = net.request(client, "GET", SEARCH_URL, params={"libraryName": package, "query": f"{package} library"},
                          headers=_headers(), retries=1).json().get("results", [])
    return results[0]["id"] if results else None


def resolve_library(conn, client: httpx.Client, package: str, ecosystem: str, *, max_age: timedelta) -> str | None:
    key = f"library:{ecosystem}:{package}"
    row = store.get_record(conn, key, SOURCE)
    if store.is_fresh(row, max_age):
        return (store.record_data(row) or {}).get("library_id")
    library = ((_library_from_repository(client, package) if ecosystem == "npm" else None)
               or _library_from_search(client, package))
    store.upsert_records(conn, SOURCE, [{"key": key, "kind": "library_id", "title": package,
                                         "text": f"{package} -> {library}", "license": LICENSE,
                                         "data": {"library_id": library}}])
    conn.commit()
    return library


def upgrade_notes(conn, client: httpx.Client | None, package: str, ecosystem: str, current: str, target: str,
                  warnings: list[str], *, online: bool = True, max_age: timedelta | None = None) -> dict | None:
    """Breaking changes between two versions: {"library_id", "query", "snippets": [...]}, or None."""
    if not config.CONTEXT7_API_KEY:
        return None
    notes = _cached_or_fetched_notes(conn, client, package, ecosystem, current, target, warnings, online,
                                     timedelta(days=config.CONTEXT7_CACHE_DAYS) if max_age is None else max_age)
    return notes and {**notes, "snippets": in_range(notes["snippets"], current, target)}


def _cached_or_fetched_notes(conn, client, package, ecosystem, current, target, warnings, online, max_age) -> dict | None:
    query = f"breaking changes when upgrading from {versions.major_label(current)} to {versions.major_label(target)}"
    cache_key = f"notes:{ecosystem}:{package}:{hashlib.sha1(query.encode()).hexdigest()[:12]}"
    row = store.get_record(conn, cache_key, SOURCE)
    if store.is_fresh(row, max_age) or not online or client is None:
        return store.record_data(row)
    try:
        library = resolve_library(conn, client, package, ecosystem, max_age=max_age)
        if not library:
            return None
        response = net.request(client, "GET", CONTEXT_URL, params={"libraryId": library, "query": query},
                               headers=_headers(), ok_statuses=(404,), retries=2)
    except net.LookupFailed:
        warnings.append(f"Context7 unavailable for {package}; no upgrade notes")
        return store.record_data(row)
    snippets = parse_snippets(response.text) if response.status_code == 200 else []
    notes = {"library_id": library, "query": query, "snippets": snippets}
    store.upsert_records(conn, SOURCE, [{"key": cache_key, "kind": "library_notes", "title": f"{package} {query}",
                                         "text": f"{len(snippets)} snippets from {library}", "license": LICENSE,
                                         "url": f"https://context7.com{library}", "data": notes}])
    conn.commit()
    return notes

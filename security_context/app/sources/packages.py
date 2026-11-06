"""Package registries (PyPI, npm): which versions of a package exist and what each one requires.

Version metadata only, not a security authority. Used by the trial plan (app/trials.py) to say
what else a held-back major upgrade needs (cryptography 49.0.0 requires cffi>=2.0.0) and
whether a newer version of a parent package brings fixed copies of what it depends on.
Looked up per package when a plan needs it and cached (PACKAGES_CACHE_HOURS).
"""

from datetime import timedelta

import httpx
from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from app import config, net, store

SOURCE = "Package registries"
PYPI_PROJECT_URL = "https://pypi.org/pypi/{name}/json"
PYPI_RELEASE_URL = "https://pypi.org/pypi/{name}/{version}/json"
NPM_URL = "https://registry.npmjs.org/{name}"
NPM_ABBREVIATED = "application/vnd.npm.install-v1+json"  # versions and their dependencies only
LICENSE = "Package metadata from PyPI (https://pypi.org) and the npm registry (https://www.npmjs.com)"
ECOSYSTEMS = {"pip": "pip", "pypi": "pip", "npm": "npm"}


def ecosystem_of(ecosystem: str | None) -> str | None:
    return ECOSYSTEMS.get((ecosystem or "").lower())


def _fetch(conn, client: httpx.Client | None, key: str, url: str, warnings: list[str], *, online: bool,
           headers: dict | None = None, shape=None) -> dict | None:
    """A registry answer (reduced by `shape` before it is cached), or None if unknown or not asked."""
    row = store.get_record(conn, key, SOURCE)
    if store.is_fresh(row, timedelta(hours=config.PACKAGES_CACHE_HOURS)) or not online or client is None:
        return store.record_data(row)
    try:
        response = net.request(client, "GET", url, headers=headers, ok_statuses=(404,), retries=1)
    except net.LookupFailed:
        warnings.append(f"{SOURCE} unavailable for {key.split(':', 1)[1]}; cached data used where available")
        return store.record_data(row)
    data = shape(response.json()) if response.status_code == 200 else {}
    store.upsert_records(conn, SOURCE, [{"key": key, "kind": "package_metadata", "title": key.split(":", 1)[1],
                                         "text": key, "url": url, "license": LICENSE, "data": data}])
    conn.commit()
    return data


def _stable(version: str) -> Version | None:
    try:
        parsed = Version(version)
    except InvalidVersion:
        return None
    return None if parsed.is_prerelease or parsed.is_devrelease else parsed


def _pypi_versions(body: dict) -> dict:
    releases = body.get("releases") or {}
    usable = [v for v, files in releases.items() if files and not all(f.get("yanked") for f in files) and _stable(v)]
    return {"versions": sorted(usable, key=_stable)}


def _pypi_requires(body: dict) -> dict:
    """Requirements that apply to a normal install: extras-only ones are left out."""
    requires = []
    for line in (body.get("info") or {}).get("requires_dist") or []:
        try:
            requirement = Requirement(line)
        except InvalidRequirement:
            continue
        if requirement.marker and "extra" in str(requirement.marker):
            continue
        requires.append([canonicalize_name(requirement.name), str(requirement.specifier)])
    return {"requires": requires, "requires_python": (body.get("info") or {}).get("requires_python")}


def _npm_versions(body: dict) -> dict:
    """Every stable version with its runtime dependencies (devDependencies are not installed by users)."""
    found = {}
    for version, meta in (body.get("versions") or {}).items():
        if "-" not in version:
            found[version] = {"requires": [[name, spec] for name, spec in (meta.get("dependencies") or {}).items()]}
    return {"versions": found}


def published(conn, client, ecosystem: str, name: str, warnings: list[str], *, online: bool = True) -> list[str] | None:
    """Stable published versions, oldest first (None if the registry could not be asked)."""
    eco = ecosystem_of(ecosystem)
    if eco == "pip":
        data = _fetch(conn, client, f"pypi:{canonicalize_name(name)}", PYPI_PROJECT_URL.format(name=name), warnings,
                      online=online, shape=_pypi_versions)
        return None if data is None else data.get("versions", [])
    if eco == "npm":
        data = _npm(conn, client, name, warnings, online)
        return None if data is None else sorted(data.get("versions", {}), key=_npm_key)
    return None


def requirements(conn, client, ecosystem: str, name: str, version: str, warnings: list[str], *,
                 online: bool = True) -> list[tuple[str, str]] | None:
    """[(dependency, version specifier)] of one published version (None if unknown)."""
    eco = ecosystem_of(ecosystem)
    if eco == "pip":
        data = _fetch(conn, client, f"pypi:{canonicalize_name(name)}@{version}",
                      PYPI_RELEASE_URL.format(name=name, version=version), warnings, online=online, shape=_pypi_requires)
        return None if not data else [tuple(r) for r in data.get("requires", [])]
    if eco == "npm":
        data = _npm(conn, client, name, warnings, online)
        meta = (data or {}).get("versions", {}).get(version)
        return None if meta is None else [tuple(r) for r in meta.get("requires", [])]
    return None


def _npm(conn, client, name: str, warnings: list[str], online: bool) -> dict | None:
    return _fetch(conn, client, f"npm:{name}", NPM_URL.format(name=name.replace("/", "%2F")), warnings,
                  online=online, headers={"Accept": NPM_ABBREVIATED}, shape=_npm_versions)


def _npm_key(version: str) -> tuple:
    try:
        return tuple(int(p) for p in version.split("+")[0].split("."))
    except ValueError:
        return (0,)

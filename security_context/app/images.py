"""Container images: what a file's container findings say about the image, and which newer
release line could resolve them.

Pure functions over data the sources returned (the scanner's findings, OSV.dev's per-release
fix data, Docker Hub's image lines, endoflife.date's support dates). Nothing here states a
fact a source did not give; the judgements, which line is a compatible fix and which is the
migration target, follow fixed rules (see `compatible` and `suggest`).
"""

import re
from collections import Counter
from datetime import date, timedelta

from app import versions
from app.sources import registry

MIN_AGE_DAYS = 90  # a release line younger than this is listed but not suggested
MIN_SUPPORT_LEFT_DAYS = 180  # nor is one that leaves support within this time
MAX_LISTED_PACKAGES = 6
_SNYK_DISTRO = re.compile(r"^SNYK-([A-Z]+?)(\d+)-")
_RELEASE_NAMES = {
    "debian": {release: name for name, release in registry.DEBIAN_RELEASES.items()},
    "ubuntu": {"16.04": "xenial", "18.04": "bionic", "20.04": "focal", "22.04": "jammy", "24.04": "noble"},
}
_DISTRO_NAMES = {"ubuntu": "Ubuntu", "debian": "Debian", "alpine": "Alpine"}


def release_name(distro: str | None, release: str | None) -> str | None:
    """What a release is called in an image tag: "bookworm", "noble", "alpine3.20". None if unknown."""
    family = (distro or "").lower()
    if family == "alpine":
        return f"alpine{release}" if release else None
    return _RELEASE_NAMES.get(family, {}).get(release or "")


def distro_of(findings: list[dict]) -> tuple[str, str] | None:
    """("ubuntu", "20.04") from a Snyk container rule id such as SNYK-UBUNTU2004-PERL-16800832."""
    for finding in findings:
        match = _SNYK_DISTRO.match(finding.get("rule_id") or "")
        if not match:
            continue
        name, digits = match.group(1).lower(), match.group(2)
        if name == "ubuntu" and len(digits) == 4:
            return name, f"{digits[:2]}.{digits[2:]}"
        if name == "alpine" and len(digits) >= 2:
            return name, f"{digits[0]}.{digits[1:]}"
        return name, digits
    return None


def os_label(distro: str | None, release: str | None) -> str | None:
    if not release:
        return None
    return f"{_DISTRO_NAMES.get(distro or '', (distro or 'base OS').capitalize())} {release}"


def image_of(findings: list[dict]) -> tuple[str | None, str | None]:
    """The scanned image (name, tag), from the first finding that names it."""
    for finding in findings:
        if finding.get("image_name"):
            return finding["image_name"], finding.get("image_tag")
    return None, None


def package_summary(findings: list[dict]) -> tuple[int, int, str]:
    """(distinct CVEs, distinct OS packages, "perl ×3, gnutls28 ×2 ...")."""
    packages = Counter(versions.split_package(f.get("package"))[0] or "?" for f in findings)
    cves = {f["cve"] for f in findings if f.get("cve")}
    listed = ", ".join(f"{name} ×{n}" if n > 1 else name for name, n in packages.most_common(MAX_LISTED_PACKAGES))
    if len(packages) > MAX_LISTED_PACKAGES:
        listed += f" +{len(packages) - MAX_LISTED_PACKAGES} more"
    return len(cves), len(packages), listed


def scanner_offers_nothing_newer(finding: dict) -> bool:
    """The scanner's 'upgrade' is the installed version (or a prefix of it), or it has none."""
    if finding.get("fixable") is False:
        return True
    _, installed = versions.split_package(finding.get("package"))
    _, offered = versions.split_package(finding.get("upgrade_to"))
    return bool(installed and offered and (installed == offered or installed.startswith(offered)))


def release_status(fixes: list[dict | None], release: str | None) -> dict:
    """Where the checked CVEs stand for one OS release:
      standard      fixed in the release's standard repositories
      subscription  fixed only for subscribers (`availability`: the source's wording)
      unfixed       listed as affected, no fix published
      not_listed    the release is not listed as affected (it ships a version that never was)
    A release that appears in none of the advisories is one the distribution's data does not
    track (for example, one past its support): nothing is counted for it, because "not listed"
    would then say nothing about whether it is affected.
    """
    status = {"checked": 0, "standard": 0, "subscription": 0, "unfixed": 0, "not_listed": 0, "availability": None}
    if not any((release or "") in (fix.get("releases") or {}) for fix in fixes if fix):
        return status
    for fix in fixes:
        if not fix or not fix.get("releases"):
            continue
        status["checked"] += 1
        entry = fix["releases"].get(release or "")
        if not entry:
            status["not_listed"] += 1
        elif not entry["fixed"]:
            status["unfixed"] += 1
        elif entry["subscription_only"]:
            status["subscription"] += 1
            status["availability"] = status["availability"] or entry.get("availability")
        else:
            status["standard"] += 1
    return status


def ended_on(cycle: dict | None, today: date) -> str | bool | None:
    """For one release line's support data: the date it went past end of life (True when the
    source gives no date), False while it is supported, None when unknown."""
    eol = (cycle or {}).get("eol")
    eol_date = _parse_date(eol)
    if eol_date:
        return eol if eol_date <= today else False
    return eol if isinstance(eol, bool) else None


def _parse_date(value) -> date | None:
    try:
        return date.fromisoformat(value) if isinstance(value, str) else None
    except ValueError:
        return None


def candidates(lines: dict | None, lifecycle: dict | None, fixes: list[dict | None], distro: str | None,
               today: date) -> list[dict]:
    """The image's newer release lines with the facts for choosing one: the version each tag
    ships, its base OS, how many of the checked CVEs that OS resolves (fixed in its standard
    repositories, or not affected), and its support dates."""
    found = []
    for line in (lines or {}).get("newer") or []:
        cycle = (lifecycle or {}).get(line.get("line") or line["tag"]) or {}
        eol = cycle.get("eol")
        eol_date = _parse_date(eol)
        status = release_status(fixes, line.get("base_release"))
        found.append({
            "tag": line["tag"], "version": line.get("version"),
            "base_os": os_label(line.get("base_distro") or distro, line.get("base_release")),
            "base_release": line.get("base_release"),
            "released": cycle.get("released"),
            "supported_until": eol if eol_date else None,
            "end_of_life": (eol_date <= today) if eol_date else (eol if isinstance(eol, bool) else None),
            "cves_resolved": status["standard"] + status["not_listed"] if status["checked"] else None,
            "cves_checked": status["checked"] or None,
        })
    return found


def _resolves(line: dict, current_release: str | None) -> bool:
    """The line's base OS resolves every checked CVE; when no CVE could be checked, it is at
    least a different OS release than the current image's."""
    if line["cves_checked"]:
        return line["cves_resolved"] == line["cves_checked"]
    return bool(line["base_release"]) and line["base_release"] != current_release


def _eligible(found: list[dict], current_release: str | None, today: date) -> list[tuple]:
    """Lines that are supported for at least MIN_SUPPORT_LEFT_DAYS more, at least MIN_AGE_DAYS
    old and resolve the CVEs, each as (supported until, released, line). Support dates must be
    known: a line is never put forward on its version number alone."""
    eligible = []
    for line in found:
        released, until = _parse_date(line["released"]), _parse_date(line["supported_until"])
        if line["end_of_life"] is not False or not until or not released:
            continue
        if released > today - timedelta(days=MIN_AGE_DAYS) or until < today + timedelta(days=MIN_SUPPORT_LEFT_DAYS):
            continue
        if not _resolves(line, current_release):
            continue
        eligible.append((until, released, line))
    return eligible


def compatible(found: list[dict], current_tag: str | None, current_release: str | None) -> dict | None:
    """A line of the same major version as the current tag that resolves the checked CVEs and
    is not past end of life: the fix that is not a breaking change. The newest one, if several."""
    same = [line for line in found if versions.same_major(line["tag"], current_tag)
            and line["end_of_life"] is not True and line["cves_checked"] and _resolves(line, current_release)]
    return max(same, key=lambda line: versions.parse(line["tag"])) if same else None


def suggest(found: list[dict], current_release: str | None, today: date) -> dict | None:
    """The migration target, by a fixed rule: the nearest eligible line (see _eligible), i.e. the
    smallest version jump that resolves the CVEs and is still supported. None if no line
    qualifies or support dates are unknown."""
    eligible = _eligible(found, current_release, today)
    return min(eligible, key=lambda entry: versions.parse(entry[2]["tag"]) or (0, 0, 0))[2] if eligible else None


def longest_supported(found: list[dict], current_release: str | None, today: date) -> dict | None:
    """The eligible line supported longest; on a tie, the longer-established one."""
    eligible = _eligible(found, current_release, today)
    return max(eligible, key=lambda entry: (entry[0], -entry[1].toordinal()))[2] if eligible else None

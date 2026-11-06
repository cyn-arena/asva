"""The trial plan: held-back upgrades to try one at a time, each with what it fixes and what else
it needs. It is for the person (or a later pipeline step) who tries them, and never goes into
the LLM prompt.

Why: "no major version change" keeps the app working but also holds back upgrades that would have
worked. Only building and testing tells them apart (on PyGoat, 4 of the 7 held back worked on
their own). So the held-back upgrades are listed in the order to try them:

  lockfile_refresh  npm: `npm update` of vulnerable packages that only come in through others
                    (versions within the ranges their parents allow; no major change)
  parent_upgrade    npm: the newest version of a direct dependency within its major version, when
                    it brings fixed copies of the vulnerable packages nested under it
  major_upgrade     a package upgrade held back as a major version change (the scanner's target)
  image_major       the container image's migration target

Safe kinds come first; then known-exploited fixes, then the most findings fixed, then the fewest
companion upgrades. Findings only in development tools (npm devDependencies) come last: they are
not in the running application.

Companion upgrades (pip, from the package registries): a requirement of the target version that
the app's pinned version does not meet (cryptography 49.0.0 needs cffi>=2.0.0), and a pinned
package whose own requirement excludes the target (requests 2.28.2 needs urllib3<1.27).
"""

import json
import re

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from app import versions
from app.sources import osv, packages

MAX_VERSIONS_SCANNED = 30  # newer versions of a pinned package checked for one that allows the target
MAX_FALLBACKS = 2   # other versions per package, as each one is a full build and test
KIND_ORDER = {"lockfile_refresh": 0, "parent_upgrade": 1, "major_upgrade": 2, "image_major": 3}
_PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*==\s*([^\s;#]+)")
_NPM_VERSION = re.compile(r"(\d+)(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?")


# -- the application's dependency file ------------------------------------------------------------

def parse_manifest(manifest: dict | None) -> dict:
    """{"ecosystem", "pins": {name: exact version}, "declared": {name: spec}, "dev": {names},
    "dev_only": {"name@version"}} from a requirements.txt or package.json sent with the request.
    `dev_only` (npm) lists the installed packages the lockfile marks as development-only; without
    it only devDependencies declared in package.json are known to be development tools."""
    out = {"ecosystem": None, "pins": {}, "declared": {}, "dev": set(),
           "dev_only": set((manifest or {}).get("dev_only") or []), "copies": (manifest or {}).get("copies") or {}}
    if not manifest or not manifest.get("content"):
        return out
    name, content = (manifest.get("file") or "").rsplit("/", 1)[-1].lower(), manifest["content"]
    if name.endswith(".json"):
        try:
            doc = json.loads(content)
        except ValueError:
            return out
        out["ecosystem"] = "npm"
        out["declared"] = {**(doc.get("devDependencies") or {}), **(doc.get("dependencies") or {})}
        out["dev"] = set(doc.get("devDependencies") or {}) - set(doc.get("dependencies") or {})
    elif name.endswith(".txt"):
        out["ecosystem"] = "pip"
        for line in content.splitlines():
            match = _PIN.match(line.split("#", 1)[0])
            if match:
                out["pins"][canonicalize_name(match.group(1))] = match.group(2)
    return out


def satisfies(version: str, spec: str) -> bool | None:
    """Does a pip version meet a specifier such as ">=2.0.0" or "<1.27,>=1.21.1"? None if unreadable."""
    try:
        return SpecifierSet(spec).contains(Version(version), prereleases=True)
    except (InvalidSpecifier, InvalidVersion):
        return None


def npm_lower_bound(spec: str | None) -> str | None:
    """The smallest version an npm range allows ("^1.20.3" -> 1.20.3, "~2.0.7" -> 2.0.7, "1.x" ->
    1.0.0); for "a || b" the smaller one. None if there is no lower bound to read."""
    bounds = []
    for alternative in (spec or "").split("||"):
        alternative = alternative.strip()
        if not alternative or alternative in ("*", "x", "latest"):
            bounds.append("0.0.0")
            continue
        first = alternative.split()[0]
        if first.startswith("<"):
            bounds.append("0.0.0")
            continue
        match = _NPM_VERSION.search(first)
        if not match:
            return None
        parts = [p if p and p.isdigit() else "0" for p in match.groups()]
        bounds.append(".".join(parts))
    return min(bounds, key=lambda v: versions.parse(v) or (0,)) if bounds else None


def _npm_comparator(token: str) -> list[tuple[str, tuple]]:
    """One npm range token -> [(operator, version)]: "^1.2.3" -> [(">=", 1.2.3), ("<", 2.0.0)]."""
    match = re.match(r"^(>=|<=|>|<|=|\^|~)?v?(\d+|x|\*)?(?:\.(\d+|x|\*))?(?:\.(\d+|x|\*))?", token)
    op, *raw = match.groups() if match else (None, None, None, None)
    nums = [int(p) if p and p.isdigit() else None for p in raw]
    if nums[0] is None:
        return []  # "*", "x", "": any version
    major, minor, patch = nums
    low = (major, minor or 0, patch or 0)
    if op == "^":
        upper = (major + 1, 0, 0) if major else (0, (minor or 0) + 1, 0) if minor else (0, 0, (patch or 0) + 1)
        return [(">=", low), ("<", upper)]
    if op == "~" or (not op and (minor is None or patch is None)):  # "~1.2.3", "1.2.x", "1.x"
        upper = (major, minor + 1, 0) if minor is not None else (major + 1, 0, 0)
        return [(">=", low), ("<", upper)]
    return [(op if op and op != "=" else "==", low)]


def npm_allows(spec: str | None, version: str) -> bool | None:
    """Does an npm range allow a version ("^1.20.3" allows 1.20.9, not 2.0.0)? None if unreadable."""
    v = versions.parse(version)
    if spec is None or v is None:
        return None
    v = v[:3]
    for alternative in spec.split("||"):
        alternative = alternative.strip()
        if " - " in alternative:
            low, high = (versions.parse(x.strip()) for x in alternative.split(" - ", 1))
            if low and high and low[:3] <= v <= high[:3]:
                return True
            continue
        tests = [c for token in alternative.split() for c in _npm_comparator(token)]
        ops = {">=": lambda a, b: a >= b, ">": lambda a, b: a > b, "<=": lambda a, b: a <= b,
               "<": lambda a, b: a < b, "==": lambda a, b: a == b}
        if all(ops[op](v, bound) for op, bound in tests):
            return True
    return False


# -- companion upgrades (pip) ---------------------------------------------------------------------

def companions(conn, client, name: str, target: str, pins: dict[str, str], warnings: list[str], *,
               online: bool = True) -> list[dict]:
    """What else has to change for `name` to be at `target`, given the app's pinned versions."""
    found, own = [], canonicalize_name(name)
    for dep, spec in packages.requirements(conn, client, "pip", name, target, warnings, online=online) or []:
        pinned = pins.get(dep)
        if pinned and spec and satisfies(pinned, spec) is False:
            options = [v for v in packages.published(conn, client, "pip", dep, warnings, online=online) or []
                       if _newer(v, pinned) and satisfies(v, spec)]
            found.append(_companion(dep, pinned, options[0] if options else None,
                                    f"{name} {target} requires {dep}{spec}"))
    for other, pinned in sorted(pins.items()):
        if other == own:
            continue
        needs = dict(packages.requirements(conn, client, "pip", other, pinned, warnings, online=online) or [])
        spec = needs.get(own)
        if spec and satisfies(target, spec) is False:
            suggestion = None
            newer = [v for v in packages.published(conn, client, "pip", other, warnings, online=online) or [] if _newer(v, pinned)]
            for version in newer[:MAX_VERSIONS_SCANNED]:
                allowed = dict(packages.requirements(conn, client, "pip", other, version, warnings, online=online) or [])
                if satisfies(target, allowed.get(own) or "") is not False:
                    suggestion = version
                    break
            found.append(_companion(other, pinned, suggestion, f"{other} {pinned} requires {name}{spec}"))
    return found


def _newer(a: str, b: str) -> bool:
    try:
        return Version(a) > Version(b)
    except InvalidVersion:
        return False


def _companion(name: str, current: str, suggest: str | None, reason: str) -> dict:
    return {"name": name, "current": current, "suggest": suggest, "reason": reason,
            "major_change": bool(suggest and not versions.same_major(current, suggest))}


# -- npm: a newer parent within its major version --------------------------------------------------

def parent_upgrade(conn, client, parent: str, current: str, nested: list[dict], fixed_in, warnings: list[str], *,
                   online: bool = True) -> dict | None:
    """The newest `parent` version within its major version, and which nested findings it fixes:
    following each finding's dependency path from that version, the vulnerable package is no longer
    reached, or reached at a version at or above its fix (lower bounds of the declared ranges)."""
    newer = [v for v in packages.published(conn, client, "npm", parent, warnings, online=online) or []
             if versions.same_major(v, current) and versions.is_newer(v, current)]
    if not newer:
        return None
    target = newer[-1]
    fixes = parent_upgrade_at(conn, client, target, nested, fixed_in, warnings, online=online)
    return {"target": target, "fixes": fixes} if fixes else None


def parent_upgrade_at(conn, client, version: str, nested: list[dict], fixed_in, warnings: list[str], *,
                      online: bool = True) -> list[str]:
    """The nested findings one given version of their parent fixes (see parent_upgrade)."""
    fixes = []
    for f in nested:
        chain = [versions.split_package(step)[0] for step in f["dependency_path"][1:]]
        here_version, reached = version, True
        for here, nxt in zip(chain, chain[1:]):
            spec = dict(packages.requirements(conn, client, "npm", here, here_version, warnings, online=online) or []).get(nxt)
            if spec is None:
                reached = False
                break
            here_version = npm_lower_bound(spec)
            if here_version is None:
                break
        fix = fixed_in(f)
        if here_version and (not reached or (fix and versions.parse(here_version) >= versions.parse(fix))):
            fixes.append(_finding_id(f))
    return fixes


def walk(conn, client, chain: list[str], version: str, fix: str | None, warnings: list[str], *,
         online: bool = True) -> bool:
    """Starting from `version` of chain[0], following the declared ranges (their lower bounds) down
    the chain of package names: is the last package no longer reached, or reached at `fix` or above?"""
    here_version = version
    for here, nxt in zip(chain, chain[1:]):
        spec = dict(packages.requirements(conn, client, "npm", here, here_version, warnings, online=online) or []).get(nxt)
        if spec is None:
            return here_version is not None  # this path no longer leads to the vulnerable package
        here_version = npm_lower_bound(spec)
        if here_version is None:
            return False
    return bool(fix and versions.parse(here_version) >= versions.parse(fix))


def npm_copy_trials(conn, client, findings: list[dict], copies: dict, fixed_in, compatible: dict, warnings: list[str], *,
                    online: bool = True) -> list[dict]:
    """npm, from every installed copy (the lockfile, sent by the client as `copies`): which copies of
    each finding's package are still below the fix, and which change fixes ALL of them:
      lockfile_refresh  the package right above a copy allows the fixed version
      parent_upgrade    a newer version of the direct dependency a copy comes in through: the newest
                        within its major version, else (major_upgrade) the newest of all
    A finding counts for a trial only when that trial alone fixes every vulnerable copy in the app."""
    vulnerable: dict[str, list[dict]] = {}  # finding id -> the app's copies below the fix
    for f in findings:
        name = versions.split_package(f.get("package"))[0]
        fix = fixed_in(f)
        if not fix:
            continue
        below = [c for c in copies.get(name, []) if not c.get("dev") and c.get("chain")
                 and versions.parse(c["version"]) < versions.parse(fix)]
        if below:
            vulnerable[_finding_id(f)] = [{**c, "fix": fix} for c in below]
    out = []
    refreshable = [fid for fid, cs in vulnerable.items() if all(_refresh_ok(conn, client, c, warnings, online) for c in cs)]
    if refreshable:
        names = sorted({c["chain"][-1].rsplit("@", 1)[0] for fid in refreshable for c in vulnerable[fid]})
        out.append({"kind": "lockfile_refresh", "name": "lockfile", "current": None, "target": None, "fixes": refreshable,
                    "note": f"`npm update {' '.join(names)}`: newer versions within the ranges the packages above them allow, "
                            "which include the fixed versions. Not a major version change.", "packages": names})
    parents = sorted({c["chain"][0] for cs in vulnerable.values() for c in cs if len(c["chain"]) > 1})
    for parent in parents:
        name, current = versions.split_package(parent)
        published = [v for v in packages.published(conn, client, "npm", name, warnings, online=online) or []
                     if versions.is_newer(v, current)]
        same = [v for v in published if versions.same_major(v, current)]
        for target, kind in ((same[-1] if same else None, "parent_upgrade"), (published[-1] if published else None, "major_upgrade")):
            if not target or (kind == "major_upgrade" and same and target == same[-1]):
                continue
            fixes, fixed_copies = [], set()
            for fid, cs in vulnerable.items():
                mine = [c for c in cs if c["chain"][0] == parent]
                done = [c for c in mine if walk(conn, client, [s.rsplit("@", 1)[0] for s in c["chain"]], target, c["fix"],
                                                warnings, online=online)]
                fixed_copies.update(c["chain"][-1].rsplit("@", 1)[0] for c in done)
                if mine and len(done) == len(cs):
                    fixes.append(fid)
            safe_already = compatible.get(name) and not versions.is_newer(target, compatible[name])
            if fixed_copies and not safe_already:
                out.append({"kind": kind, "name": name, "current": current, "target": target, "fixes": fixes,
                            "note": (f"{'Same major version' if kind == 'parent_upgrade' else 'Major version change'}; brings "
                                     f"fixed copies of {', '.join(sorted(fixed_copies))}"
                                     + ("" if fixes else " (other copies of them remain, so no finding is fully fixed by this alone)")
                                     + ".")})
            if kind == "parent_upgrade" and fixed_copies and len(fixes) == len([f for f, cs in vulnerable.items()
                                                                                if any(c["chain"][0] == parent for c in cs)]):
                break  # the same-major version already fixes everything this parent brings in
    return out


def _refresh_ok(conn, client, copy: dict, warnings: list[str], online: bool) -> bool:
    if len(copy["chain"]) < 2:
        return False
    parent_name, parent_version = copy["chain"][-2].rsplit("@", 1)
    name = copy["chain"][-1].rsplit("@", 1)[0]
    spec = dict(packages.requirements(conn, client, "npm", parent_name, parent_version, warnings, online=online) or []).get(name)
    return bool(npm_allows(spec, copy["fix"]))


def _finding_id(f: dict) -> str:
    return f.get("cve") or f.get("rule_id") or "?"


# -- other versions to try when one fails ----------------------------------------------------------

def _no_advisories(conn, client, name: str, version: str, ecosystem: str, warnings: list[str], online: bool) -> bool:
    """OSV.dev was asked and knows none. Not knowing is not the same as clean."""
    return osv.advisories(conn, client, name, version, osv.osv_ecosystem(ecosystem), warnings, online=online) == []


def clean_versions(conn, client, name: str, above: str, ecosystem: str, warnings: list[str], *, online: bool = True) -> list[str]:
    """Up to MAX_FALLBACKS versions newer than `above` with no known advisory: the newest of its own
    major version first, then the newest of each major after it, the smallest step first."""
    newest_of: dict[int, str] = {}
    for version in packages.published(conn, client, ecosystem, name, warnings, online=online) or []:
        parsed = versions.parse(version)
        if parsed and _newer(version, above):
            newest_of[parsed[0]] = version  # published() is oldest first
    found = []
    for major in sorted(newest_of):
        if len(found) == MAX_FALLBACKS:
            break
        if _no_advisories(conn, client, name, newest_of[major], ecosystem, warnings, online):
            found.append(newest_of[major])
    return found


# -- the plan --------------------------------------------------------------------------------------

def plan(conn, client, findings: list[dict], upgrades: list[dict], references: list[dict], manifest: dict | None,
         warnings: list[str], *, online: bool = True, use_registries: bool = True, use_osv: bool = True) -> list[dict]:
    app = parse_manifest(manifest)
    exploited = {r["id"] for r in references if r["type"] == "cve" and r.get("kev")}
    trials = []
    by_id: dict[str, list[dict]] = {}
    for f in findings:
        by_id.setdefault(_finding_id(f), []).append(f)

    def dev_finding(f: dict) -> bool:
        if app["dev_only"]:
            return f.get("package") in app["dev_only"]
        path = f.get("dependency_path") or []
        return len(path) > 1 and versions.split_package(path[1])[0] in app["dev"]

    def dev_upgrade(u: dict) -> bool:
        mine = [f for fid in u.get("fixes") or [] for f in by_id.get(fid, [])
                if versions.split_package(f.get("upgrade_to"))[0] == u["name"]]
        return bool(mine) and all(dev_finding(f) for f in mine) or u["name"] in app["dev"]

    # trials go on top of the safe candidate: the compatible upgrades are already applied
    pins = dict(app["pins"])
    for u in upgrades:
        if u["kind"] == "package" and u.get("compatible_target"):
            key = canonicalize_name(u["name"])
            if key in pins:
                pins[key] = u["compatible_target"]

    def add(kind, name, current, target, fixes, note, also=(), dev_only=False):
        trials.append({"kind": kind, "name": name, "current": current, "target": target, "fixes": sorted(set(fixes)),
                       "known_exploited": sorted(set(fixes) & exploited), "dev_only": dev_only,
                       "also_needs": list(also), "note": note})

    def needs(name: str, version: str) -> list[dict]:
        return companions(conn, client, name, version, pins, warnings, online=online) if (
            use_registries and app["ecosystem"] == "pip" and pins) else []

    def _fallback(version: str, name: str | None = None) -> dict:
        return {"target": version, "also_needs": needs(name or u["name"], version)}

    def major_options(u: dict) -> tuple[str, list[str], str]:
        """The version to try first, what to try after it, and a note if that is not the scanner's own target.
        The scanner's target may itself have a known advisory: then a clean version goes first."""
        target, note, before = u["target"], "", []
        if use_registries and use_osv and app["ecosystem"] and not _no_advisories(
                conn, client, u["name"], target, app["ecosystem"], warnings, online):
            cleaner = clean_versions(conn, client, u["name"], target, app["ecosystem"], warnings, online=online)
            if cleaner:
                target, before = cleaner[0], [u["target"]]
                note = f" The scanner's target {u['target']} still has a known advisory, so {target} goes first."
        floor = u.get("compatible_target") or u.get("current")
        lower = {versions.split_package(f.get("upgrade_to"))[1] for f in findings
                 if versions.split_package(f.get("upgrade_to"))[0] == u["name"]}
        lower = sorted((v for v in lower if v and v not in (target, u["target"]) and _newer(u["target"], v) and (not floor or _newer(v, floor))),
                       key=versions.parse, reverse=True)
        return target, (before + lower)[:MAX_FALLBACKS], note

    for u in upgrades:
        if u["kind"] == "package" and u.get("major_change") and (not u.get("compatible_target") or u.get("compatible_scope") == "partial"):
            target, others, changed = major_options(u)
            add("major_upgrade", u["name"], u.get("current"), target, u.get("fixes") or [],
                f"Major version change ({versions.major_label(u.get('current'))} → {versions.major_label(target)}): "
                "try it on its own and run the app's tests; the code may need changes." + changed, needs(u["name"], target),
                dev_only=dev_upgrade(u))
            trials[-1]["fallbacks"] = [_fallback(version) for version in others]
        elif u["kind"] == "image" and not u.get("compatible_target") and u.get("target"):
            add("image_major", u["name"], u.get("current"), u.get("target"), u.get("fixes") or [],
                "New major version of the image: what runs on or connects to it may need changes.")

    if app["ecosystem"] == "npm" and app["copies"] and use_registries:
        cache_all: dict[tuple, str | None] = {}

        def fix_of(f):
            name, version = versions.split_package(f.get("package"))
            key = (name, version, _finding_id(f))
            if key not in cache_all:
                found = osv.advisories(conn, client, name, version, "npm", warnings, online=online) if use_osv else None
                hit = next((a for a in found or [] if _finding_id(f) in a["aliases"] or a["id"] == _finding_id(f)), None)
                target_name, target = versions.split_package(f.get("upgrade_to"))
                cache_all[key] = (hit and hit["fixed"]) or (target if target_name == name else None)
            return cache_all[key]

        compatible = {u["name"]: u.get("compatible_target") for u in upgrades if u["kind"] == "package"}
        in_app = [f for f in findings if not dev_finding(f)]
        dev_side = [f for f in findings if dev_finding(f)]
        majors_by_name = {t["name"] for t in trials}
        for found, dev in ((npm_copy_trials(conn, client, in_app, app["copies"], fix_of, compatible, warnings, online=online), False),
                           (npm_copy_trials(conn, client, dev_side, {n: [{**c, "dev": False} for c in cs if c.get("dev")]
                                                                       for n, cs in app["copies"].items()},
                                            fix_of, compatible, warnings, online=online), True)):
            for t in found:
                if t["kind"] == "major_upgrade" and t["name"] in majors_by_name:
                    continue
                add(t["kind"], t["name"], t["current"], t["target"], t["fixes"], t["note"], dev_only=dev)
        # the scanner's own major targets for packages that are not declared (a dev tool's dependency
        # shown as if direct) cannot be applied by editing package.json: leave them out
        trials[:] = [t for t in trials if not (t["kind"] == "major_upgrade" and t["dev_only"]
                                              and t["name"] not in app["declared"] and t["name"] not in
                                              {x["name"] for x in trials if x is not t and x["kind"] != "major_upgrade"})]
    elif app["ecosystem"] == "npm":
        nested = [f for f in findings if len(f.get("dependency_path") or []) > 2]
        cache: dict[tuple, str | None] = {}

        def fixed_in(f):
            name, version = versions.split_package(f.get("package"))
            key = (name, version, _finding_id(f))
            if key not in cache:
                found = osv.advisories(conn, client, name, version, "npm", warnings, online=online) if use_osv else None
                hit = next((a for a in found or [] if _finding_id(f) in a["aliases"] or a["id"] == _finding_id(f)), None)
                cache[key] = hit and hit["fixed"]
            return cache[key]

        by_parent: dict[str, list[dict]] = {}
        for f in nested:
            by_parent.setdefault(f["dependency_path"][1], []).append(f)
        # a refresh fixes a nested finding when the package right above it allows the fixed version
        refreshable = []
        if use_registries:
            for f in nested:
                if dev_finding(f):
                    continue
                parent_name, parent_version = versions.split_package(f["dependency_path"][-2])
                name = versions.split_package(f["package"])[0]
                spec = dict(packages.requirements(conn, client, "npm", parent_name, parent_version, warnings,
                                                  online=online) or []).get(name)
                fix = fixed_in(f)
                if fix and npm_allows(spec, fix):
                    refreshable.append(f)
        if refreshable:
            names = sorted({versions.split_package(f["package"])[0] for f in refreshable})
            add("lockfile_refresh", "lockfile", None, None, [_finding_id(f) for f in refreshable],
                f"`npm update {' '.join(names)}`: newer versions within the ranges the packages above them allow, "
                "which include the fixed versions. Not a major version change.")
        compatible = {u["name"]: u.get("compatible_target") for u in upgrades if u["kind"] == "package"}
        if use_registries:
            for parent, group in sorted(by_parent.items()):
                name, current = versions.split_package(parent)
                found = parent_upgrade(conn, client, name, current, [f for f in group if not dev_finding(f)] or group,
                                       fixed_in, warnings, online=online)
                if found and compatible.get(name):
                    already = parent_upgrade_at(conn, client, compatible[name], group, fixed_in, warnings, online=online)
                    if set(found["fixes"]) <= set(already):
                        continue  # the safe upgrade of this parent already fixes these
                if found:
                    vulnerable = sorted({versions.split_package(f["package"])[0] for f in group if _finding_id(f) in found["fixes"]})
                    add("parent_upgrade", name, current, found["target"], found["fixes"],
                        f"Same major version; brings fixed copies of {', '.join(vulnerable)}.", dev_only=name in app["dev"])

    if use_registries and use_osv and app["ecosystem"]:
        for u in upgrades:
            if u["kind"] == "package" and u.get("compatible_target"):
                u["fallbacks"] = [_fallback(version) for version in clean_versions(
                    conn, client, u["name"], u["compatible_target"], app["ecosystem"], warnings, online=online)
                    if version != u["compatible_target"]]

    trials.sort(key=lambda t: (t["dev_only"], KIND_ORDER[t["kind"]], -len(t["known_exploited"]), -len(t["fixes"]),
                               len(t["also_needs"]), t["name"]))
    for order, trial in enumerate(trials, 1):
        trial["order"] = order
    return trials

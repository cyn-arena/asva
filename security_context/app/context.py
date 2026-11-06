"""Assembles the response for one file's findings.

  items       prompt context for the LLM, size-budgeted (max_chars, default 2,500):
                code/logic/config fixes  OWASP sections (or a compact CWE entry if none match)
                dependency upgrades      upgrade notes (scanner target vs installed version,
                                         major-version risk, OSV.dev cross-check)
                container findings       where the OS-package fixes are published (OSV.dev), the
                                         image's newer release lines (Docker Hub, endoflife.date)
                                         and the one suggested
                any CVE in CISA KEV      a "known exploited, fix first" item, placed first
  references  structured citations for the PR body and the UI, not for the prompt and not
              budgeted: CVEs (NVD: CVSS, CWE, KEV flag), CWEs (definition, mitigations, OWASP
              Top 10 labels), OSV advisories, OWASP sections, Context7's breaking-change
              notes for major library upgrades, and image sources.
  upgrades    the same upgrade advice as data: per package or image, the current version, the
              target, the smallest fixed version, the newest version and whether it is a major
              change.

Every source can be left out (`exclude`), which is how results with and without a source are
compared. Retrieved text is reference material, not evidence: the scanner finding stays
authoritative.
"""

from dataclasses import dataclass, field
from datetime import date

import httpx

from app import config, images, store, versions
from app.retrieve import Retriever, cwe_compact_item, cwe_details, item, normalise_cwe
from app import trials as trial_plan
from app.sources import context7, kev, lifecycle, nvd, osv, registry
from app.sources import cwe as cwe_source
from app.text import truncate

GUIDANCE_FIX_TYPES = {"code_change", "logic_change", "config_change"}
MIN_TRUNCATED_CHARS = 200
SHOWN_IDS = 3
MAX_DISTRO_LOOKUPS = 30     # container CVEs checked against the distribution's fix data per request
MAX_LISTED_LINES = 4        # newer image lines shown in the prompt
REFERENCE_DESCRIPTION_CHARS = 400
REFERENCE_MITIGATION_CHARS = 300
REFERENCE_MITIGATIONS = 3
# ecosystem -> (the file a version bump edits, how a package that only comes in through
# another one is fixed instead)
_MANIFESTS = {
    "npm": ("package.json", "a lockfile refresh or npm overrides"),
    "pip": ("requirements.txt", "its own pinned line or a constraints file"),
    "pypi": ("requirements.txt", "its own pinned line or a constraints file"),
    "maven": ("pom.xml", "a dependencyManagement entry"),
    "nuget": ("the project file", "a direct PackageReference for the transitive package"),
    "golang": ("go.mod", "a newer indirect requirement (go get)"),
    "go": ("go.mod", "a newer indirect requirement (go get)"),
    "rubygems": ("the Gemfile", "a Gemfile.lock update (bundle update)"),
    "composer": ("composer.json", "a composer.lock update"),
}
_MANIFEST_DEFAULT = ("the dependency file", "a lockfile refresh or a pinned override of the transitive package")


def _ids(values) -> str:
    values = sorted(values)
    shown = ", ".join(values[:SHOWN_IDS])
    return shown + (f" +{len(values) - SHOWN_IDS} more" if len(values) > SHOWN_IDS else "")


def _version_in_path(path: list[str] | None, name: str) -> str | None:
    for element in path or []:
        element_name, element_version = versions.split_package(element)
        if element_name == name:
            return element_version
    return None


def _vulnerabilities(advisories: list[dict], current: str | None) -> list[dict]:
    """OSV.dev's records for one package version, one entry per vulnerability: records that share
    an id or alias are the same vulnerability (PyPI ones have a GHSA and a PYSEC record).
    Each entry: {"id" (the CVE if there is one), "fixed" (smallest fixed version), "within" (smallest
    fixed version in the installed major version, or None)}."""
    groups: list[dict] = []
    for advisory in advisories:
        names = {advisory["id"], *advisory["aliases"]}
        group = next((g for g in groups if g["names"] & names), None)
        if group is None:
            group = {"names": set(), "fixes": []}
            groups.append(group)
        group["names"] |= names
        group["fixes"] += advisory.get("fixed_versions") or []
    merged = []
    for group in groups:
        fixes = sorted({(versions.parse(v), v) for v in group["fixes"] if versions.parse(v)})
        merged.append({"id": min((n for n in group["names"] if n.startswith("CVE-")), default=min(group["names"])),
                       "fixed": fixes[0][1] if fixes else None,
                       "within": next((v for _, v in fixes if versions.same_major(v, current)), None)})
    return merged


def _flag_exploited(upgrades: list[dict], kev_hits: dict) -> None:
    """A known-exploited CVE whose fix is held back (no compatible fix, or only a partial one)
    must not wait in the backlog: say so in the note that goes to the PR."""
    for upgrade in upgrades:
        exploited = sorted(set(upgrade.get("fixes") or []) & set(kev_hits))
        if exploited and (not upgrade.get("compatible_target") or upgrade.get("compatible_scope") == "partial"):
            upgrade["note"] = ((upgrade.get("note") or "").strip() + f" {', '.join(exploited)} is known to be exploited "
                               f"(CISA KEV) and is not fixed by a compatible bump: plan this migration urgently.").strip()


def _suggestion_rule(fix_data_checked: bool) -> str:
    """How the migration target was chosen (images.suggest), in words."""
    basis = "whose base OS resolves the checked CVEs" if fix_data_checked else "on a newer base OS than this image"
    return f"the nearest supported line {basis}"


def apply_budget(items: list[dict], max_chars: int, warnings: list[str]) -> list[dict]:
    kept, used, dropped = [], 0, 0
    for entry in items:
        remaining = max_chars - used
        if len(entry["text"]) <= remaining:
            kept.append(entry)
            used += len(entry["text"])
        elif remaining >= MIN_TRUNCATED_CHARS:
            entry = {**entry, "text": truncate(entry["text"], remaining)}
            kept.append(entry)
            used += len(entry["text"])
        else:
            dropped += 1
    if dropped:
        warnings.append(f"{dropped} item(s) left out to stay within {max_chars} characters")
    return kept


@dataclass
class _Run:
    """One request's working state (the builder itself is shared between requests)."""
    conn: object
    warnings: list[str]
    trace: dict
    refs: "_References"
    off: frozenset[str]
    online: bool
    upgrades: list[dict] = field(default_factory=list)
    osv_cwes: dict[str, None] = field(default_factory=dict)  # CWEs named by matched OSV advisories

    def uses(self, source: str) -> bool:
        return source not in self.off


class ContextBuilder:
    def __init__(self, retriever: Retriever, client: httpx.Client | None, online: bool = config.ONLINE_LOOKUPS,
                 max_library_notes: int = config.MAX_LIBRARY_NOTES, passage_max_chars: int = config.PASSAGE_MAX_CHARS,
                 today=date.today, library_notes_in_prompt: bool | None = None,
                 image_lines_in_prompt: bool | None = None):
        self.retriever = retriever
        self.client = client
        self.online = online and client is not None
        self.max_library_notes = max_library_notes
        self.library_notes_in_prompt = (config.LIBRARY_NOTES_IN_PROMPT if library_notes_in_prompt is None
                                        else library_notes_in_prompt)
        self.image_lines_in_prompt = (config.IMAGE_LINES_IN_PROMPT if image_lines_in_prompt is None
                                      else image_lines_in_prompt)
        self.passage_max_chars = passage_max_chars
        self.today = today

    # -- entry point ------------------------------------------------------------

    def build(self, conn, findings: list[dict], fix_type: str | None, max_chars: int, trace: dict | None = None,
              exclude=()) -> tuple[list[dict], list[dict], list[str], list[dict]]:
        """-> (items for the prompt, references for the PR/UI, warnings, upgrades).
        `trace` gets debug details; `exclude` names sources to answer without."""
        trace = {} if trace is None else trace
        warnings: list[str] = []
        off = frozenset(str(s).strip().lower() for s in exclude or ()) | config.DISABLED_SOURCES
        if unknown := sorted(off - set(config.SOURCE_IDS)):
            warnings.append(f"Unknown source(s) ignored: {', '.join(unknown)} (known: {', '.join(config.SOURCE_IDS)})")
        run = _Run(conn, warnings, trace, _References(), off, self.online)

        cve_ids = list(dict.fromkeys(f["cve"].upper() for f in findings if f.get("cve")))
        cves = nvd.lookup(conn, self.client, cve_ids, warnings, online=self.online) if cve_ids and run.uses("nvd") else {}
        kev_hits = kev.lookup(conn, cve_ids) if cve_ids and run.uses("kev") else {}
        cwes = self._resolve_cwes(run, findings)

        items: list[dict] = []
        wants_guidance = fix_type is None or fix_type in GUIDANCE_FIX_TYPES
        if wants_guidance:
            guidance = self.retriever.guidance(conn, findings, warnings, trace, use_cwe=run.uses("cwe"),
                                               keyword_fallback=run.uses("keyword")) if run.uses("owasp") else []
            items += guidance
            run.refs.add_guidance(guidance)
            if not guidance:
                items += [i for i in (cwe_compact_item(conn, c) for c in cwes) if i]
        elif fix_type == "version_upgrade":
            packages = [f for f in findings if f.get("finding_type") != "container" and f.get("package")]
            containers = [f for f in findings if f.get("finding_type") == "container"]
            if packages:
                items += self._dependency_items(run, packages)
            if containers:
                items.append(self._container_item(run, containers))

        if kev_hits:
            items.insert(0, self._kev_item(kev_hits))
            _flag_exploited(run.upgrades, kev_hits)
        if run.uses("cwe"):
            cwes = list(dict.fromkeys(cwes + list(run.osv_cwes)))
        run.refs.add_cves(cve_ids, cves, kev_hits, enriched=run.uses("nvd"))
        run.refs.add_cwes(conn, cwes)

        trace.setdefault("queries", [])
        trace.update({
            "resolved_cwes": cwes,
            "guidance_search": ("ran" if run.uses("owasp") else "skipped (source excluded)") if wants_guidance
            else f"skipped (no prose guidance for {fix_type})",
            "cves": {"requested": len(cve_ids), "found_in_nvd": len(cves), "known_exploited": sorted(kev_hits)},
            "online_lookups": self.online,
            "excluded_sources": sorted(off),
        })
        return apply_budget(items, max_chars, warnings), run.refs.items, warnings, run.upgrades

    # -- trial plan -------------------------------------------------------------

    def plan_trials(self, conn, findings: list[dict], upgrades: list[dict], references: list[dict],
                    manifest: dict | None, warnings: list[str], exclude=()) -> list[dict]:
        """Held-back upgrades to try one at a time (app/trials.py), from build()'s upgrade data."""
        off = set(config.DISABLED_SOURCES) | set(exclude)
        return trial_plan.plan(conn, self.client, findings, upgrades, references, manifest, warnings,
                               online=self.online, use_registries="registries" not in off, use_osv="osv" not in off)

    # -- CWE hub ----------------------------------------------------------------

    def _resolve_cwes(self, run: _Run, findings: list[dict]) -> list[str]:
        """From the finding itself (`cwe`, plus the scanner's rule tags in `cwes`), or via
        CVE -> CWE links (filled by NVD lookups)."""
        if not run.uses("cwe"):
            return []
        resolved: dict[str, None] = {}
        unresolved = []
        for f in findings:
            found = [cwe for cwe in map(normalise_cwe, [f.get("cwe"), *(f.get("cwes") or [])]) if cwe]
            if f.get("cve"):
                if run.uses("nvd"):
                    found += store.linked(run.conn, f["cve"].upper(), "has_cwe")
                if not found:
                    unresolved.append(f["cve"].upper())
            resolved.update(dict.fromkeys(found))
        if unresolved:
            run.warnings.append(f"{len(unresolved)} finding(s) have a CVE but no known CWE (e.g. {unresolved[0]})")
        return list(resolved)

    # -- dependency upgrades -------------------------------------------------------

    def _dependency_items(self, run: _Run, findings: list[dict]) -> list[dict]:
        conn, warnings, trace = run.conn, run.warnings, run.trace
        groups: dict[str, dict] = {}  # package to upgrade -> details
        no_target = []
        for f in findings:
            vuln_name, vuln_version = versions.split_package(f.get("package"))
            target_name, target_version = versions.split_package(f.get("upgrade_to"))
            if not target_name or not target_version:
                no_target.append(f)
                continue
            group = groups.setdefault(target_name, {"current": None, "targets": [], "fixes": {}, "direct": False,
                                                    "ecosystem": (f.get("ecosystem") or "npm").lower()})
            group["targets"].append(target_version)
            installed = vuln_version if vuln_name == target_name else _version_in_path(f.get("dependency_path"), target_name)
            group["current"] = group["current"] or installed
            group["direct"] |= vuln_name == target_name
            group["fixes"].setdefault(f"{vuln_name}@{vuln_version}", set()).add(f.get("cve") or f.get("rule_id") or "?")

        lines, majors, checked = [], [], []
        for name, group in sorted(groups.items()):
            current, target = group["current"], versions.newest(group["targets"])
            # The finding ids are in the references and upgrade data; the prompt only needs how many
            # findings a bump fixes and in which packages (a file can have dozens of findings).
            vulnerable_packages = sorted({p.rsplit("@", 1)[0] for p in group["fixes"]})
            fixes = (f"{len(set().union(*group['fixes'].values()))} finding(s) in "
                     f"{', '.join(vulnerable_packages[:SHOWN_IDS])}"
                     + (f" +{len(vulnerable_packages) - SHOWN_IDS} more" if len(vulnerable_packages) > SHOWN_IDS else ""))
            upgrade = {"kind": "package", "name": name, "ecosystem": group["ecosystem"], "current": current,
                       "target": target, "target_source": "scanner", "min_fixed": None, "compatible_scope": None,
                       "major_change": False, "status": "ok",
                       "fixes": sorted(set().union(*group["fixes"].values())), "note": None}
            line = f"- {name} {current or '(installed version unknown)'} → {target}"
            if current and versions.parse(current) == versions.parse(target):
                vulnerable = ", ".join(sorted({p.rsplit('@', 1)[0] for p in group["fixes"]}))
                manifest, remedy = _MANIFESTS.get(group["ecosystem"], _MANIFEST_DEFAULT)
                line += (f": already at the target, so editing {manifest} cannot fix {vulnerable}; "
                         f"it needs {remedy} (reviewer decision).")
                upgrade.update(status="already_at_target",
                               note=f"{name} is already at {target}; the vulnerable packages ({vulnerable}) come in "
                                    f"through it and need {remedy}.")
            elif versions.is_breaking(current, target):
                line += f": MAJOR version change ({versions.major_label(current)} → {versions.major_label(target)}); fixes {fixes}."
                majors.append((name, group["ecosystem"], current, target))
                upgrade.update(status="major_change", major_change=True)
            else:
                line += f": fixes {fixes}."
            sentence, advisories = self._osv_check(run, name, group, current, target, checked, upgrade)
            compatible, reason = self._compatible_package(name, group, current, target, upgrade, advisories)
            upgrade["compatible_target"] = compatible
            lines.append(line + sentence + reason)
            run.upgrades.append(upgrade)

        for f in no_target:
            name, version = versions.split_package(f.get("package"))
            ecosystem = osv.osv_ecosystem(f.get("ecosystem"))
            fixed = None
            if name and version and ecosystem and run.uses("osv"):
                found = osv.advisories(conn, self.client, name, version, ecosystem, warnings, online=self.online) or []
                run.refs.add_advisories(name, found, None)
                match = next((a for a in found if f.get("cve") in a["aliases"] or a["id"] == f.get("cve")), None)
                fixed = match and match["fixed"]
            lines.append(f"- {f.get('package')}: no upgrade from the scanner" +
                         (f"; OSV.dev: fixed in {fixed}." if fixed else "; no fixed version known."))
            run.upgrades.append({"kind": "package", "name": name or f.get("package") or "?",
                                 "ecosystem": (f.get("ecosystem") or "").lower() or None, "current": version,
                                 "target": None, "target_source": None, "compatible_target": None, "min_fixed": fixed,
                                 "major_change": False, "status": "no_target",
                                 "fixes": [f.get("cve") or f.get("rule_id") or "?"],
                                 "note": "The scanner offers no upgrade for this finding."})

        trace["dependency_groups"] = {name: {"installed": g["current"], "target": versions.newest(g["targets"])}
                                      for name, g in groups.items()}
        trace["osv_checked"] = checked
        out = []
        if lines:
            crosscheck = ", cross-checked with OSV.dev" if run.uses("osv") else ""
            header = f"Dependency upgrade notes (scanner targets{crosscheck})"
            out.append(item(osv.SOURCE if run.uses("osv") else "scanner findings", "dependency-upgrades", "upgrade_notes",
                            header, f"{header}:\n" + "\n".join(lines), None, osv.LICENSE if run.uses("osv") else None,
                            store.now_iso()))
        if run.uses("context7"):
            out += self._library_items(run, majors)
        return out

    @staticmethod
    def _compatible_package(name: str, group: dict, current: str | None, target: str, upgrade: dict,
                            advisories: list[dict] | None) -> tuple[str | None, str]:
        """-> (the version to move to without a major version change, a sentence for the prompt).

        A target in the same major version is the compatible fix. When the scanner's target is a
        major version change, a compatible fix exists only if OSV.dev lists a fix within the
        installed major version for every advisory against the installed version, and the upgrade
        is not also needed to pull in fixed transitive packages. Otherwise there is none: the
        finding needs a migration, not a version bump."""
        if upgrade["status"] == "already_at_target":
            return None, ""
        if not upgrade["major_change"]:
            upgrade["compatible_scope"] = "all"
            return target, ""
        label = versions.major_label(current)
        own = _vulnerabilities(advisories or [], current)
        within = [a["within"] for a in own]
        direct_only = set(group["fixes"]) <= {f"{name}@{current}"}
        if own and all(within) and direct_only:
            compatible = versions.newest(within)
            upgrade["compatible_scope"] = "all"
            return compatible, f" OSV.dev lists a fix within {label}: {name} {compatible}, a compatible alternative."
        if own and not all(within):
            beyond = [a["fixed"] for a in own if not a["within"] and a["fixed"]] or [target]
            lowest, highest = min(beyond, key=versions.parse), versions.newest(beyond)
            where = f"first fixed in {lowest}" if lowest == highest else f"fixed in {lowest} to {highest}"
            if any(within) and direct_only:
                # some vulnerabilities are fixed within the installed major version: that bump is
                # safe to apply, and the rest still need the migration
                compatible, fixed = versions.newest([v for v in within if v]), sum(1 for v in within if v)
                left = _ids({a["id"] for a in own if not a["within"]})
                upgrade["compatible_scope"] = "partial"
                upgrade["note"] = (f"Partly fixable without a major version change: {name} {compatible} resolves {fixed} of "
                                   f"the {len(own)} vulnerabilities OSV.dev lists for {name} {current}. No fix within {label} "
                                   f"for {left} ({where}): those need a migration to {versions.major_label(target)}.")
                return compatible, (f" OSV.dev lists a fix within {label} for {fixed} of its {len(own)} vulnerabilities in "
                                    f"{name} {current}: {name} {compatible} resolves those without a major version change; "
                                    f"the rest have no fix within {label} ({where}).")
            upgrade["note"] = (f"No compatible fix: OSV.dev lists no fix within {label} ({where}). "
                               f"This needs a migration to {versions.major_label(target)}, not a version bump.")
            return None, (f" OSV.dev lists no fix within {label} ({where}), so no compatible "
                          f"version bump resolves this.")
        upgrade["note"] = (f"No compatible fix is known: the scanner's target is a major version change "
                           f"({label} → {versions.major_label(target)}).")
        return None, ""

    def _osv_check(self, run: _Run, name: str, group: dict, current: str | None, target: str, checked: list,
                   upgrade: dict) -> tuple[str, list[dict] | None]:
        """Cross-check a direct dependency's target with OSV; say only what the prompt needs.
        -> (sentence, OSV's advisories against the installed version, None if it wasn't asked)."""
        ecosystem = osv.osv_ecosystem(group["ecosystem"])
        if not run.uses("osv"):
            return "", None
        if not (group["direct"] and current and ecosystem):
            for package, ids in group["fixes"].items():  # transitive: record the vulnerable package's own fixes
                vuln_name, vuln_version = versions.split_package(package)
                if vuln_name and vuln_version and ecosystem:
                    found = osv.advisories(run.conn, self.client, vuln_name, vuln_version, ecosystem, run.warnings,
                                           online=self.online) or []
                    run.refs.add_advisories(vuln_name, found, None)
                    self._note_cwes(run, found, ids)
            return "", None
        found = osv.advisories(run.conn, self.client, name, current, ecosystem, run.warnings, online=self.online)
        if found is None:
            return "", None
        checked.append(f"{name}@{current}")
        run.refs.add_advisories(name, found, target)
        finding_ids = group["fixes"].get(f"{name}@{current}", set())
        matched = [a for a in found if (set(a["aliases"]) | {a["id"]}) & finding_ids]
        self._note_cwes(run, matched, finding_ids)
        if matched and all(a["fixed"] for a in matched):
            upgrade["min_fixed"] = versions.newest([a["fixed"] for a in matched])
        late = [f"{a['aliases'][0] if a['aliases'] else a['id']} needs {a['fixed']}" for a in matched
                if a["fixed"] is None or versions.is_newer(a["fixed"], target)]
        if late:
            upgrade.update(status="osv_disagrees", note=f"OSV.dev: {', '.join(late)}.")
            return f" OSV.dev disagrees: {', '.join(late)}.", found
        confirmed = {i for a in matched for i in (set(a["aliases"]) | {a["id"]}) & finding_ids}
        return (f" OSV.dev confirms {len(confirmed)} of these." if confirmed else ""), found

    @staticmethod
    def _note_cwes(run: _Run, advisories: list[dict], finding_ids) -> None:
        for advisory in advisories:
            if (set(advisory["aliases"]) | {advisory["id"]}) & set(finding_ids):
                run.osv_cwes.update(dict.fromkeys(c for c in map(normalise_cwe, advisory.get("cwes") or []) if c))

    def _library_items(self, run: _Run, majors: list[tuple]) -> list[dict]:
        """Context7's breaking-change notes for major upgrades. They always go to the references,
        for whoever carries out the migration; into the prompt only if configured, because a
        major upgrade is not applied as a version bump."""
        out, looked_up = [], []
        for name, ecosystem, current, target in majors[: self.max_library_notes]:
            notes = context7.upgrade_notes(run.conn, self.client, name, ecosystem, current, target, run.warnings,
                                           online=self.online)
            looked_up.append({"package": name, "library": notes and notes.get("library_id"),
                              "snippets": len(notes["snippets"]) if notes else 0,
                              "in_prompt": self.library_notes_in_prompt})
            if not notes or not notes["snippets"]:
                continue
            run.refs.add_library(notes, f"{name} {versions.major_label(current)} → {versions.major_label(target)}")
            if not self.library_notes_in_prompt:
                continue
            header = (f"Breaking changes, {name} {versions.major_label(current)} → {versions.major_label(target)} "
                      f"(from the library's own documentation via Context7):")
            body = "\n".join(f"- {s['title']}: {s['description']}" for s in notes["snippets"])
            url = next((s["source"] for s in notes["snippets"] if s["source"]), f"https://context7.com{notes['library_id']}")
            out.append(item(context7.SOURCE, notes["library_id"], "library_notes", f"{name} upgrade notes",
                            truncate(f"{header}\n{body}", self.passage_max_chars), url, context7.LICENSE, store.now_iso()))
        run.trace["library_notes"] = looked_up
        return out

    # -- container images ---------------------------------------------------------

    def _container_item(self, run: _Run, findings: list[dict]) -> dict:
        conn, warnings = run.conn, run.warnings
        cve_count, package_count, listed = images.package_summary(findings)
        name, tag = images.image_of(findings)
        distro = images.distro_of(findings)

        lines = None
        if name and run.uses("dockerhub"):
            lines = registry.image_lines(conn, self.client, name, tag, warnings, online=self.online)
        current_facts = (lines or {}).get("current") or {}
        family = distro[0] if distro else current_facts.get("base_distro")
        release = distro[1] if distro else current_facts.get("base_release")
        current_os = images.os_label(family, release)

        fixes: list[dict | None] = []
        if run.uses("osv") and family:
            seen = set()
            for f in findings:
                cve, package = (f.get("cve") or "").upper(), versions.split_package(f.get("package"))[0]
                if not cve or (cve, package) in seen or len(seen) >= MAX_DISTRO_LOOKUPS:
                    continue
                seen.add((cve, package))
                fix = osv.distro_fixes(conn, self.client, cve, family, package, warnings, online=self.online)
                fixes.append(fix)
                run.refs.add_distro_fix(package, fix, release, family)
        here = images.release_status(fixes, release)

        cycles = None
        if name and lines and run.uses("endoflife"):
            cycles = lifecycle.cycles(conn, self.client, name, warnings, online=self.online)
        today = self.today()
        line_name = registry.line_text(tag)
        ended = images.ended_on((cycles or {}).get(line_name or ""), today)  # the current line: past end of life?
        found = images.candidates(lines, cycles, fixes, family, today)
        compatible = images.compatible(found, tag, release)
        suggested = images.suggest(found, release, today)        # the migration target
        longest = images.longest_supported(found, release, today)
        stuck = [f for f in findings if images.scanner_offers_nothing_newer(f)]

        image = f"{name}:{tag}" if name and tag else name
        text = "Container image" + (f" {image}" if image else "") + (f" ({current_os})" if current_os else "")
        text += f": {cve_count} CVE(s) in {package_count} OS package(s) ({listed})."
        if ended:
            text += (f"\n{name} {line_name} is past end of life" + (f" since {ended}" if isinstance(ended, str) else "")
                     + f" ({lifecycle.SOURCE}).")

        status = "unknown"
        if here["checked"]:
            source = "OSV.dev (the distribution's own security data)"
            if here["subscription"]:
                status = "newer_line_needed"
                text += (f"\n{source}: for {current_os}, {here['subscription']} of {here['checked']} checked fixes are "
                         f"published only as \"{here['availability'] or 'subscription required'}\", not in the "
                         f"standard package repositories")
                text += f"; {here['standard']} are in the standard repositories." if here["standard"] else "."
            elif here["standard"] == here["checked"]:
                status = "rebuild_may_suffice"
                text += (f"\n{source}: {current_os} publishes fixes for all {here['checked']} checked CVEs in its standard "
                         f"repositories, so a rebuilt or newer patch release of the same image line may already include them.")
            else:
                status = "newer_line_needed" if here["unfixed"] else status
                text += (f"\n{source}: for {current_os}, {here['standard']} of {here['checked']} checked CVEs have a fix "
                         f"in the standard repositories" + (f"; {here['unfixed']} have no fix yet." if here["unfixed"] else "."))
        elif stuck:
            status = "newer_line_needed"
            text += (f"\nFor {len(stuck)} of {len(findings)} findings the scanner offers no newer package version than the "
                     f"installed one, so updating single packages inside this image is not possible: move the service "
                     f"to a newer, supported image tag.")
        else:
            text += "\nThe scanner lists fixed package versions; a newer image tag that ships them resolves these findings."

        # The OS release already publishes every fix and the image line is still maintained:
        # the same tag, rebuilt, resolves the findings. No other tag is put forward then.
        rebuild = status == "rebuild_may_suffice" and not ended
        note = None
        if rebuild:
            built = (lines or {}).get("current") or {}
            text += (f"\nNo tag change is needed for these CVEs: re-pull or rebuild {image or 'the image'} to pick the fixes up"
                     + (f" (Docker Hub's current build of this tag is from {built['built']})." if built.get("built") else "."))
            note = f"No tag change needed: {current_os} publishes the fixes, so a re-pulled or rebuilt image resolves these findings."
            compatible = suggested = None
        else:
            if self.image_lines_in_prompt:
                text += self._image_lines_text(name, found, suggested, bool(cycles))
            text += self._image_advice_text(name, tag, found, compatible, suggested if self.image_lines_in_prompt else None,
                                            longest, bool(here["checked"]))

        chosen = compatible or suggested
        if found and not compatible and not rebuild:
            note = (f"No compatible fix: no {versions.major_label(tag)} line of {name} resolves these findings. "
                    + (f"Migration target: {name}:{suggested['tag']}." if suggested
                       else "No migration target is suggested: support dates are unknown or no line qualifies."))
        if lines:
            run.refs.add_image(name, tag, lines, bool(cycles))
        run.upgrades.append({
            "kind": "image", "name": name or "(image not named by the scan)", "ecosystem": current_os, "current": tag,
            "target": chosen["tag"] if chosen else None,
            "target_source": ("same major version, resolves the checked CVEs" if compatible
                              else _suggestion_rule(bool(suggested["cves_checked"])) if suggested else None),
            "compatible_target": compatible["tag"] if compatible else None,
            "compatible_scope": "all" if compatible else None,
            "min_fixed": None,
            "major_change": bool(chosen and versions.is_breaking(tag, chosen["tag"])), "status": status,
            "fixes": sorted({f["cve"] for f in findings if f.get("cve")}),
            "candidates": [{k: v for k, v in line.items() if k != "base_release"} for line in found] or None,
            "note": note,
        })
        run.trace["container"] = {
            "image": image, "base_os": current_os, "fix_data": here, "newer_lines": [line["tag"] for line in found],
            "compatible": compatible["tag"] if compatible else None,
            "suggested": suggested["tag"] if suggested else None}
        return item(osv.SOURCE if here["checked"] else "scanner findings", "container-summary", "container_summary",
                    "Container image summary", text, None, osv.LICENSE if here["checked"] else None, store.now_iso())

    @staticmethod
    def _image_lines_text(name: str | None, found: list[dict], suggested: dict | None, has_dates: bool) -> str:
        if not found:
            return ""
        open_lines = [line for line in found if line["end_of_life"] is not True]
        ended = [line["tag"] for line in found if line["end_of_life"] is True]
        shown = open_lines[-MAX_LISTED_LINES:]
        if suggested and suggested not in shown:
            shown = [suggested] + shown[1:]
        checked = any(line["cves_checked"] for line in shown)
        notes = ["Docker Hub"] + (["support dates: endoflife.date"] if has_dates else []) + (
            ['"resolved" = fixed in that base OS\'s standard packages, or not affected'] if checked else [])
        text = f"\nNewer release lines of {name} ({'; '.join(notes)}):"
        for line in shown:
            facts = [" on ".join(part for part in (line["version"], line["base_os"]) if part)]
            if line["cves_checked"]:
                facts.append(f"{line['cves_resolved']}/{line['cves_checked']} checked CVEs resolved")
            if line["supported_until"]:
                facts.append(f"supported until {line['supported_until']}")
            elif line["released"]:
                facts.append(f"released {line['released']}")
            text += f"\n- {name}:{line['tag']}: {', '.join(fact for fact in facts if fact)}"
        if ended:
            text += f"\n(past end of life, not listed: {', '.join(ended)})"
        return text

    @staticmethod
    def _image_advice_text(name: str | None, tag: str | None, found: list[dict], compatible: dict | None,
                           suggested: dict | None, longest: dict | None, fix_data_checked: bool) -> str:
        """Which line to move to: the compatible one (same major version) if there is one;
        otherwise that there is none, and the migration target."""
        if not found or not versions.parse(tag):
            return ""
        major = versions.major_label(tag)
        if compatible:
            return (f"\nCompatible fix (same major version, {major}): {name}:{compatible['tag']} resolves the checked "
                    f"CVEs without a major version change.")
        resolving = "The lines that resolve these CVEs are" if fix_data_checked else "The newer lines are"
        text = (f"\nCompatible fix (same major version, {major}): none. {resolving} new major versions of {name}: "
                f"moving to one is a migration (what runs on or connects to this image may need changes: application "
                f"code, client libraries, stored data), not a drop-in tag bump.")
        if suggested:
            text += f"\nMigration target: {name}:{suggested['tag']}, {_suggestion_rule(bool(suggested['cves_checked']))}"
            if longest and longest is not suggested:
                text += f"; {name}:{longest['tag']} is supported longest (until {longest['supported_until']})"
            text += "."
        return text

    # -- known exploited -------------------------------------------------------------

    def _kev_item(self, kev_hits: dict[str, dict]) -> dict:
        lines = [f"- {cve}: {k.get('name') or ''} (added {k.get('date_added')}; ransomware use: {k.get('ransomware')})"
                 for cve, k in sorted(kev_hits.items())]
        text = "Known exploited in the wild (CISA KEV), highest priority:\n" + "\n".join(lines)
        first = sorted(kev_hits)[0]
        return item(kev.SOURCE, first, "kev", "Known exploited vulnerabilities", text, kev_hits[first].get("url"),
                    kev.LICENSE, store.now_iso())


class _References:
    """Citations for the PR body and UI, deduplicated by (type, id)."""

    def __init__(self):
        self.items: list[dict] = []
        self._seen: set[tuple] = set()

    def _add(self, ref: dict) -> None:
        key = (ref["type"], ref["id"])
        if key not in self._seen:
            self._seen.add(key)
            self.items.append(ref)

    def add_cves(self, cve_ids: list[str], cves: dict, kev_hits: dict, enriched: bool = True) -> None:
        for cve_id in cve_ids:
            data, exploited = cves.get(cve_id) or {}, kev_hits.get(cve_id)
            self._add({"type": "cve", "id": cve_id, "title": data.get("title"),
                       "url": data.get("url") or nvd.DETAIL_URL.format(cve=cve_id),
                       "source": nvd.SOURCE if enriched else "scanner findings",
                       "license": nvd.LICENSE if enriched else None, "cvss": data.get("cvss"),
                       "severity": data.get("severity"), "cwes": data.get("cwes"), "kev": bool(exploited),
                       "kev_date": exploited.get("date_added") if exploited else None})

    def add_cwes(self, conn, cwes: list[str]) -> None:
        """Each CWE with MITRE's definition and top mitigations: the PR body can explain the
        weakness without that text taking up prompt space."""
        for cwe in cwes:
            details = cwe_details(conn, cwe)
            record = details["record"] if details else None
            mitigations = None
            if details and details["mitigations"]:
                suffix = f" (from parent {details['inherited_from'].split(':', 1)[0]})" if details["inherited_from"] else ""
                mitigations = [truncate(line[2:], REFERENCE_MITIGATION_CHARS) + suffix
                               for line in details["mitigations"][:REFERENCE_MITIGATIONS]]
            self._add({"type": "cwe", "id": cwe, "title": record["title"] if record else None,
                       "url": record["url"] if record else None, "source": cwe_source.SOURCE,
                       "license": cwe_source.LICENSE, "owasp_top10": cwe_source.top10(conn, cwe),
                       "description": truncate(details["description"], REFERENCE_DESCRIPTION_CHARS) if details else None,
                       "mitigations": mitigations})

    def add_guidance(self, guidance: list[dict]) -> None:
        for g in guidance:
            self._add({"type": "guidance", "id": f"{g['key']}#{g['section'] or ''}",
                       "title": f"{g['title']} › {g['section'] or 'Introduction'}", "url": g["url"],
                       "source": g["source"], "license": g["license"]})

    def add_advisories(self, package: str, advisories: list[dict], target: str | None) -> None:
        for a in advisories:
            beyond = (a["fixed"] is None or versions.is_newer(a["fixed"], target)) if target else None
            self._add({"type": "advisory", "id": a["id"], "title": a["summary"], "url": a["url"], "source": osv.SOURCE,
                       "license": osv.LICENSE, "package": package, "fixed_in": a["fixed"], "aliases": a["aliases"],
                       "severity": a.get("severity"), "beyond_target": beyond})

    def add_distro_fix(self, package: str | None, fix: dict | None, release: str | None, family: str | None = None) -> None:
        """An OS package's fix for the image's own OS release, with the distribution's wording
        for where it is published. With none there, the newer releases that have one."""
        releases = (fix or {}).get("releases") or {}
        entry = releases.get(release or "")
        if not entry or not entry["fixed"]:
            newer = osv.newer_release_fixes(releases, release)
            if newer:
                self._add({"type": "os_release_fix", "id": fix["id"], "title": f"{package}: fixed in newer releases than {release}",
                           "url": fix["url"], "source": osv.SOURCE, "license": osv.LICENSE, "package": package,
                           "newer_release_fixes": newer, "release_name": images.release_name(family, release),
                           "newer_release_names": {r: n for r in newer if (n := images.release_name(family, r))}})
            return
        self._add({"type": "advisory", "id": fix["id"], "title": f"{package}: fix for release {release}",
                   "url": fix["url"], "source": osv.SOURCE, "license": osv.LICENSE, "package": package,
                   "fixed_in": entry["fixed"], "availability": entry.get("availability"),
                   "subscription_only": entry.get("subscription_only")})

    def add_image(self, name: str, tag: str | None, lines: dict, with_dates: bool) -> None:
        path = f"_/{name}" if lines["repository"].startswith("library/") else f"r/{lines['repository']}"
        self._add({"type": "image", "id": f"{name}:{tag}", "title": f"{name}: release lines and base images",
                   "url": registry.HUB_URL.format(path=path), "source": registry.SOURCE, "license": registry.LICENSE})
        if with_dates:
            product = lifecycle.product_of(name)
            self._add({"type": "image", "id": f"{product} support dates", "title": f"{product}: release and end-of-life dates",
                       "url": lifecycle.PAGE_URL.format(product=product), "source": lifecycle.SOURCE,
                       "license": lifecycle.LICENSE})

    def add_library(self, notes: dict, upgrade: str) -> None:
        """Each breaking-change note with its text, e.g. for "mongodb 2.x → 3.x"."""
        for s in notes["snippets"]:
            if s["source"]:
                self._add({"type": "library_docs", "id": f"{s['source']}#{s['title']}", "title": s["title"], "url": s["source"],
                           "source": context7.SOURCE, "license": context7.LICENSE, "package": upgrade,
                           "description": truncate(s["description"], REFERENCE_DESCRIPTION_CHARS)})

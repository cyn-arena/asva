#!/usr/bin/env python3
"""
normaliser.py -- SARIF Normaliser for ASVA (AI-Assisted Vulnerability Analysis)
================================================================================
Converts Snyk SARIF output files (Snyk Container, Snyk Open Source, Snyk Code)
into a single structured JSON output:

  ranked_unified_findings.json -- full findings as a flat list sorted by
                                  priority (critical first), used by triage.py
                                  (Stage A) and agent_loop.py (Stage B)

Usage:
    python normaliser.py --inputs image.sarif.json sca.sarif.json sast.sarif.json
                         --output-dir ./output

Requirements: Python 3.10+ (no third-party libraries needed)
"""

import json
import re
import uuid
import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path


# ===========================================================================
# SECTION 1: CONSTANTS
# ===========================================================================
#
# Snyk SARIF uses the standard "level" field (error / warning / note) rather
# than plain severity words.  LEVEL_TO_SEVERITY maps these to our labels.
#
# Dependency/container severity uses Snyk's explicit rating when present.
# CVSS remains a separate score; critical promotion is a fallback only.
#
# Snyk Code (SAST) has no CVSS score at all.  SAST_PSEUDO_SCORE maps its
# level to a synthetic score so all three scan types share one ranking.
# has_real_score=False on these findings tells the triage LLM they are
# derived, not from an official CVSS database.

LEVEL_TO_SEVERITY: dict[str, str] = {
    "error":   "high",
    "warning": "medium",
    "note":    "low",
    "none":    "info",
}

SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high":     1,
    "medium":   2,
    "low":      3,
    "info":     4,
    "unknown":  5,
}

SAST_PSEUDO_SCORE: dict[str, float] = {
    "error":   8.5,
    "warning": 5.0,
    "note":    2.0,
}

# Fields included in the lean priority_list.json sent to the triage LLM.
# The full unified_findings.json adds "description", "ecosystem", "dedup_key".
LEAN_FIELDS = {
    "finding_id", "finding_type", "severity", "score", "has_real_score",
    "identifiers", "title", "summary", "location", "dependency",
    "remediation", "priority",
}


# ===========================================================================
# SECTION 2: HELPER FUNCTIONS
# ===========================================================================

def extract_cve(text: str | None) -> str | None:
    """Return the first CVE-YYYY-NNNNN identifier found in text, or None."""
    if not text:
        return None
    match = re.search(r"CVE-\d{4}-\d{4,}", text)
    return match.group(0) if match else None


def extract_cwe(rule_properties: dict) -> str | None:
    """
    Return the first CWE identifier from a rule's properties.cwe list.

    Snyk Code rules carry a "cwe" array, e.g. ["CWE-94"].
    SCA / Container rules do not have this field.
    """
    cwe_list = rule_properties.get("cwe", [])
    return cwe_list[0] if cwe_list else None


def parse_cvss(rule_properties: dict) -> float | None:
    """
    Extract a CVSS v3 base score from a rule's properties dictionary.

    Snyk uses two possible keys:
      - "cvssv3_baseScore"   : preferred
      - "security-severity"  : fallback, sometimes the string "null"

    Returns None when no valid score in 0.0--10.0 is found.
    """
    for key in ("cvssv3_baseScore", "security-severity"):
        val = rule_properties.get(key)
        if val is None or val == "null":
            continue
        try:
            score = float(val)
            if 0.0 <= score <= 10.0:
                return score
        except (ValueError, TypeError):
            pass
    return None


def get_severity_from_level(level: str | None) -> str:
    """Convert a SARIF level string to a normalised severity label."""
    if not level:
        return "unknown"
    return LEVEL_TO_SEVERITY.get(level, "unknown")


def promote_to_critical(severity: str, cvss_score: float | None) -> str:
    """
    Promote ANY finding to "critical" when its CVSS score is 9.0 or above.

    Snyk emits CVSS 9.x findings as "warning" (medium) rather than "error"
    (high) for OS-level packages.  The score is the authoritative signal --
    the SARIF level is not reliable for critical promotion.
    """
    if cvss_score is not None and cvss_score >= 9.0:
        return "critical"
    return severity


def parse_package(fully_qualified_name: str | None) -> tuple[str | None, str | None]:
    """
    Split "name@version" into (name, version).

    Uses rsplit on the last '@' so scoped packages like "@types/node@14.0.0"
    are handled correctly.
    """
    if not fully_qualified_name:
        return None, None
    parts = fully_qualified_name.rsplit("@", 1)
    name    = parts[0] if parts else None
    version = parts[1] if len(parts) > 1 else None
    return name, version


def parse_fix_version(
    fixes: list | None, package_name: str | None
) -> tuple[bool, str | None]:
    """
    Determine whether a dependency fix exists and what the upgrade target is.

    Snyk stores remediation in results[].fixes[].description.text:
        "Upgrade to body-parser@1.20.3"
        "Upgrade to perl/perl-base@5.30.0-9ubuntu0.5+esm2"
        "There is no fixed version for this vulnerability"

    OS package versions use characters npm versions don't -- an epoch ("1:2.4.48-5"),
    "+" and "~" ("...+esm2", "...~esm1") -- and package names can contain "+"
    ("libstdc++6").  The pattern must keep all of them: a version cut off at "+esm2"
    is the version that is already installed.

    Returns (fixable, upgrade_to).
    """
    if not fixes:
        return False, None

    for fix in fixes:
        description = fix.get("description", {}).get("text", "")
        if "no fixed version" in description.lower():
            return False, None
        match = re.search(r"[Uu]pgrade\s+to\s+([\w\-\.\/@\+]+@[\w\.\-\+~:]+)", description)
        if match:
            return True, match.group(1)
        match = re.search(r"@([\d]+\.[\d]+[\d\.]*)", description)
        if match and package_name:
            return True, f"{package_name}@{match.group(1)}"

    return False, None


def python_remediation(help_markdown, package_name, package_version, is_direct):
    """Read Snyk pip's bounded remediation section; never infer parent upgrades."""
    section = re.search(r"(?ms)^#+ Remediation\s*\n(.*?)(?=^#+ |\Z)", help_markdown or "")
    if not section:
        return None
    guidance = section.group(1).strip()
    evidence = {"source": "rule.help.markdown", "guidance": guidance,
                "status": "unsupported", "upgrade_to": None}
    match = re.fullmatch(
        r"Upgrade `([A-Za-z0-9_.-]+)` to version (\d+(?:\.\d+){1,3}(?:, \d+(?:\.\d+){1,3})*) or higher\.",
        guidance,
    )
    canonical = lambda name: re.sub(r"[-_.]+", "-", name or "").lower()
    if not match or canonical(match[1]) != canonical(package_name):
        evidence["reason"] = "No supported package-specific upgrade recommendation"
        return evidence
    if is_direct is not True:
        evidence["reason"] = "Transitive or unknown dependency requires source-parent upgrade evidence"
        return evidence
    if not re.fullmatch(r"\d+(?:\.\d+){1,3}", package_version or ""):
        evidence["reason"] = "Installed version is not a supported stable release"
        return evidence
    version_key = lambda value: tuple(map(int, value.split("."))) + (0,) * (4 - len(value.split(".")))
    current = version_key(package_version)
    targets = sorted((v for v in match[2].split(", ") if version_key(v) > current), key=version_key)
    if not targets:
        evidence["reason"] = "No recommended upgrade newer than the installed version"
        return evidence
    # Prefer the installed release line when Snyk lists fixes on several branches.
    same_line = [v for v in targets if version_key(v)[:2] == current[:2]]
    target = (same_line or targets)[0]
    evidence.update(status="recommended", upgrade_to=f"{package_name}@{target}")
    return evidence


def parse_container_image(
    artifact_uri: str | None, automation_id: str | None
) -> tuple[str | None, str | None]:
    """
    Recover the scanned image's (name, tag) for a container finding.

    Snyk Container reports the image in two places, neither complete on its own:

      run.automationDetails.id   "Snyk/Container/docker-image|mongo/0/<timestamp>"
                                 -> the image name, without its tag
      artifactLocation.uri       "mongo_4.4"
                                 -> the image reference with ":" replaced by "_"

    The name tells us where the tag starts -- an image name can itself contain
    underscores, so splitting the uri alone would be a guess.  When the run does not
    name the image, the uri is returned whole as the name and the tag is None.
    """
    if not artifact_uri:
        return None, None

    match = re.search(r"docker-image\|(.+)/\d+/[^/]+$", automation_id or "")
    if not match:
        return artifact_uri, None

    name   = match.group(1)
    prefix = name.replace(":", "_") + "_"
    tag    = artifact_uri[len(prefix):] if artifact_uri.startswith(prefix) else None
    return name, tag or None


def parse_help_upgrade(help_text, package_name, current_version=None):
    """Read only Snyk's Remediation section when result.fixes is absent."""
    if not help_text or not package_name:
        return False, None
    section = re.search(r"(?im)^\s*#{1,6}\s+Remediation\s*\r?\n([\s\S]*?)(?=^\s*#{1,6}\s|\Z)", help_text)
    if not section:
        return False, None
    text = section.group(1).replace("`", "")
    if re.search(r"no (?:fixed version|fix)|no remediation", text, re.I):
        return False, None
    upgrade = re.search(r"Upgrade\s+([\w.@/-]+)\s+to\s+versions?\s+([^\n]+)", text, re.I)
    if not upgrade or re.sub(r"[-_.]+", "-", upgrade.group(1)).lower() != re.sub(r"[-_.]+", "-", package_name).lower():
        return False, None
    versions = re.findall(r"(?<![\w.])\d+(?:\.\d+)+(?:[a-zA-Z]+\d+)?(?![\w.])", upgrade.group(2).rstrip("."))
    def numeric(version):
        return tuple(int(part) for part in re.match(r"\d+(?:\.\d+)*", version).group().split("."))
    if not versions:
        return False, None
    current = numeric(current_version) if current_version and re.match(r"^\d", current_version) else None
    viable = [version for version in versions if current is None or numeric(version) >= current]
    if not viable:
        return False, None
    compatible = [version for version in viable if current and numeric(version)[0] == current[0]]
    target = min(compatible or viable, key=numeric)
    return True, f"{package_name}@{target}"


def dependency_severity(rule, result, level, cvss_score):
    """Preserve Snyk's rating even when CVSS would otherwise promote it."""
    for props in (result.get("properties", {}), rule.get("properties", {})):
        for field in ("severity", "issueSeverity"):
            rating = str(props.get(field, "")).lower()
            if rating in SEVERITY_ORDER and rating != "unknown":
                return rating
    title = rule.get("shortDescription", {}).get("text", "")
    rating = re.match(r"\s*(critical|high|medium|low|info)\s+severity\b", title, re.I)
    if rating:
        return rating.group(1).lower()
    return promote_to_critical(get_severity_from_level(level), cvss_score)


def parse_dependency_path(
    help_markdown: str | None,
) -> tuple[list | None, bool | None]:
    """
    Parse the real dependency chain from the detailed paths block in Snyk's
    SCA rule help markdown.

    Snyk markdown has TWO "Introduced through" sections:

      1. Summary line (plain text, comma-separated, may say "and others"):
            * Introduced through: owasp-nodejs-goat@1.3.0, forever@2.0.0 and others

      2. Detailed paths (italic markdown, arrow-separated, one line each):
            * _Introduced through_: owasp-nodejs-goat@1.3.0 > forever@2.0.0 > brace-expansion@1.1.11

    We specifically target the italic `_Introduced through_:` format (section 2)
    to get the real chain.  The summary line is deliberately ignored -- it
    truncates long chains and cannot be relied on for is_direct classification.

    Returns (dependency_path, is_direct):
        path     : list of "name@version" strings from root to vulnerable pkg
        is_direct: True only when the chain has exactly 2 hops (root -> pkg)
    """
    if not help_markdown:
        return None, None

    # Match the FIRST detailed-path line: _Introduced through_: a > b > c
    match = re.search(r"_[Ii]ntroduced\s+through_[:\s]+([^\n]+)", help_markdown)
    if not match:
        return None, None

    chain_str = match.group(1).strip()
    # Split on the > or unicode right-angle quotation mark Snyk uses
    parts = [p.strip() for p in re.split(r"[>›]", chain_str) if p.strip()]
    if not parts:
        return None, None

    is_direct = len(parts) <= 2
    return parts, is_direct


def extract_ecosystem(tags: list | None) -> str:
    """
    Extract the package manager / ecosystem tag from a rule's properties.tags.

    "deb"  -> OS package inside a container image (needs image rebuild)
    "npm"  -> Node.js package (needs npm install + PR)
    "pip"  -> Python package
    """
    if not tags:
        return "unknown"
    for tag in tags:
        if tag in ("deb", "rpm", "apk", "npm", "pip", "maven", "gem", "nuget", "golang"):
            return tag
    return "unknown"


def detect_scan_source(tool_name: str) -> str:
    """
    Map a SARIF tool driver name to a scan-source label.

        "Snyk Container"  -> "container"
        "Snyk Open Source"-> "sca"
        "SnykCode"        -> "sast"
    """
    name_lower = tool_name.lower()
    if "container" in name_lower:
        return "container"
    if "open source" in name_lower or "oss" in name_lower:
        return "sca"
    if "code" in name_lower or "sast" in name_lower:
        return "sast"
    return "unknown"


def make_dedup_key(
    scan_source: str,
    cve_id: str | None,
    rule_id: str | None,
    package_name: str | None,
    artifact_uri: str | None,
    start_line: int | None,
    *,
    ecosystem: str = "unknown",
    package_version: str | None = None,
    dependency_path: list | None = None,
    image_context: str | None = None,
    remediation: dict | None = None,
) -> str:
    """
    Build a deduplication key that keeps genuinely distinct findings separate.

    Dependency observations retain scanner, advisory, ecosystem, installed version,
    manifest/image and dependency path. Distinct remediation is retained too: a
    higher CVSS observation must never replace an actionable upgrade recommendation.

    SAST:
        Key = rule_id | file | line
        Every occurrence of a rule at a different file/line is a separate
        finding.  Without file+line in the key, all 315 SAST results collapse
        to one per rule (42 entries instead of 315).
    """
    if scan_source == "sast":
        file_part = (artifact_uri or "").lower()
        line_part = str(start_line) if start_line is not None else "?"
        return f"{rule_id or 'unknown'}|{file_part}|{line_part}"

    return json.dumps([scan_source, cve_id, rule_id, ecosystem, package_name,
                       package_version, artifact_uri, dependency_path, image_context,
                       remediation], separators=(",", ":"), sort_keys=True)


# ===========================================================================
# SECTION 3: PER-RESULT EXTRACTION
# ===========================================================================
#
# SARIF separates *what* a vulnerability is (rule) from *where* it was found
# (result).  extract_finding merges both into one nested dict.
#
# Key structural differences across the three scan types:
#
#   Container:  severity on rule.defaultConfiguration.level; no dep chain;
#               the scanned image is named on the run, not on the result
#   SCA:        severity on result.level; dep chain in rule.help.markdown
#   SAST:       no CVSS score; location is a real file+line (not a package);
#               CWE in rule.properties.cwe; description in result.message.text

def extract_code_flow(result: dict) -> list[dict]:
    """Ordered, de-duplicated [{"file", "line"}] steps from a SAST result's SARIF
    codeFlows/threadFlows (source to sink). Snyk Code and Semgrep emit these; the fix agent
    uses them to show the data flow and to pull in other files on the path (ITP2 task 3.1).
    Empty when the scanner gives no code flow."""
    steps: list[dict] = []
    seen: set[tuple] = set()
    for code_flow in result.get("codeFlows") or []:
        for thread_flow in code_flow.get("threadFlows") or []:
            for step in thread_flow.get("locations") or []:
                phys = (step.get("location") or {}).get("physicalLocation") or {}
                uri = (phys.get("artifactLocation") or {}).get("uri")
                line = (phys.get("region") or {}).get("startLine")
                if not uri or (uri, line) in seen:
                    continue
                seen.add((uri, line))
                steps.append({"file": uri, "line": line})
    return steps


def extract_finding(
    result: dict, rule: dict, scan_source: str, automation_id: str | None = None
) -> dict:
    """
    Convert one SARIF result + its matching rule into a normalised finding.

    automation_id is the run's automationDetails.id, used to name the scanned
    image for container findings (see parse_container_image).

    Returns a dict with nested location{}, identifiers{}, remediation{},
    and dependency{} objects so the triage LLM sees a consistent shape
    regardless of which scanner produced the finding.
    """
    rule_id    = result.get("ruleId", rule.get("id", "unknown"))
    rule_props = rule.get("properties", {})
    tags       = rule_props.get("tags", [])

    # ------------------------------------------------------------------
    # Location: pull file path, line number (SAST), and package (SCA/container)
    # ------------------------------------------------------------------
    locations    = result.get("locations", [])
    artifact_uri = None
    start_line   = None
    fqn          = None   # "body-parser@1.18.3" from logicalLocations

    if locations:
        loc     = locations[0]
        logical = loc.get("logicalLocations", [])
        if logical:
            fqn = logical[0].get("fullyQualifiedName")
        phys         = loc.get("physicalLocation", {})
        artifact_uri = phys.get("artifactLocation", {}).get("uri")
        region       = phys.get("region", {})
        line_val     = region.get("startLine")
        if isinstance(line_val, int) and line_val > 1:
            # startLine=1 is a Snyk placeholder for dependency scans; ignore it
            start_line = line_val

    package_name, package_version = parse_package(fqn)
    ecosystem = extract_ecosystem(tags)

    # ------------------------------------------------------------------
    # Severity and score
    # ------------------------------------------------------------------
    rule_default_level = rule.get("defaultConfiguration", {}).get("level")
    result_level       = result.get("level")
    level              = rule_default_level or result_level
    severity           = get_severity_from_level(level)

    cvss_score = parse_cvss(rule_props)
    if scan_source != "sast":
        severity = dependency_severity(rule, result, level, cvss_score)

    if scan_source == "sast":
        # SAST has no CVSS; derive a pseudo-score from the SARIF level
        score         = SAST_PSEUDO_SCORE.get(level or "", 0.0)
        has_real_score = False
    else:
        score          = cvss_score
        has_real_score = cvss_score is not None

    # ------------------------------------------------------------------
    # Identifiers
    # ------------------------------------------------------------------
    full_desc_text = rule.get("fullDescription", {}).get("text", "")
    cve_id         = extract_cve(full_desc_text)
    cwe            = extract_cwe(rule_props)

    # ------------------------------------------------------------------
    # Title and summary
    # ------------------------------------------------------------------
    title = (
        rule.get("shortDescription", {}).get("text")
        or rule.get("name")
    )

    # SAST: use result.message.text (one concise sentence)
    # SCA/Container: rule shortDescription is already concise
    if scan_source == "sast":
        summary = result.get("message", {}).get("text") or title or ""
    else:
        summary = title or ""

    # ------------------------------------------------------------------
    # Location object
    # ------------------------------------------------------------------
    image_name = image_tag = None   # container only

    if scan_source == "sast":
        location_kind = "source_file"
        pkg_display   = None
        file_display  = artifact_uri or "unknown"
        display       = f"{file_display}:{start_line}" if start_line else file_display
    elif scan_source == "container":
        location_kind = ("os_package" if ecosystem in {"deb", "rpm", "apk"} else
                         "dependency" if ecosystem != "unknown" else "container_package")
        pkg_display   = fqn  # "apparmor@2.10.95-0ubuntu2.11"
        file_display  = artifact_uri or "unknown"
        display       = f"{pkg_display} in {file_display}" if pkg_display else file_display
        image_name, image_tag = parse_container_image(artifact_uri, automation_id)
    else:  # sca
        location_kind = "dependency"
        pkg_display   = fqn  # "body-parser@1.18.3"
        file_display  = artifact_uri or "unknown"
        display       = f"{pkg_display} in {file_display}" if pkg_display else file_display

    location = {
        "kind":       location_kind,
        "file":       file_display,
        "line":       start_line,
        "package":    pkg_display,
        "display":    display,
        "image_name": image_name,
        "image_tag":  image_tag,
    }

    # ------------------------------------------------------------------
    # Dependency chain (SCA only)
    # ------------------------------------------------------------------
    help_md             = rule.get("help", {}).get("markdown")
    dep_path, is_direct = parse_dependency_path(help_md)
    dependency = {"path": dep_path, "is_direct": is_direct} if dep_path is not None else None

    # ------------------------------------------------------------------
    # Remediation
    # ------------------------------------------------------------------
    fixes                = result.get("fixes")
    fixable, upgrade_to  = parse_fix_version(fixes, package_name)
    remediation_evidence = None
    if scan_source == "sca" and ecosystem == "pip" and not fixes:
        remediation_evidence = python_remediation(help_md, package_name, package_version, is_direct)
        if remediation_evidence and remediation_evidence["status"] == "recommended":
            fixable, upgrade_to = True, remediation_evidence["upgrade_to"]
    elif not fixes and scan_source != "sast":
        fixable, upgrade_to = parse_help_upgrade(help_md or rule.get("help", {}).get("text"), package_name, package_version)

    if scan_source == "sast":
        remediation_type = "code_change"
        fixable          = True   # SAST findings are always fixable (code edits)
    elif fixable:
        remediation_type = "version_upgrade"
    else:
        remediation_type = "no_fix"

    remediation = {
        "type":       remediation_type,
        "fixable":    fixable,
        "upgrade_to": upgrade_to,
    }

    # ------------------------------------------------------------------
    # Dedup key and ecosystem
    # ------------------------------------------------------------------
    dedup_key = make_dedup_key(
        scan_source, cve_id, rule_id, package_name, artifact_uri, start_line,
        ecosystem=ecosystem, package_version=package_version, dependency_path=dep_path,
        image_context=automation_id if scan_source == "container" else None,
        remediation=remediation,
    )

    return {
        # Core identity
        "finding_id":    str(uuid.uuid4()),
        "finding_type":  scan_source,
        "provenance": {"scan_source": scan_source, "automation_id": automation_id,
                       "artifact_uri": artifact_uri},
        "package": {"name": package_name, "version": package_version},
        # Severity and score
        "severity":      severity,
        "score":         score,
        "has_real_score": has_real_score,
        # Identifiers
        "identifiers": {
            "cve":     cve_id,
            "cwe":     cwe,
            "rule_id": rule_id,
        },
        # Human-readable
        "title":   title,
        "summary": summary,
        # Where it is
        "location":   location,
        # SAST data flow, source to sink (empty for SCA/container or when not reported)
        "code_flow":  extract_code_flow(result) if scan_source == "sast" else [],
        # Dependency context (SCA only)
        "dependency": dependency,
        # How to fix it
        "remediation": remediation,
        **({"remediation_evidence": remediation_evidence} if remediation_evidence else {}),
        # Priority filled by assign_priorities()
        "priority": None,
        # True if finding is inside node_modules/ — triage skips these
        "is_node_modules": (file_display or "").startswith("node_modules/"),
        # Full details for the fix stage (stripped from lean priority_list)
        "description": full_desc_text if scan_source != "sast" else summary,
        "ecosystem":   ecosystem,
        "dedup_key":   dedup_key,
    }


# ===========================================================================
# SECTION 4: SARIF FILE PROCESSING
# ===========================================================================

def process_sarif_file(sarif_path: Path, *, strict: bool = False) -> list[dict]:
    """
    Parse a single SARIF JSON file and return a list of normalised findings.

    Strict evidence processing rejects extraction failures instead of treating
    skipped results as a completed clean scan. Exploratory callers may skip them.
    """
    sys.stdout.reconfigure(encoding="utf-8")
    print(f"\n  Reading: {sarif_path.name}")
    with sarif_path.open("r", encoding="utf-8") as f:
        sarif = json.load(f)

    findings: list[dict] = []

    for run in sarif.get("runs", []):
        tool_name   = run.get("tool", {}).get("driver", {}).get("name", "")
        scan_source = detect_scan_source(tool_name)
        print(f"    Tool: {tool_name!r} -> scan_source={scan_source!r}")

        rules_list  = run.get("tool", {}).get("driver", {}).get("rules", [])
        rules_by_id = {r["id"]: r for r in rules_list if "id" in r}
        print(f"    Rules defined: {len(rules_by_id)}")

        automation_id = run.get("automationDetails", {}).get("id")

        skipped = 0
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            if not rule_id and isinstance(result.get("ruleIndex"), int):
                index = result["ruleIndex"]
                if 0 <= index < len(rules_list):
                    rule_id = rules_list[index]["id"]
                    result = {**result, "ruleId": rule_id}
            rule    = rules_by_id.get(rule_id, {})
            try:
                finding = extract_finding(result, rule, scan_source, automation_id)
                finding["provenance"]["tool"] = tool_name
                finding["provenance"]["report"] = sarif_path.name
                findings.append(finding)
            except Exception as e:
                if strict:
                    raise ValueError(f"Cannot normalise {sarif_path.name} result {rule_id!r}: {e}") from e
                skipped += 1
                print(
                    f"    [WARN] Skipped result rule_id={rule_id!r}: {e}",
                    file=sys.stderr,
                )

        print(f"    Extracted: {len(findings)} findings  |  Skipped: {skipped}")

    return findings


# ===========================================================================
# SECTION 5: DEDUPLICATION
# ===========================================================================
#
# Merge only identical observation contexts (including remediation).
#
# SAST: every finding has a unique (rule, file, line) key, so no merging
# occurs -- all 315 results stay distinct.

def deduplicate(findings: list[dict]) -> list[dict]:
    """Remove duplicate findings across scan files.  Returns deduplicated list."""
    seen: dict[str, dict] = {}

    for finding in findings:
        key = finding["dedup_key"]
        if key not in seen:
            seen[key] = finding
        else:
            merged = seen[key].get("merged_rule_ids", [seen[key].get("identifiers", {}).get("rule_id") or "unknown"])
            merged = sorted(set(merged + [finding.get("identifiers", {}).get("rule_id") or "unknown"]))
            existing_score = seen[key].get("score") or 0.0
            new_score      = finding.get("score") or 0.0
            if new_score > existing_score:
                seen[key] = finding
            seen[key]["merged_rule_ids"] = merged

    return list(seen.values())


# ===========================================================================
# SECTION 6: SORTING AND PRIORITY ASSIGNMENT
# ===========================================================================
#
# Sort key (precedence order):
#   1. Severity tier        critical=0, high=1, medium=2, low=3
#   2. Real score first     has_real_score=True sorts before False
#   3. Score descending     higher score = more urgent within same tier
#   4. Title ascending      tiebreaker for reproducible ordering

def sort_findings(findings: list[dict]) -> list[dict]:
    """Sort findings from most to least urgent."""

    def sort_key(f: dict) -> tuple:
        sev_rank   = SEVERITY_ORDER.get(f["severity"], 5)
        real_first = 0 if f.get("has_real_score") else 1
        score      = f.get("score") or 0.0
        title      = (f.get("title") or "").lower()
        return (sev_rank, real_first, -score, title)

    return sorted(findings, key=sort_key)


def assign_priorities(findings: list[dict]) -> list[dict]:
    """Add a 1-based integer priority field.  priority=1 is most urgent."""
    for i, finding in enumerate(findings, start=1):
        finding["priority"] = i
    return findings


# ===========================================================================
# SECTION 7: OUTPUT STRUCTURE BUILDERS
# ===========================================================================

def build_ranked_unified(findings: list[dict]) -> list[dict]:
    """
    Build ranked_unified_findings.json: a flat list of all findings sorted
    by priority (most urgent first) with FULL details included.

    This is the single source of truth for the agent pipeline:
      - triage.py reads this instead of priority_list.json
      - Contains all fields unlike the lean priority_list.json
      - Flat list unlike unified_findings.json which is grouped by file

    Internal dedup_key field is stripped as it is not needed downstream.
    """
    strip_fields = {"dedup_key"}
    return [
        {k: v for k, v in f.items() if k not in strip_fields}
        for f in findings
]


# ===========================================================================
# SECTION 8: MAIN ENTRY POINT
# ===========================================================================

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Normalise Snyk SARIF files into ranked_unified_findings.json "
            "for the ASVA agent pipeline."
        )
    )
    parser.add_argument(
        "--inputs",
        nargs="+",
        required=True,
        metavar="FILE",
        help="One or more SARIF .json input files",
    )
    parser.add_argument(
        "--output-dir",
        default="../findings",
        metavar="DIR",
        help="Directory to write output files (created if absent). Default: ../findings",
    )
    parser.add_argument(
        "--scan-run-id",
        default=None,
        help="Explicit scan run ID, e.g. a GitHub Actions run ID. Defaults to a timestamp.",
    )
    parser.add_argument("--app-prefix", default="", help="Repository prefix to strip from finding paths")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("ASVA SARIF Normaliser")
    print("=" * 60)

    print("\n[1/5] Loading SARIF files...")
    scan_run_id = args.scan_run_id or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    all_findings: list[dict] = []
    input_audit = []
    for path_str in args.inputs:
        path = Path(path_str)
        if not path.exists():
            print(f"[ERROR] File not found: {path}", file=sys.stderr)
            sys.exit(1)
        findings_from_file = process_sarif_file(path, strict=True)
        raw = json.loads(path.read_text(encoding="utf-8"))
        input_audit.append({"file": path.name, "extracted": len(findings_from_file), "runs": [
            {"driver": run.get("tool", {}).get("driver", {}).get("name"),
             "results": len(run.get("results", []))} for run in raw.get("runs", [])]})
        for f in findings_from_file:
            f["scan_run_id"] = scan_run_id
            prefix = args.app_prefix.strip("/") + "/"
            location = f["location"]
            if args.app_prefix and location["file"].startswith(prefix):
                location["file"] = location["file"][len(prefix):]
                location["display"] = location["display"].replace(prefix, "")
        all_findings.extend(findings_from_file)
    print(f"\n  Total raw findings across all files: {len(all_findings)}")

    print("\n[2/5] Deduplicating...")
    deduped = deduplicate(all_findings)
    removed = len(all_findings) - len(deduped)
    print(f"  Removed {removed} duplicate(s) -> {len(deduped)} unique findings remain")

    print("\n[3/5] Sorting by severity and score...")
    sorted_findings = sort_findings(deduped)
    prioritised     = assign_priorities(sorted_findings)
    print(f"  Priority range: 1 (most urgent) -> {len(prioritised)} (least urgent)")

    print("\n[4/5] Building output...")
    ranked_unified = build_ranked_unified(prioritised)

    print("\n[5/5] Writing ranked_unified_findings.json...")
    ranked_unified_path = output_dir / "ranked_unified_findings.json"
    (output_dir / "normalisation-audit.json").write_text(json.dumps({
        "scan_run_id": scan_run_id, "inputs": input_audit, "raw_extracted": len(all_findings),
        "normalised": len(prioritised), "deduplicated": removed,
        "merged": [{"finding_id": f["finding_id"], "rule_ids": f["merged_rule_ids"]}
                   for f in prioritised if "merged_rule_ids" in f],
    }, indent=2), encoding="utf-8")
    with ranked_unified_path.open("w", encoding="utf-8") as f:
        json.dump(ranked_unified, f, indent=2, ensure_ascii=False)
    print(f"  Wrote: {ranked_unified_path}  ({ranked_unified_path.stat().st_size:,} bytes)")

    # Summary
    sev_counts: dict[str, int] = {}
    scan_sources: set[str] = set()
    for f in prioritised:
        sev_counts[f["severity"]] = sev_counts.get(f["severity"], 0) + 1
        scan_sources.add(f["finding_type"])

    print("\n" + "=" * 60)
    print("SUMMARY")
    print("=" * 60)
    print(f"  Scan sources : {', '.join(sorted(scan_sources))}")
    print(f"  Total unique : {len(prioritised)}")
    for level in ("critical", "high", "medium", "low", "info", "unknown"):
        count = sev_counts.get(level, 0)
        if count:
            bar = "#" * min(count, 40)
            print(f"    {level:8s}: {count:4d}  {bar}")
    print("\nDone.\n")


if __name__ == "__main__":
    main()

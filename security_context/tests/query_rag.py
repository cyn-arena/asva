#!/usr/bin/env python3
"""End-to-end demo/test against a running Security Context Service, using real ASVA findings.

For each file it walks through the pipeline step by step:
  1. the finding(s) from the scan (SARIF -> ASVA normaliser -> triage batch)
  2. the identifiers the scan gave us (CWE / CVE / package / image)
  3. what the service did: search queries, NVD / KEV / OSV.dev / Context7 / Docker Hub lookups
  4. the context for the LLM prompt (size-budgeted)
  5. the upgrade data (dependency and container files): targets as data, for the agent and the PR
  6. the trial plan (dependency and container files): the upgrades held back, in the order to try
     them one at a time, with what else each needs (for the PR, not sent to the LLM)
  7. the references for the PR body / UI (not sent to the LLM)
  8. a check of the expected content, within the size budget

The findings are real NodeGoat findings from the ASVA pipeline (Snyk SARIF -> normaliser ->
triage), hardcoded in tests/fixtures/nodegoat_findings.json. One request per file, as the
agent sends them. The default run is the five files shown at the POC:
  3 SAST   app/routes/contributions.js (eval injection x3), profile.js (ReDoS), research.js (SSRF)
  1 SCA    package.json        (26 dependency findings)
  1 image  docker-compose.yml  (7 container findings, mongo:4.4)
--all adds the other two files of the scan: app/routes/index.js (open redirect) and
config/env/development.js (hardcoded secret).

--app pygoat uses PyGoat's findings instead (tests/fixtures/pygoat_findings.json, from a pipeline
run): its requirements.txt (62 dependency findings), and with --all also its six code files. There
are no expected-content checks for PyGoat. For a dependency file, the file itself is sent too
(tests/fixtures/<app>_files/), as ASVA would for the trial plan.

The first run looks CVEs, packages and the image up online and is slower; later runs use the cache.

    python tests/query_rag.py                        # the five cases
    python tests/query_rag.py --all                  # all seven
    python tests/query_rag.py --only package         # one case (live demo)
    python tests/query_rag.py --app pygoat           # PyGoat's requirements.txt, with its trial plan
    python tests/query_rag.py --only research --full
    python tests/query_rag.py --only docker --compare osv      # the case with and without a source
    python tests/query_rag.py --without context7 --without kev # answer without these sources

Sources that can be left out: cwe, owasp, nvd, kev, osv, context7, dockerhub, endoflife,
and "keyword" (the keyword fallback of the OWASP search).
"""

import argparse
import json
import re
import sys
import textwrap
from collections import Counter
from pathlib import Path

import httpx

FIXTURES = Path(__file__).parent / "fixtures"
APPS = {"nodegoat": ("NodeGoat", "nodegoat_findings.json", "nodegoat_files"),  # findings, dependency files
        "pygoat": ("PyGoat", "pygoat_findings.json", "pygoat_files")}
BUDGET = 2500  # the service default (DEFAULT_MAX_CHARS)
WIDTH = 100
PREVIEW_CHARS = 320

SCANNERS = {"sast": "Snyk Code (SAST)", "sca": "Snyk Open Source (SCA)", "container": "Snyk Container"}
KIND_LABELS = {"guidance": "OWASP", "cwe": "MITRE CWE", "upgrade_notes": "Upgrade notes",
               "library_notes": "Context7", "container_summary": "Container", "kev": "CISA KEV"}
ALLOWLIST = ["allowlist", "allow list", "allow-list", "whitelist"]

# What a useful answer contains, per file: the cheat sheet that should be found, the key
# advice that should be in the prompt (any listed phrase counts), the OWASP Top 10 label.
CASES = {
    "app/routes/contributions.js": {
        "expect_docs": {"Nodejs_Security_Cheat_Sheet", "Injection_Prevention_Cheat_Sheet"},
        "key_advice": {"avoid eval / dynamic code": ["should only be used where necessary", "do not have to dynamically generate code", "avoid"],
                       "validate input (allowlist)": ["input validation", "accept known good", *ALLOWLIST]},
        "top10": "A03:2021 - Injection",
    },
    "app/routes/profile.js": {
        "expect_docs": {"Nodejs_Security_Cheat_Sheet", "JavaScript_and_TypeScript_Security_Cheat_Sheet"},
        "key_advice": {"cause: nested repetition in the regex": ["grouping with repetition", "nested quantif", "overlapping"]},
    },
    "app/routes/research.js": {
        "expect_docs": {"Server_Side_Request_Forgery_Prevention_Cheat_Sheet"},
        "key_advice": {"allowlist of targets": ALLOWLIST, "validate the URL/input": ["validat"]},
        "top10": "A10:2021 - Server-Side Request Forgery (SSRF)",
    },
    "package.json": {
        "key_advice": {"mongodb 2.x → 3.x flagged as a major upgrade": ["mongodb 2.2.36 → 3.1.13: major version change"],
                       "forever already at its target (bump can't fix)": ["forever 2.0.0 → 2.0.0: already at the target"],
                       "transitive qs fixed via body-parser": ["body-parser 1.18.3 → 1.20.4"]},
        # shown, but not required: these come from online sources that may be unavailable or have no key
        "optional_advice": {"targets confirmed independently (OSV.dev)": ["osv.dev confirms"],
                            "no compatible fix for mongodb, none within 2.x (OSV.dev)": ["no fix within 2.x"]},
        "upgrade_data": {"compatible targets for body-parser, marked and underscore, none for mongodb":
                         lambda u: {x["name"] for x in u if x.get("compatible_target")} == {"body-parser", "marked", "underscore"},
                         "smallest fixed version of marked (OSV.dev)": lambda u: any(x["name"] == "marked" and x.get("min_fixed") for x in u)},
    },
    "docker-compose.yml": {
        "key_advice": {"fixes are subscription-only, in the source's words": ["available with ubuntu pro"],
                       "says the image line is past end of life": ["mongo 4.4 is past end of life"],
                       "says there is no compatible (same major version) fix": ["compatible fix (same major version, 4.x): none"],
                       "warns a new major version is not a drop-in change": ["not a drop-in"]},
        "upgrade_data": {"migration target as data, and no compatible target":
                         lambda u: any(x["kind"] == "image" and x.get("target") and not x.get("compatible_target") for x in u),
                         "newer release lines with base OS and support dates as data":
                         lambda u: any(c.get("base_os") and c.get("supported_until") for x in u for c in x.get("candidates") or [])},
    },
    # the two further files of the scan (--all)
    "app/routes/index.js": {
        "extra": True,
        "expect_docs": {"Unvalidated_Redirects_and_Forwards_Cheat_Sheet"},
        "key_advice": {"allowlist of targets": [*ALLOWLIST, "list of trusted urls"], "validate the URL": ["validat"]},
        "top10": "A01:2021 - Broken Access Control",
    },
    "config/env/development.js": {
        "extra": True,
        "expect_docs": {"Web_Frontend_Security_Cheat_Sheet", "Secrets_Management_Cheat_Sheet", "Nodejs_Security_Cheat_Sheet"},
        "key_advice": {"keep secrets out of code (environment / secrets manager)":
                       ["environment variable", "vault", "secrets manag", "secret manag", "key management", "secret store"]},
        # Neither the similarity search nor the keyword fallback reaches the Secrets Management cheat sheet for this finding.
        "known_gaps": {"keep secrets out of code (environment / secrets manager)"},
    },
}


# -- the hardcoded real findings ------------------------------------------------------------

def load_fixture(app: str = "nodegoat") -> dict:
    _, findings_file, files_dir = APPS[app]
    fixture = json.loads((FIXTURES / findings_file).read_text(encoding="utf-8"))
    if app == "nodegoat":
        by_file = {entry["file"]: entry for entry in fixture["files"]}
        fixture["files"] = [by_file[name] for name in CASES if name in by_file]
    else:  # the dependency file first
        fixture["files"].sort(key=lambda entry: entry["finding_type"] != "sca")
    for entry in fixture["files"]:
        manifest = FIXTURES / files_dir / entry["file"]
        if entry["finding_type"] == "sca" and manifest.exists():
            entry["manifest"] = {"file": entry["file"], "content": manifest.read_text(encoding="utf-8")}
    return fixture


def to_request(finding: dict) -> dict:
    """Normalised ASVA finding -> the lean fields the service takes."""
    ids, location, remediation = finding["identifiers"], finding["location"], finding["remediation"]
    return {
        "finding_type": finding["finding_type"], "cve": ids.get("cve"), "cwe": ids.get("cwe"),
        "cwes": finding.get("sarif_cwes") or None,  # the CWE ids on the scanner's rule (SARIF tags)
        "rule_id": ids.get("rule_id"), "package": location.get("package"), "ecosystem": finding.get("ecosystem"),
        "upgrade_to": remediation.get("upgrade_to"), "fixable": remediation.get("fixable"),
        "dependency_path": (finding.get("dependency") or {}).get("path"),
        "image_name": location.get("image_name"), "image_tag": location.get("image_tag"),
        "title": finding.get("title"), "summary": finding.get("summary"), "description": finding.get("description"),
    }


# -- output helpers -------------------------------------------------------------------------

def step(n: int, title: str) -> None:
    print(f"\n  {n}) {title}")


def line(text: str, indent: int = 5) -> None:
    print(textwrap.fill(text, WIDTH, initial_indent=" " * indent, subsequent_indent=" " * (indent + 2)))


def block(text: str, indent: int = 9) -> None:
    for paragraph in text.splitlines():
        if paragraph.strip():
            print(textwrap.fill(paragraph.strip(), WIDTH, initial_indent=" " * indent, subsequent_indent=" " * (indent + 2)))


def short_section(section: str | None) -> str:
    parts = (section or "(intro)").split(" > ")
    return " › ".join(parts if len(parts) <= 2 else ["…"] + parts[-2:])


def counted(values) -> str:
    counts = Counter(v for v in values if v)
    return ", ".join(f"{v} ×{n}" if n > 1 else v for v, n in counts.most_common()) or "none"


def readable(markdown: str) -> str:
    """Preview only: markdown links to their label, emphasis markers dropped."""
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", markdown)
    return re.sub(r"(\*\*|__|\*(?=\S)|(?<=\S)\*)", "", text)


def severity(f: dict) -> str:
    """Snyk titles can say "Low severity" while ASVA rates the finding critical (CVSS >= 9.0
    promotion), so show the score next to the normalised severity."""
    return f"{f['severity']} · CVSS {f['score']}" if f.get("has_real_score") else f["severity"]


def item_label(item: dict) -> str:
    label = KIND_LABELS.get(item["kind"], item["kind"])
    if item["kind"] != "guidance":
        return f"[{label}]  {item['title']}"
    how = "keyword match" if item.get("matched_by") == "keyword" else f"{item['score']:.3f}"
    return f"[{label} {how}]  {item['title']}  ›  {short_section(item['section'])}"


def show_findings(findings: list[dict], kind: str, max_findings: int) -> None:
    if kind == "sast":  # identical findings on several lines are listed once
        groups: dict[tuple, list] = {}
        for f in findings:
            groups.setdefault((f["title"], f["identifiers"]["rule_id"], f["summary"], f["severity"]), []).append(f)
        shown = list(groups.items())[:max_findings]
        for (title, rule_id, summary, _), group in shown:
            lines = ", ".join(str(f["location"]["line"]) for f in group if f["location"].get("line"))
            line(f"[{severity(group[0])}] {title}  —  {group[0]['location']['file']}" + (f":{lines}" if lines else ""))
            line(f"rule {rule_id}: {summary}", indent=9)
        remaining = len(groups) - len(shown)
    else:
        for f in findings[:max_findings]:
            line(f"[{severity(f)}] {f['title']}")
            line(f"{f['location'].get('package')}  →  upgrade to {f['remediation'].get('upgrade_to')}"
                 f"   ({f['identifiers'].get('cve') or f['identifiers']['rule_id']})", indent=9)
        remaining = len(findings) - max_findings
    if remaining > 0:
        line(f"… and {remaining} more")


def show_upgrades(upgrades: list[dict]) -> None:
    for u in upgrades:
        if u["kind"] == "image":
            target = f"{u['name']}:{u['target']}" if u.get("target") else "no line suggested"
            compatible = f"{u['name']}:{u['compatible_target']}" if u.get("compatible_target") else "none"
            line(f"image {u['name']}:{u['current']} ({u.get('ecosystem') or 'base OS unknown'})  →  compatible fix: {compatible};  "
                 f"migration target: {target}   [{u['status']}{', MAJOR change' if u['major_change'] else ''}]")
            for c in u.get("candidates") or []:
                state = "past end of life" if c.get("end_of_life") else (
                    f"supported until {c['supported_until']}" if c.get("supported_until") else "support dates unknown")
                resolved = f", {c['cves_resolved']}/{c['cves_checked']} CVEs resolved" if c.get("cves_checked") else ""
                line(f"{u['name']}:{c['tag']}  {c.get('version') or '?'} on {c.get('base_os') or '?'}{resolved}, {state}", indent=9)
        else:
            extras = [f"compatible fix {u['compatible_target']}" if u.get("compatible_target")
                      else "nothing to bump" if u["status"] == "already_at_target" else "no compatible fix",
                      f"smallest fix {u['min_fixed']}" if u.get("min_fixed") else None]
            line(f"{u['name']} {u.get('current') or '?'}  →  {u.get('target') or 'no target'}   [{u['status']}]   "
                 + ", ".join(e for e in extras if e))
            if u.get("note"):
                line(u["note"], indent=9)


def show_references(refs: list[dict], max_listed: int) -> None:
    by_type: dict[str, list] = {}
    for ref in refs:
        by_type.setdefault(ref["type"], []).append(ref)
    for ref in sorted(by_type.get("cve", []), key=lambda r: -(r.get("cvss") or 0))[:max_listed]:
        exploited = "  ⚠ KNOWN EXPLOITED (CISA KEV)" if ref.get("kev") else ""
        score = f"CVSS {ref['cvss']} {ref['severity']}" if ref.get("cvss") is not None else "no CVSS"
        line(f"[NVD]    {ref['id']}  {score}  {', '.join(ref.get('cwes') or []) or ''}{exploited}")
    if len(by_type.get("cve", [])) > max_listed:
        line(f"… and {len(by_type['cve']) - max_listed} more CVEs")
    cwes = by_type.get("cwe", [])
    for ref in cwes[:max_listed]:
        top10 = f"  OWASP Top 10: {'; '.join(ref['owasp_top10'])}" if ref.get("owasp_top10") else ""
        line(f"[CWE]    {ref['id']}: {ref.get('title') or ''}{top10}")
    if len(cwes) > max_listed:
        line(f"… and {len(cwes) - max_listed} more CWEs")
    if cwes and cwes[0].get("description"):
        line(f"each with MITRE's definition and mitigations, e.g. {cwes[0]['id']}: {cwes[0]['description'][:150]} …", indent=9)
        if cwes[0].get("mitigations"):
            line(f"mitigation: {cwes[0]['mitigations'][0][:170]} …", indent=9)
    advisories = by_type.get("advisory", [])
    distro = [a for a in advisories if a.get("availability")]
    packages = [a for a in advisories if not a.get("availability")]
    if packages:
        beyond = [a for a in packages if a.get("beyond_target")]
        line(f"[OSV]    {len(packages)} advisories checked" +
             (f"; {len(beyond)} stay open after the target upgrade, e.g. "
              f"{beyond[0]['package']}: {(beyond[0].get('aliases') or [beyond[0]['id']])[0]} (fixed in {beyond[0].get('fixed_in') or 'no fix'})"
              if beyond else ""))
    for ref in distro[:2]:
        line(f"[OSV]    {ref['id']}  {ref['package']} fixed in {ref['fixed_in']}  —  {ref['availability']}")
    if len(distro) > 2:
        line(f"… and {len(distro) - 2} more OS-package fixes with their availability")
    for ref in by_type.get("guidance", []):
        line(f"[OWASP]  {ref['title']}")
    for ref in by_type.get("library_docs", [])[:3]:
        line(f"[Docs]   {ref.get('package') or ''}: {ref['title']}  ({ref['source']})")
        if ref.get("description"):
            line(ref["description"][:200], indent=13)
    for ref in by_type.get("image", []):
        line(f"[Image]  {ref['title']}  ({ref['source']}: {ref['url']})")


# -- the demo -------------------------------------------------------------------------------

def show_trials(trials: list[dict]) -> None:
    for t in trials:
        what = f"{t['name']} {t.get('current') or '?'} → {t['target']}" if t.get("target") else t["note"].split(":")[0].strip("`")
        exploited = f", known exploited: {', '.join(t['known_exploited'])}" if t.get("known_exploited") else ""
        line(f"{t['order']:>2}. {what}   fixes {len(t['fixes'])}{exploited}" + ("   [dev tools only]" if t.get("dev_only") else ""))
        for c in t.get("also_needs") or []:
            line(f"also needs {c['name']} {c.get('current') or ''} → {c.get('suggest') or '?'}  ({c['reason']})", indent=9)


def ask(client: httpx.Client, entry: dict, exclude: list[str]) -> dict:
    payload = {"fix_type": entry["fix_type"], "findings": [to_request(f) for f in entry["findings"]], "debug": True}
    if entry.get("manifest"):
        payload["manifest"] = entry["manifest"]
    if exclude:
        payload["exclude_sources"] = exclude
    response = client.post("/v1/context", json=payload, timeout=180)
    response.raise_for_status()
    return response.json()


def show_case(number: int, total: int, entry: dict, client: httpx.Client, full: bool, max_findings: int,
              exclude: list[str], compare: str | None) -> dict:
    findings = entry["findings"]
    request_findings = [to_request(f) for f in findings]
    kind = entry["finding_type"]
    case = CASES.get(entry["file"])  # None: no expected content defined (PyGoat)

    print("\n" + "═" * WIDTH)
    print(f" CASE {number}/{total}   {entry['file']}   ({SCANNERS.get(kind, kind)}, {len(findings)} finding(s))")
    print("═" * WIDTH)

    step(1, f"Finding(s) from the scan   (SARIF → ASVA normaliser → triage batch {entry['batch_id']})")
    show_findings(findings, kind, max_findings)

    step(2, "Identifiers from the scan")
    own = [r["cwe"] for r in request_findings if r["cwe"]]
    tagged = [c for r in request_findings for c in (r["cwes"] or [])]
    if own:
        line(f"CWE: {counted(own)}")
    elif tagged:
        line(f"CWE: {len(set(tagged))} distinct, from the scanner's rule tags in the SARIF file — {', '.join(list(dict.fromkeys(tagged))[:5])}"
             f"{' …' if len(set(tagged)) > 5 else ''}")
    else:
        line("CWE: none from the scanner (resolved from the CVEs via NVD, below)")
    cves = list(dict.fromkeys(r["cve"] for r in request_findings if r["cve"]))
    line(f"CVE: {len(cves)} distinct — {', '.join(cves[:4])}{' …' if len(cves) > 4 else ''}" if cves else "CVE: none")
    if kind == "sca":
        line(f"packages: {counted(r['package'].rsplit('@', 1)[0] for r in request_findings if r['package'])}")
    if kind == "container":
        image = next((f"{r['image_name']}:{r['image_tag']}" for r in request_findings if r.get("image_name")), "not named by the scan")
        line(f"image: {image};  OS packages: {counted(r['package'].rsplit('@', 1)[0] for r in request_findings if r['package'])}")

    body = ask(client, entry, exclude)
    debug = body.get("debug") or {}

    step(3, f"What the service did   (POST /v1/context, fix_type {entry['fix_type']})")
    if debug.get("excluded_sources"):
        line(f"answering WITHOUT: {', '.join(debug['excluded_sources'])}")
    for query in debug.get("queries", []):
        line("OWASP search query:")
        line(f"\"{query['text']}\"", indent=9)
        line(f"best similarity {query['best_similarity']}" + (f";  title match boosted: {query['title_match']}" if query.get("title_match") else ""), indent=9)
        if query.get("keyword_fallback"):
            line(f"low confidence → keyword fallback added: {'; '.join(short_section(s) for s in query['keyword_fallback'])}", indent=9)
    if debug.get("guidance_search", "").startswith("skipped"):
        line(f"OWASP search: {debug['guidance_search']}")
    cve_info = debug.get("cves") or {}
    if cve_info.get("requested"):
        line(f"NVD: {cve_info['found_in_nvd']} of {cve_info['requested']} CVEs found;  "
             f"CISA KEV: {len(cve_info['known_exploited'])} known exploited")
    resolved = debug.get("resolved_cwes", [])
    line(f"CWE lookup: {', '.join(resolved[:8]) or 'none'}{f' … ({len(resolved)} in all)' if len(resolved) > 8 else ''}")
    if debug.get("osv_checked"):
        line(f"OSV.dev cross-check: {', '.join(debug['osv_checked'])}")
    for lib in debug.get("library_notes", []):
        where = "in the prompt" if lib.get("in_prompt") else "to the references, for the migration"
        line(f"Context7: {lib['package']} → {lib['library'] or 'not found'} ({lib['snippets']} breaking-change notes, {where})")
    if container := debug.get("container"):
        data = container["fix_data"]
        line(f"OSV.dev (Ubuntu's security data), {container['base_os']}: {data['checked']} CVEs checked — "
             f"{data['subscription']} fixed for subscribers only, {data['standard']} in the standard repositories")
        line(f"Docker Hub: newer lines of {container['image']} → {', '.join(container['newer_lines']) or 'none found'};  "
             f"suggested by rule: {container['suggested'] or 'none'}")

    items = body["items"]
    total_chars = sum(len(i["text"]) for i in items)
    step(4, f"Context for the LLM prompt   ({len(items)} item(s), {total_chars:,} / {BUDGET:,} chars ≈ {total_chars // 4:,} tokens)"
            + ("" if full else "   [preview; --full for the exact text]"))
    if not items:
        line("(nothing)")
    for item in items:
        line(item_label(item))
        text = item["text"] if full else readable(item["text"])
        if not full and len(text) > PREVIEW_CHARS and item["kind"] in ("guidance", "library_notes"):
            text = text[:PREVIEW_CHARS] + " …"
        block(text)
    for warning in body["warnings"]:
        line(f"warning: {warning}")

    number_of_step = 5
    if body.get("upgrades"):
        step(number_of_step, f"Upgrade data   ({len(body['upgrades'])} entr{'y' if len(body['upgrades']) == 1 else 'ies'}, as data for the agent and the PR)")
        show_upgrades(body["upgrades"])
        number_of_step += 1
    if body.get("trials"):
        step(number_of_step, f"Upgrades to try next, one at a time   ({len(body['trials'])}, the trial plan for the PR, "
                             "not sent to the LLM)")
        show_trials(body["trials"])
        number_of_step += 1

    step(number_of_step, f"References for the PR / UI   ({len(body['references'])}, not sent to the LLM)")
    show_references(body["references"], max_listed=5 if not full else 50)

    if case is None:
        ok, gaps = None, 0
    else:
        ok, notes, gaps = check(case, body, kind, total_chars)
        step(number_of_step + 1, f"Check: {'PASS' if ok else 'FAIL'}" + (f" ({gaps} known gap)" if gaps else ""))
        for note in notes:
            line(note)

    if compare and case is not None:
        show_comparison(client, entry, case, kind, body, compare, exclude)
    return {"file": entry["file"], "type": kind, "findings": len(findings), "chars": total_chars,
            "refs": len(body["references"]), "ok": ok, "gaps": gaps}


def check(case: dict, body: dict, kind: str, total: int) -> tuple[bool, list[str], int]:
    items, refs = body["items"], body["references"]
    text = "\n".join(f"{i['title'] or ''} {i['section'] or ''}\n{i['text']}" for i in items).lower()
    ok, gaps = total <= BUDGET, 0
    notes = [f"{'✓' if ok else '✗'} size {total:,} ≤ {BUDGET:,} chars"]
    if kind == "sast":
        has_doc = bool(case["expect_docs"] & {i["key"] for i in items if i["kind"] == "guidance"})
        ok &= has_doc
        notes.append(f"{'✓' if has_doc else '✗'} expected cheat sheet: {' or '.join(sorted(case['expect_docs']))}")
        if case.get("top10"):
            labelled = any(case["top10"] in (r.get("owasp_top10") or []) for r in refs if r["type"] == "cwe")
            ok &= labelled
            notes.append(f"{'✓' if labelled else '✗'} OWASP Top 10 label: {case['top10']}")
        explained = any(r.get("description") and r.get("mitigations") for r in refs if r["type"] == "cwe")
        ok &= explained
        notes.append(f"{'✓' if explained else '✗'} CWE definition and mitigations in the references")
    else:
        enriched = sum(1 for r in refs if r["type"] == "cve" and r.get("cvss") is not None)
        notes.append(f"{'✓' if enriched else '✗'} {enriched} CVE(s) enriched from NVD (CVSS, CWE)")
        ok &= enriched > 0
        labelled = sum(1 for r in refs if r["type"] == "cwe")
        notes.append(f"{'✓' if labelled else '✗'} {labelled} CWE(s) resolved for these findings")
        ok &= labelled > 0
    for advice, keywords in case["key_advice"].items():
        present = any(k.lower() in text for k in keywords)
        if not present and advice in case.get("known_gaps", ()):
            gaps += 1
            notes.append(f"✗ {advice}   (known gap, see evaluation/results.md)")
            continue
        ok &= present
        notes.append(f"{'✓' if present else '✗'} {advice}")
    for advice, keywords in case.get("optional_advice", {}).items():
        present = any(k.lower() in text for k in keywords)
        notes.append(f"{'✓' if present else '–'} {advice}" + ("" if present else "   (not in this answer; optional)"))
    for label, predicate in case.get("upgrade_data", {}).items():
        present = bool(predicate(body.get("upgrades") or []))
        ok &= present
        notes.append(f"{'✓' if present else '✗'} upgrade data: {label}")
    return ok, notes, gaps


def show_comparison(client: httpx.Client, entry: dict, case: dict, kind: str, with_all: dict, source: str,
                    exclude: list[str]) -> None:
    """The same request again without one source: what the answer loses, and what it saves."""
    without = ask(client, entry, sorted({*exclude, source}))
    before, after = sum(len(i["text"]) for i in with_all["items"]), sum(len(i["text"]) for i in without["items"])
    print("\n  " + "─" * (WIDTH - 4))
    print(f"  WITHOUT {source.upper()}   (same request, exclude_sources: [{source}])")
    line(f"prompt context: {before:,} → {after:,} chars ({after - before:+,});  references: "
         f"{len(with_all['references'])} → {len(without['references'])};  upgrade entries: "
         f"{len(with_all.get('upgrades') or [])} → {len(without.get('upgrades') or [])}")
    line("context without it:")
    if not without["items"]:
        line("(nothing)", indent=9)
    for item in without["items"]:
        line(item_label(item), indent=9)
        if item["kind"] not in ("guidance", "library_notes"):
            block(readable(item["text"]), indent=13)
    _, notes_with, _ = check(case, with_all, kind, before)
    _, notes_without, _ = check(case, without, kind, after)
    lost = [b for a, b in zip(notes_with, notes_without) if a.startswith("✓") and not b.startswith("✓")]
    line("checks that no longer hold: " + ("none" if not lost else ""))
    for note in lost:
        line(note, indent=9)
    kinds_with, kinds_without = Counter(r["type"] for r in with_all["references"]), Counter(r["type"] for r in without["references"])
    changed = {k: (kinds_with[k], kinds_without.get(k, 0)) for k in kinds_with if kinds_with[k] != kinds_without.get(k, 0)}
    if changed:
        line("references: " + ", ".join(f"{k} {a} → {b}" for k, (a, b) in changed.items()))
    fields = ("cvss", "kev", "owasp_top10", "description", "availability")
    for name in fields:
        a = sum(1 for r in with_all["references"] if r.get(name))
        b = sum(1 for r in without["references"] if r.get(name))
        if a != b:
            line(f"references with {name}: {a} → {b}", indent=9)
    for name in ("compatible_target", "min_fixed", "target", "candidates"):
        a = sum(1 for u in with_all.get("upgrades") or [] if u.get(name))
        b = sum(1 for u in without.get("upgrades") or [] if u.get(name))
        if a != b:
            line(f"upgrade entries with {name}: {a} → {b}", indent=9)


def run(url: str, full: bool, only: str | None, everything: bool, max_findings: int, exclude: list[str],
        compare: str | None, app: str = "nodegoat") -> bool:
    fixture = load_fixture(app)

    def default(entry: dict) -> bool:
        return not CASES[entry["file"]].get("extra") if app == "nodegoat" else entry["finding_type"] == "sca"

    entries = [e for e in fixture["files"] if (only.lower() in e["file"].lower() if only else everything or default(e))]
    if not entries:
        sys.exit(f"No case matches --only {only!r}; files: {', '.join(e['file'] for e in fixture['files'])}")

    with httpx.Client(base_url=url, timeout=60) as client:
        health = client.get("/healthz").json()
        print(f"RAG Security Context Service  {url}  ({health['status']})")
        for source, state in health["snapshot"].items():
            print(f"  {source}: {state['version']}, {state['items']} items")
        online = health.get("online", {})
        print(f"  online lookups: {'on' if online.get('lookups') else 'off'}; NVD key: {'yes' if online.get('nvd_api_key') else 'no'} "
              f"({online.get('nvd_sync_mode')} mode); Context7: {'yes' if online.get('context7') else 'no key'}")
        if health.get("disabled_sources"):
            print(f"  sources switched off in the configuration: {', '.join(health['disabled_sources'])}")
        src = fixture["source"]
        print(f"Findings: {APPS[app][0]} scan run {src['scan_run_id']} @ {src['commit_sha']} (hardcoded in {APPS[app][1]})")
        results = [show_case(n, len(entries), e, client, full, max_findings, exclude, compare) for n, e in enumerate(entries, 1)]

    print("\n" + "═" * WIDTH + "\n SUMMARY" + (f"   (without: {', '.join(exclude)})" if exclude else "") + "\n" + "═" * WIDTH)
    print(f"  {'File':32} {'Type':10} {'Findings':>8} {'Prompt context':>16} {'References':>11}  Result")
    for r in results:
        result = ("not checked" if r["ok"] is None else "PASS" if r["ok"] else "FAIL") + (f" ({r['gaps']} known gap)" if r["gaps"] else "")
        print(f"  {r['file']:32} {r['type']:10} {r['findings']:>8} {r['chars']:>10,} chars {r['refs']:>11}  {result}")
    total = sum(r["chars"] for r in results)
    print(f"\n  Total prompt context: {total:,} chars (≈ {total // 4:,} tokens)")
    passed = all(r["ok"] is not False for r in results)
    if any(r["ok"] is not None for r in results):
        print(f"  {'ALL PASSED' if passed else 'SOME CASES FAILED'}")
    else:
        print("  No expected-content checks for these files.")
    return passed


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")  # cheat sheets contain non-ASCII text; also safe when redirected to a file
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default="http://localhost:8800")
    parser.add_argument("--app", choices=sorted(APPS), default="nodegoat", help="Whose findings to use (default nodegoat).")
    parser.add_argument("--full", action="store_true", help="Print the full context text and every reference.")
    parser.add_argument("--only", metavar="TEXT", help="Run only the case(s) whose file name contains TEXT.")
    parser.add_argument("--all", action="store_true", help="Also run index.js and development.js (seven cases).")
    parser.add_argument("--without", action="append", default=[], metavar="SOURCE",
                        help="Answer without this source (repeatable), e.g. --without osv.")
    parser.add_argument("--compare", metavar="SOURCE",
                        help="After each case, show the same request without this source and what was lost.")
    parser.add_argument("--max-findings", type=int, default=4, help="Findings listed per case in step 1 (default 4).")
    args = parser.parse_args()
    sys.exit(0 if run(args.url, args.full, args.only, args.all, args.max_findings, args.without, args.compare, args.app) else 1)

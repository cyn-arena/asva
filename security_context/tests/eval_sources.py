#!/usr/bin/env python3
"""What does each source contribute? Runs every demo case with all sources, then again
without each source in turn, and reports what was lost and how much prompt text was saved.

Purpose: to show which sources earn their place, and which could be dropped so that less
text is sent to the LLM (attention dilution). It reads tests/fixtures only and runs the
service's code in-process against the local database (python -m app.sync first), with
online lookups as configured in .env. The first run looks CVEs, packages and images up
online and is slower; later runs use the cache.

    python tests/eval_sources.py                 # writes evaluation/results.md and results.json
    python tests/eval_sources.py --offline       # cached lookups only

Three parts:
  1. per source: the facts the answer loses without it, and the prompt characters it costs
  2. per case: where the prompt characters go, and the facts lost per source
  3. OWASP search quality over NodeGoat's own-code SAST issue types: similarity search,
     keyword search, similarity with the keyword fallback, and the effect of the CWE name
  4. how much OWASP text is needed: coverage against the number and length of sections

A "fact" is something a useful answer should contain, checked mechanically (a phrase in the
prompt text, or a field in the references / upgrade data). The lists are in this file.
"""

import argparse
import json
import sys
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app import config, net, store  # noqa: E402
from app.context import ContextBuilder  # noqa: E402
from app.embed import Embedder  # noqa: E402
from app.retrieve import Retriever  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"
OUT_DIR = ROOT / "evaluation"
BUDGET = config.DEFAULT_MAX_CHARS

SOURCES = {  # id -> (name, what it is used for)
    "owasp": ("OWASP Cheat Sheet Series", "how-to-fix guidance for code findings (similarity search)"),
    "cwe": ("MITRE CWE", "weakness name in the search query; definition, mitigations and OWASP Top 10 label in references"),
    "keyword": ("Keyword fallback", "keyword matches when the similarity search is unsure (a method, not a source)"),
    "nvd": ("NVD", "CVSS score, severity and CWE per CVE"),
    "kev": ("CISA KEV", "flags CVEs known to be exploited"),
    "osv": ("OSV.dev", "cross-checks upgrade targets; smallest fixed version; where an OS package fix is published"),
    "context7": ("Context7", "breaking-change notes for major library upgrades (in the references, for the migration)"),
    "dockerhub": ("Docker Hub", "newer release lines of a container image and their base OS; decides whether a compatible line exists"),
    "registries": ("Package registries (PyPI, npm)", "what each package version requires: companion and parent upgrades in "
                   "the trial plan (not in the prompt; measured in evaluation/trial_results.md)"),
    "endoflife": ("endoflife.date", "whether the image's line is past end of life; support dates, needed to name a migration target"),
}

# An extra case to show what CISA KEV does: none of NodeGoat's CVEs are in the catalogue.
KEV_ILLUSTRATION = {
    "file": "(illustration) pom.xml with Log4Shell", "finding_type": "sca", "fix_type": "version_upgrade", "illustration": True,
    "findings": [{"finding_type": "sca", "severity": "critical", "title": "Remote Code Execution in log4j-core",
                  "summary": "Remote Code Execution in log4j-core", "description": "(CVE-2021-44228) log4j-core",
                  "identifiers": {"cve": "CVE-2021-44228", "cwe": None, "rule_id": "SNYK-JAVA-ORGAPACHELOGGINGLOG4J-2314720"},
                  "location": {"package": "org.apache.logging.log4j:log4j-core@2.14.1"},
                  "remediation": {"upgrade_to": "org.apache.logging.log4j:log4j-core@2.17.1", "fixable": True},
                  "ecosystem": "maven", "sarif_cwes": ["CWE-502"], "dependency": None}],
}


def to_request(finding: dict) -> dict:
    """Normalised ASVA finding -> the fields the service takes (as integration/asva_rag_client.py does)."""
    ids, location, remediation = finding["identifiers"], finding["location"], finding["remediation"]
    return {
        "finding_type": finding["finding_type"], "cve": ids.get("cve"), "cwe": ids.get("cwe"),
        "cwes": finding.get("sarif_cwes") or None, "rule_id": ids.get("rule_id"),
        "package": location.get("package"), "ecosystem": finding.get("ecosystem"),
        "upgrade_to": remediation.get("upgrade_to"), "fixable": remediation.get("fixable"),
        "dependency_path": (finding.get("dependency") or {}).get("path"),
        "image_name": location.get("image_name"), "image_tag": location.get("image_tag"),
        "title": finding.get("title"), "summary": finding.get("summary"), "description": finding.get("description"),
    }


# -- facts ----------------------------------------------------------------------------------

def prompt_text(result: dict) -> str:
    """What the LLM sees: each item's title, section and text."""
    return "\n".join(f"{i['title'] or ''} {i['section'] or ''}\n{i['text']}" for i in result["items"]).lower()


def has_phrase(*phrases):
    return lambda result: any(p in prompt_text(result) for p in phrases)


def refs(result, kind):
    return [r for r in result["references"] if r["type"] == kind]


REFERENCE_FACTS_CODE = [
    ("weakness named and defined (MITRE CWE)", "references", lambda r: any(x.get("description") for x in refs(r, "cwe"))),
    ("mitigations listed (MITRE CWE)", "references", lambda r: any(x.get("mitigations") for x in refs(r, "cwe"))),
    ("OWASP Top 10 category", "references", lambda r: any(x.get("owasp_top10") for x in refs(r, "cwe"))),
    ("links to the guidance used", "references", lambda r: bool(refs(r, "guidance"))),
]
FACTS_SCA = [
    ("flags mongodb 2.x → 3.x as a major upgrade", "prompt", has_phrase("mongodb 2.2.36 → 3.1.13: major version change")),
    ("says a package is already at its target, so a bump cannot fix it", "prompt", has_phrase("already at the target")),
    ("routes the transitive qs fix through body-parser", "prompt", has_phrase("body-parser 1.18.3 → 1.20.4")),
    ("independent confirmation of the scanner's targets", "prompt", has_phrase("osv.dev confirms")),
    ("says no compatible fix exists for mongodb (none within 2.x)", "prompt", has_phrase("no fix within 2.x")),
    ("smallest fixed version per package", "upgrades", lambda r: any(u.get("min_fixed") for u in r["upgrades"])),
    ("major change marked as data", "upgrades", lambda r: any(u.get("major_change") for u in r["upgrades"])),
    ("compatible target per package as data", "upgrades", lambda r: any(u.get("compatible_target") for u in r["upgrades"])),
    ("CVSS score and severity per CVE", "references", lambda r: any(x.get("cvss") is not None for x in refs(r, "cve"))),
    ("weakness per CVE, with OWASP Top 10 category", "references", lambda r: any(x.get("owasp_top10") for x in refs(r, "cwe"))),
    ("advisories that stay open after the upgrade", "references", lambda r: any(x.get("beyond_target") for x in refs(r, "advisory"))),
    ("mongodb 3.x breaking-change notes for the migration", "references",
     lambda r: any(x.get("description") for x in refs(r, "library_docs"))),
]
FACTS_CONTAINER = [
    ("names the image and its base OS", "prompt", has_phrase("mongo:4.4 (ubuntu 20.04)")),
    ("says the fixes are subscription-only, in the source's words", "prompt", has_phrase("available with ubuntu pro")),
    ("says the image's release line is past end of life", "prompt", has_phrase("is past end of life")),
    ("says no compatible (same major version) fix exists", "prompt", has_phrase("compatible fix (same major version, 4.x): none")),
    ("warns that a new major version is not a drop-in change", "prompt", has_phrase("not a drop-in")),
    ("newer release lines with their base OS", "upgrades", lambda r: any(u.get("candidates") for u in r["upgrades"])),
    ("support dates per release line", "upgrades",
     lambda r: any(c.get("supported_until") for u in r["upgrades"] for c in u.get("candidates") or [])),
    ("migration target", "upgrades", lambda r: any(u["kind"] == "image" and u.get("target") for u in r["upgrades"])),
    ("fix version and availability per CVE", "references", lambda r: any(x.get("availability") for x in refs(r, "advisory"))),
    ("CVSS score and severity per CVE", "references", lambda r: any(x.get("cvss") is not None for x in refs(r, "cve"))),
    ("weakness per CVE", "references", lambda r: bool(refs(r, "cwe"))),
]
FACTS_KEV = [
    ("says the CVE is known to be exploited, fix first", "prompt", has_phrase("known exploited in the wild")),
    ("known-exploited flag and date", "references", lambda r: any(x.get("kev") for x in refs(r, "cve"))),
    ("CVSS score and severity", "references", lambda r: any(x.get("cvss") is not None for x in refs(r, "cve"))),
]


def facts_for(entry: dict, validation: dict) -> list[tuple]:
    if entry.get("illustration"):
        return FACTS_KEV
    if entry["finding_type"] == "sca":
        return FACTS_SCA
    if entry["finding_type"] == "container":
        return FACTS_CONTAINER
    advice = []
    for title in dict.fromkeys(f["title"] for f in entry["findings"]):
        for label, phrases in validation.get(title, {}).items():
            advice.append((f"key advice: {label}", "prompt", has_phrase(*phrases)))
    return advice + REFERENCE_FACTS_CODE


# -- running ----------------------------------------------------------------------------------

def run(builder, conn, entry: dict, exclude=()) -> dict:
    trace = {}
    items, references, warnings, upgrades = builder.build(
        conn, [to_request(f) for f in entry["findings"]], entry["fix_type"], BUDGET, trace, exclude=exclude)
    return {"items": items, "references": references, "warnings": warnings, "upgrades": upgrades, "trace": trace}


def chars(result: dict) -> int:
    return sum(len(i["text"]) for i in result["items"])


def chars_by_source(result: dict) -> dict[str, int]:
    spent: dict[str, int] = {}
    for i in result["items"]:
        label = i["source"] + (" (keyword match)" if i.get("matched_by") == "keyword" else "")
        spent[label] = spent.get(label, 0) + len(i["text"])
    return spent


def evaluate_sources(builder, conn, cases: list[dict], validation: dict) -> list[dict]:
    rows = []
    for entry in cases:
        facts = facts_for(entry, validation)
        base = run(builder, conn, entry)
        present = [(label, where) for label, where, check in facts if check(base)]
        absent = [label for label, _, check in facts if not check(base)]
        row = {"file": entry["file"], "type": entry["finding_type"], "findings": len(entry["findings"]),
               "illustration": bool(entry.get("illustration")), "chars": chars(base), "chars_by_source": chars_by_source(base),
               "references": len(base["references"]), "facts_total": len(facts),
               "facts_present": [label for label, _ in present], "facts_absent": absent, "without": {}}
        for source in SOURCES:
            result = run(builder, conn, entry, exclude=[source])
            lost = [(label, where) for (label, where, check) in facts if (label, where) in present and not check(result)]
            row["without"][source] = {
                "chars": chars(result), "chars_saved": row["chars"] - chars(result),
                "references_lost": row["references"] - len(result["references"]),
                "lost_prompt": [label for label, where in lost if where == "prompt"],
                "lost_data": [f"{label} ({where})" for label, where in lost if where != "prompt"]}
        rows.append(row)
        print(f"  {entry['file']}: {row['chars']} chars, {len(present)}/{len(facts)} facts")
    return rows


def evaluate_search(conn, embedder, issues: list[dict]) -> dict:
    """Key-advice coverage of the OWASP search over the SAST issue types, per search method."""
    chunks, matrix = store.load_chunks(conn)
    fallback = dict(fallback_below=config.KEYWORD_FALLBACK_BELOW, fallback_results=config.KEYWORD_FALLBACK_RESULTS)
    methods = {
        "similarity only": dict(fallback_results=0),
        "keyword only": dict(fallback_below=99.0, fallback_results=config.GUIDANCE_TOP_K),
        f"similarity + keyword fallback (below {config.KEYWORD_FALLBACK_BELOW}, {config.KEYWORD_FALLBACK_RESULTS} results)": fallback,
        "same, without the CWE name in the search query": {**fallback, "use_cwe": False},
    }
    out = {"methods": {}, "issues": []}
    per_issue: dict[str, dict] = {}
    for name, settings in methods.items():
        settings = dict(settings)
        use_cwe = settings.pop("use_cwe", True)
        retriever = Retriever(embedder, chunks, matrix, **settings)
        tuned, held_out, size = [], [], []
        for issue in issues:
            trace = {}
            items = retriever.guidance(conn, [{k: issue[k] for k in ("cwe", "rule_id", "title", "summary")}], [], trace,
                                       use_cwe=use_cwe)
            text = "\n".join(f"{i['title']} {i['section'] or ''}\n{i['text']}" for i in items).lower()
            hits = [any(p in text for p in phrases) for phrases in issue["facts"].values()]
            (held_out if issue.get("held_out") else tuned).append(sum(hits) / len(hits))
            size.append(sum(len(i["text"]) for i in items))
            per_issue.setdefault(issue["title"], {"cwe": issue["cwe"], "held_out": bool(issue.get("held_out")),
                                                  "best_similarity": trace["queries"][0]["best_similarity"]})[name] = {
                "covered": sum(hits), "of": len(hits),
                "sections": [("[keyword] " if i["matched_by"] == "keyword" else "") + f"{i['title']} › {(i['section'] or 'Introduction').split(' > ')[-1]}"
                             for i in items]}
        everything = tuned + held_out
        out["methods"][name] = {"tuned_on": round(sum(tuned) / len(tuned), 4), "all": round(sum(everything) / len(everything), 4),
                                "issues_tuned_on": len(tuned), "issues_all": len(everything),
                                "average_chars": round(sum(size) / len(size))}
    out["issues"] = [{"title": title, **data} for title, data in sorted(per_issue.items(), key=lambda kv: kv[1]["best_similarity"])]
    return out


def evaluate_amount(conn, embedder, issues: list[dict]) -> list[dict]:
    """Key-advice coverage against how much OWASP text is returned: sections per finding and
    characters per section. The service default is the last row of each block's largest setting."""
    chunks, matrix = store.load_chunks(conn)
    rows = []
    for top_k in (1, 2, 3, 4):
        for passage in (400, 800, 1200):
            retriever = Retriever(embedder, chunks, matrix, top_k=top_k, passage_max_chars=passage,
                                  fallback_results=min(config.KEYWORD_FALLBACK_RESULTS, max(top_k - 1, 0)))
            coverage, size = [], []
            for issue in issues:
                items = retriever.guidance(conn, [{k: issue[k] for k in ("cwe", "rule_id", "title", "summary")}], [], {})
                text = "\n".join(f"{i['title']} {i['section'] or ''}\n{i['text']}" for i in items).lower()
                hits = [any(p in text for p in phrases) for phrases in issue["facts"].values()]
                coverage.append(sum(hits) / len(hits))
                size.append(sum(len(i["text"]) for i in items))
            rows.append({"sections": top_k, "section_chars": passage, "coverage": round(sum(coverage) / len(coverage), 4),
                         "average_chars": round(sum(size) / len(size)),
                         "default": top_k == config.GUIDANCE_TOP_K and passage == config.PASSAGE_MAX_CHARS})
    return rows


# -- report -----------------------------------------------------------------------------------

def per_source(rows: list[dict]) -> list[dict]:
    summary = []
    for source, (name, purpose) in SOURCES.items():
        real = [r for r in rows if not r["illustration"]]
        lost_prompt = [(r["file"], label) for r in rows for label in r["without"][source]["lost_prompt"]]
        lost_data = [(r["file"], label) for r in rows for label in r["without"][source]["lost_data"]]
        on_nodegoat = [x for x in lost_prompt + lost_data if not x[0].startswith("(illustration)")]
        saved = sum(r["without"][source]["chars_saved"] for r in real)
        if source == "keyword":
            reading = ("No effect on these files: no finding's best similarity is below the threshold. "
                       "Its effect on the wider issue set is in part 3.")
        elif [x for x in lost_prompt if not x[0].startswith("(illustration)")]:
            reading = "Keep: the prompt loses facts without it."
        elif on_nodegoat:
            reading = "Keep for the PR / UI data; it adds nothing to the prompt."
        elif lost_prompt or lost_data:
            reading = "No effect on NodeGoat's findings; matters only when a CVE is in the catalogue (see the illustration)."
        else:
            reading = "No measurable effect on these cases."
        summary.append({"id": source, "name": name, "purpose": purpose, "prompt_chars": saved,
                        "lost_prompt": lost_prompt, "lost_data": lost_data, "reading": reading})
    return summary


def markdown(rows: list[dict], sources: list[dict], search: dict, amount: list[dict], meta: dict) -> str:
    real = [r for r in rows if not r["illustration"]]
    total = sum(r["chars"] for r in real)
    out = ["# Source evaluation: results with and without each source", "",
           f"Generated {meta['generated_at']} by `tests/eval_sources.py` from the NodeGoat scan "
           f"{meta['scan_run_id']} @ {meta['commit_sha']} ({len(real)} files, {sum(r['findings'] for r in real)} findings). "
           f"Prompt budget per file: {BUDGET:,} characters.", "",
           "A fact is something a useful answer should contain, checked mechanically. \"Lost\" means the fact was in "
           "the answer with all sources and is missing without that source.", "",
           "## 1. What each source contributes", "",
           "| Source | Used for | Prompt characters it adds | Prompt facts lost without it | PR / upgrade-data facts lost without it | Reading |",
           "|---|---|---:|---:|---:|---|"]
    for s in sources:
        out.append(f"| {s['name']} | {s['purpose']} | {s['prompt_chars']:,} | {len(s['lost_prompt'])} | {len(s['lost_data'])} | {s['reading']} |")
    out += ["", f"Total prompt text over the {len(real)} files with all sources: {total:,} characters "
                f"(about {total // 4:,} tokens). A negative number means the answer grows without that source "
                f"(a fallback text replaces it).", ""]
    out += ["### The facts behind the counts", ""]
    for s in sources:
        if not (s["lost_prompt"] or s["lost_data"]):
            continue
        out.append(f"**Without {s['name']}:**")
        for file, label in s["lost_prompt"]:
            out.append(f"- prompt, {file}: {label}")
        for file, label in s["lost_data"]:
            out.append(f"- {file}: {label}")
        out.append("")

    out += ["## 2. Per file", "",
            "| File | Type | Findings | Prompt characters | Where they go | Facts present | Facts missing even with all sources |",
            "|---|---|---:|---:|---|---:|---|"]
    for r in rows:
        spent = ", ".join(f"{k} {v:,}" for k, v in sorted(r["chars_by_source"].items(), key=lambda kv: -kv[1]))
        out.append(f"| {r['file']} | {r['type']} | {r['findings']} | {r['chars']:,} | {spent} | "
                   f"{len(r['facts_present'])} of {r['facts_total']} | {'; '.join(r['facts_absent']) or '-'} |")
    out += ["", "Prompt characters per file without each source (bold = facts were lost):", "",
            "| File | all | " + " | ".join(f"-{s}" for s in SOURCES) + " |", "|---|---:|" + "---:|" * len(SOURCES)]
    for r in rows:
        cells = []
        for s in SOURCES:
            w = r["without"][s]
            lost = len(w["lost_prompt"]) + len(w["lost_data"])
            cells.append(f"**{w['chars']:,}** ({lost} lost)" if lost else f"{w['chars']:,}")
        out.append(f"| {r['file']} | {r['chars']:,} | " + " | ".join(cells) + " |")

    out += ["", "## 3. OWASP search: similarity, keyword, and the fallback", "",
            f"Share of key fix advice found in the returned sections, averaged per issue type, over NodeGoat's "
            f"own-code SAST issue types. The ranking was tuned on {next(iter(search['methods'].values()))['issues_tuned_on']} "
            f"of them; the rest were added later and are the fairer test.", "",
            "| Search method | Issue types it was tuned on | All issue types | Average prompt characters |", "|---|---:|---:|---:|"]
    for name, m in search["methods"].items():
        out.append(f"| {name} | {m['tuned_on']:.0%} ({m['issues_tuned_on']}) | {m['all']:.0%} ({m['issues_all']}) | {m['average_chars']:,} |")
    names = list(search["methods"])
    out += ["", "Per issue type, lowest similarity first (covered key-advice points):", "",
            "| Issue type | CWE | Best similarity | " + " | ".join(n.split(" (")[0] for n in names) + " |",
            "|---|---|---:|" + "---:|" * len(names)]
    fallback = names[2]
    for issue in search["issues"]:
        cells = " | ".join(f"{issue[n]['covered']} of {issue[n]['of']}" for n in names)
        held = " (added later)" if issue["held_out"] else ""
        out.append(f"| {issue['title']}{held} | {issue['cwe']} | {issue['best_similarity']:.3f} | {cells} |")
    switched = [i for i in search["issues"] if any(s.startswith("[keyword]") for s in i[fallback]["sections"])]
    if switched:
        out += ["", "Issue types where the fallback changed the result:", ""]
        for issue in switched:
            out.append(f"**{issue['title']}** (best similarity {issue['best_similarity']:.3f}): "
                       f"{issue[names[0]]['covered']} of {issue[names[0]]['of']} → {issue[fallback]['covered']} of {issue[fallback]['of']}")
            for label, key in (("similarity only", names[0]), ("with fallback", fallback)):
                out.append(f"- {label}: " + "; ".join(issue[key]["sections"]))
            out.append("")
    without_cwe = names[3]
    changed = [i for i in search["issues"] if i[fallback]["covered"] != i[without_cwe]["covered"]]
    out += ["Issue types where leaving the CWE name out of the search query changed the coverage: "
            + ("; ".join(f"{i['title']} ({i[fallback]['covered']} of {i[fallback]['of']} with the name, "
                         f"{i[without_cwe]['covered']} without)" for i in changed) or "none") + ".", ""]

    out += ["## 4. How much OWASP text is needed", "",
            f"Coverage over all {next(iter(search['methods'].values()))['issues_all']} issue types against the number of "
            f"sections returned per finding and the characters kept per section (keyword fallback as configured).", "",
            "| Sections per finding | Characters per section | Key advice covered | Average prompt characters |", "|---:|---:|---:|---:|"]
    for row in amount:
        mark = "  ← service default" if row["default"] else ""
        out.append(f"| {row['sections']} | {row['section_chars']:,} | {row['coverage']:.0%} | {row['average_chars']:,}{mark} |")
    return "\n".join(out) + "\n"


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--offline", action="store_true", help="Use cached lookups only (no network calls).")
    args = parser.parse_args()

    fixture = json.loads((FIXTURES / "nodegoat_findings.json").read_text(encoding="utf-8"))
    issues = json.loads((FIXTURES / "sast_validation.json").read_text(encoding="utf-8"))["issues"]
    validation = {issue["title"]: issue["facts"] for issue in issues}
    cases = fixture["files"] + [KEV_ILLUSTRATION]

    with closing(store.connect(config.DB_PATH)) as conn, net.make_client() as client:
        if not store.counts(conn)["chunks"]:
            sys.exit("The database is empty: run `python -m app.sync` first.")
        embedder = Embedder()
        builder = ContextBuilder(Retriever.from_db(conn, embedder), client, online=config.ONLINE_LOOKUPS and not args.offline)
        print("Sources, case by case (all sources, then without each one):")
        rows = evaluate_sources(builder, conn, cases, validation)
        print("OWASP search methods over the SAST issue types ...")
        search = evaluate_search(conn, embedder, issues)
        amount = evaluate_amount(conn, embedder, issues)
        snapshot = store.snapshot(conn)

    sources = per_source(rows)
    meta = {"generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), **fixture["source"],
            "snapshot": snapshot, "budget": BUDGET, "disabled_sources": sorted(config.DISABLED_SOURCES)}
    OUT_DIR.mkdir(exist_ok=True)
    (OUT_DIR / "results.json").write_text(json.dumps(
        {"meta": meta, "sources": sources, "cases": rows, "search": search, "amount": amount},
        indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    (OUT_DIR / "results.md").write_text(markdown(rows, sources, search, amount, meta), encoding="utf-8")

    print("\nSource                    prompt chars   prompt facts lost   data facts lost   reading")
    for s in sources:
        print(f"  {s['name']:24} {s['prompt_chars']:>10,} {len(s['lost_prompt']):>19} {len(s['lost_data']):>17}   {s['reading']}")
    for name, m in search["methods"].items():
        print(f"  search, {name}: {m['tuned_on']:.0%} on the {m['issues_tuned_on']} tuned-on issue types, {m['all']:.0%} on all {m['issues_all']}")
    print(f"\nWrote {OUT_DIR / 'results.md'} and results.json")


if __name__ == "__main__":
    main()

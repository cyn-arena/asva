#!/usr/bin/env python3
"""Does each source have anything to give outside NodeGoat?

tests/eval_sources.py measures the sources on NodeGoat's own findings. A source that adds
nothing there may still matter for another application, so this script runs the same
with-and-without comparison on cases from other stacks: Java, Python, .NET, Go and Ruby
dependencies, and Debian- and Alpine-based images (tests/fixtures/other_stacks.json).

Those cases are hand-built from well-known public vulnerabilities; no application was scanned
and none exists to run the fixes against. So this shows what the sources return, case by case,
not whether a fix works. It reads tests/fixtures only and runs the service's code in-process
against the local database, with online lookups as configured in .env.

    python tests/eval_stacks.py              # writes evaluation/other_stacks.md and .json
    python tests/eval_stacks.py --offline    # cached lookups only
"""

import argparse
import json
import sys
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).parent))

from app import config, net, store  # noqa: E402
from app.context import ContextBuilder  # noqa: E402
from app.embed import Embedder  # noqa: E402
from app.retrieve import Retriever  # noqa: E402
from eval_sources import FIXTURES, OUT_DIR, SOURCES, chars, has_phrase, refs, run  # noqa: E402

# Facts that do not name a package or an image, so they apply to any case.
FACTS_SCA = [
    ("independent confirmation of the scanner's target", "prompt", has_phrase("osv.dev confirms")),
    ("for a major upgrade: the compatible fix, or that there is none", "prompt",
     has_phrase("no fix within", "a compatible alternative", "without a major version change")),
    ("warning that a CVE is known to be exploited", "prompt", has_phrase("known exploited in the wild")),
    ("smallest fixed version per package", "upgrades", lambda r: any(u.get("min_fixed") for u in r["upgrades"])),
    ("compatible target for a major upgrade", "upgrades",
     lambda r: any(u.get("major_change") and u.get("compatible_target") for u in r["upgrades"])),
    ("reason a major upgrade is held back", "upgrades",
     lambda r: any(u.get("major_change") and "OSV.dev" in (u.get("note") or "") for u in r["upgrades"])),
    ("CVSS score and severity per CVE", "references", lambda r: any(x.get("cvss") is not None for x in refs(r, "cve"))),
    ("known-exploited flag per CVE", "references", lambda r: any(x.get("kev") for x in refs(r, "cve"))),
    ("weakness defined, with OWASP Top 10 category", "references", lambda r: any(x.get("owasp_top10") for x in refs(r, "cwe"))),
    ("advisories that stay open after the upgrade", "references", lambda r: any(x.get("beyond_target") for x in refs(r, "advisory"))),
    ("breaking-change notes for a major upgrade", "references", lambda r: bool(refs(r, "library_docs"))),
]
FACTS_CONTAINER = [
    ("where the fixes stand for the image's OS release", "prompt", has_phrase("the distribution's own security data")),
    ("that no tag change is needed (the OS publishes the fixes)", "prompt", has_phrase("no tag change is needed")),
    ("that the image's release line is past end of life", "prompt", has_phrase("is past end of life")),
    ("compatible fix, or that there is none", "prompt", has_phrase("compatible fix (same major version")),
    ("warning that a CVE is known to be exploited", "prompt", has_phrase("known exploited in the wild")),
    ("known-exploited flag per CVE", "references", lambda r: any(x.get("kev") for x in refs(r, "cve"))),
    ("support dates per release line", "upgrades",
     lambda r: any(c.get("supported_until") for u in r["upgrades"] for c in u.get("candidates") or [])),
    ("fix version per CVE for the OS release", "references",
     lambda r: any(": fix for release" in (x.get("title") or "") for x in refs(r, "advisory"))),
    ("newer release lines with their base OS", "upgrades", lambda r: any(u.get("candidates") for u in r["upgrades"])),
    ("migration target", "upgrades", lambda r: any(u["kind"] == "image" and u.get("target") for u in r["upgrades"])),
    ("CVSS score and severity per CVE", "references", lambda r: any(x.get("cvss") is not None for x in refs(r, "cve"))),
    ("weakness defined", "references", lambda r: any(x.get("description") for x in refs(r, "cwe"))),
]


def outcome(entry: dict, result: dict) -> list[str]:
    """What the service says for one case, in a few lines."""
    lines = []
    if entry["finding_type"] == "sca":
        for u in result["upgrades"]:
            compatible = u.get("compatible_target") or "none"
            if u.get("compatible_scope") == "partial":
                compatible += " (partial)"
            verdict = {"ok": "apply", "osv_disagrees": "apply (OSV.dev disagrees with the target)", "already_at_target": "cannot be fixed by a bump",
                       "no_target": "no target"}.get(u["status"], "major change: " + ("apply the compatible fix" if u.get("compatible_target") else "held back"))
            lines.append(f"{u['name']} {u.get('current')} → scanner {u.get('target')} | compatible fix {compatible} | {verdict}"
                         + (f" | smallest fixed {u['min_fixed']}" if u.get("min_fixed") else ""))
        exploited = sorted(x["id"] for x in refs(result, "cve") if x.get("kev"))
        if exploited:
            lines.append(f"known exploited (CISA KEV): {', '.join(exploited)}")
        return lines
    image = next((u for u in result["upgrades"] if u["kind"] == "image"), None)
    facts = (result["trace"].get("container") or {})
    here = facts.get("fix_data") or {}
    lines.append(f"image {facts.get('image')} on {facts.get('base_os') or 'unknown OS'}; status {image['status'] if image else '?'}")
    if here.get("checked"):
        lines.append(f"fix data for this OS release: {here['standard']} in the standard repositories, {here['subscription']} subscription-only, "
                     f"{here['unfixed']} without a fix, of {here['checked']} checked")
    else:
        lines.append("fix data for this OS release: none found")
    for c in (image or {}).get("candidates") or []:
        resolved = f"{c['cves_resolved']}/{c['cves_checked']} CVEs resolved" if c.get("cves_checked") else "CVEs not checked"
        support = ("past end of life" if c.get("end_of_life") else f"supported until {c['supported_until']}" if c.get("supported_until")
                   else "support dates unknown")
        lines.append(f"  line {c['tag']}: {c.get('version') or '?'} on {c.get('base_os') or 'unknown OS'}, {resolved}, {support}")
    if image:
        lines.append(f"compatible fix: {image.get('compatible_target') or 'none'}; migration target: "
                     f"{image.get('target') if not image.get('compatible_target') else '-'}")
    return lines


def evaluate(builder, conn, cases: list[dict]) -> list[dict]:
    rows = []
    for entry in cases:
        facts = FACTS_SCA if entry["finding_type"] == "sca" else FACTS_CONTAINER
        base = run(builder, conn, entry)
        present = [(label, where) for label, where, check in facts if check(base)]
        row = {"file": entry["file"], "stack": entry["stack"], "type": entry["finding_type"], "findings": len(entry["findings"]),
               "chars": chars(base), "outcome": outcome(entry, base), "text": "\n\n".join(i["text"] for i in base["items"]),
               "facts_present": [label for label, _ in present], "warnings": base["warnings"], "without": {}}
        for source in SOURCES:
            result = run(builder, conn, entry, exclude=[source])
            lost = [(label, where) for label, where, check in facts if (label, where) in present and not check(result)]
            row["without"][source] = {"chars_saved": row["chars"] - chars(result),
                                      "lost_prompt": [label for label, where in lost if where == "prompt"],
                                      "lost_data": [f"{label} ({where})" for label, where in lost if where != "prompt"],
                                      "outcome": outcome(entry, result)}
        rows.append(row)
        print(f"  {entry['file']}: {row['chars']} chars, {len(present)}/{len(facts)} facts")
    return rows


def per_source(rows: list[dict]) -> list[dict]:
    summary = []
    for source, (name, _) in SOURCES.items():
        prompt_cases = [r["file"] for r in rows if r["without"][source]["lost_prompt"]]
        data_cases = [r["file"] for r in rows if r["without"][source]["lost_data"]]
        changed = [r["file"] for r in rows if r["without"][source]["outcome"] != r["outcome"]]
        summary.append({"id": source, "name": name, "cases": len(rows),
                        "prompt_cases": len(prompt_cases), "data_cases": len(set(prompt_cases) | set(data_cases)),
                        "outcome_changed": changed, "prompt_chars": sum(r["without"][source]["chars_saved"] for r in rows),
                        "lost_prompt": sorted({label for r in rows for label in r["without"][source]["lost_prompt"]}),
                        "lost_data": sorted({label for r in rows for label in r["without"][source]["lost_data"]})})
    return summary


def markdown(rows: list[dict], sources: list[dict], meta: dict) -> str:
    out = ["# Other stacks: does each source have anything to give outside NodeGoat?", "",
           f"Generated {meta['generated_at']} by `tests/eval_stacks.py` from `tests/fixtures/other_stacks.json`: "
           f"{len(rows)} cases, {sum(r['findings'] for r in rows)} findings.", "",
           "**What these cases are.** Hand-built from well-known public vulnerabilities (real CVE ids, packages and "
           "versions) in the shape ASVA sends. No application was scanned and none exists to run the fixes against, "
           "so this shows what the sources return, not whether a fix works. The NodeGoat results, which are measured "
           "on a real scan and a running app, are in `results.md` and `fix_results.md`.", "",
           "## 1. What each source gives across these cases", "",
           "| Source | Cases where the prompt loses a fact without it | Cases where prompt or PR data loses a fact | "
           "Cases where the outcome changes | Prompt characters it adds |", "|---|---:|---:|---:|---:|"]
    for s in sources:
        out.append(f"| {s['name']} | {s['prompt_cases']} of {s['cases']} | {s['data_cases']} of {s['cases']} | "
                   f"{len(s['outcome_changed'])} of {s['cases']} | {s['prompt_chars']:,} |")
    out += ["", "\"Outcome\" is the decision the service reports: per package the compatible fix and whether to apply or "
                "hold back; per image the fix status, the lines and the target.", "", "What is lost without each source:", ""]
    for s in sources:
        lost = [f"prompt: {label}" for label in s["lost_prompt"]] + s["lost_data"]
        out.append(f"- **{s['name']}**: " + ("; ".join(lost) if lost else "nothing in these cases"))
    out += ["", "## 2. Case by case", ""]
    for r in rows:
        out += [f"### {r['file']} ({r['stack']}, {r['findings']} finding(s), {r['chars']:,} prompt characters)", "",
                "With all sources:", ""] + [f"- {line.strip()}" for line in r["outcome"]] + [""]
        for source, (name, _) in SOURCES.items():
            w = r["without"][source]
            if w["outcome"] != r["outcome"] or w["lost_prompt"] or w["lost_data"]:
                lost = [f"prompt: {label}" for label in w["lost_prompt"]] + w["lost_data"]
                out.append(f"Without {name} ({-w['chars_saved']:+,} characters): loses " + ("; ".join(lost) or "no listed fact")
                           + (". Outcome becomes: " + " / ".join(line.strip() for line in w["outcome"] if line not in r["outcome"])
                              if w["outcome"] != r["outcome"] else "."))
                out.append("")
        if r["warnings"]:
            out += ["Warnings: " + "; ".join(r["warnings"]), ""]
    return "\n".join(out) + "\n"


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--offline", action="store_true", help="Use cached lookups only (no network calls).")
    args = parser.parse_args()
    cases = json.loads((FIXTURES / "other_stacks.json").read_text(encoding="utf-8"))["files"]
    with closing(store.connect(config.DB_PATH)) as conn, net.make_client() as client:
        if not store.counts(conn)["chunks"]:
            sys.exit("The database is empty: run `python -m app.sync` first.")
        builder = ContextBuilder(Retriever.from_db(conn, Embedder()), client, online=config.ONLINE_LOOKUPS and not args.offline)
        print("Other stacks, case by case (all sources, then without each one):")
        rows = evaluate(builder, conn, cases)
    sources = per_source(rows)
    meta = {"generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
    OUT_DIR.mkdir(exist_ok=True)
    (OUT_DIR / "other_stacks.json").write_text(json.dumps({"meta": meta, "sources": sources, "cases": rows}, indent=1,
                                                          ensure_ascii=False) + "\n", encoding="utf-8")
    (OUT_DIR / "other_stacks.md").write_text(markdown(rows, sources, meta), encoding="utf-8")
    print(f"\n{'Source':26}{'prompt facts in':>16}{'any fact in':>13}{'outcome changes in':>20}{'prompt chars':>14}")
    for s in sources:
        print(f"  {s['name']:24}{s['prompt_cases']:>10} of {s['cases']}{s['data_cases']:>8} of {s['cases']}"
              f"{len(s['outcome_changed']):>15} of {s['cases']}{s['prompt_chars']:>14,}")
    print(f"\nWrote {OUT_DIR / 'other_stacks.md'} and other_stacks.json")


if __name__ == "__main__":
    main()

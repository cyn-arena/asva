#!/usr/bin/env python3
"""How well does the OWASP guidance search do outside NodeGoat?

tests/eval_sources.py scores the search on NodeGoat's own 12 issue types, which the ranking
was partly tuned on. This script runs it on issue types from six languages that it was never
tuned on (tests/fixtures/search_cases.json): each names the OWASP cheat sheets that are the
right place to look, written down before the search was run.

Scored per search method:
  top hit      the first section returned is from an expected cheat sheet
  any hit      at least one returned section is
  on topic     share of the returned sections that are (the rest is text the LLM has to read
               past: the dilution this service is meant to keep low)

    python tests/eval_search.py      # writes evaluation/search_results.md and .json
"""

import json
import sys
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).parent))

from app import config, store  # noqa: E402
from app.embed import Embedder  # noqa: E402
from app.retrieve import Retriever  # noqa: E402
from eval_sources import FIXTURES, OUT_DIR  # noqa: E402

FALLBACK = dict(fallback_below=config.KEYWORD_FALLBACK_BELOW, fallback_results=config.KEYWORD_FALLBACK_RESULTS)
METHODS = {
    "similarity only": dict(fallback_results=0),
    "keyword only": dict(fallback_below=99.0, fallback_results=config.GUIDANCE_TOP_K),
    "similarity + keyword fallback (service default)": FALLBACK,
    "default, without the CWE name in the query": {**FALLBACK, "use_cwe": False},
}
DEFAULT = "similarity + keyword fallback (service default)"


def sheet(title: str) -> str:
    return title.replace(" Cheat Sheet", "").strip()


def search(retriever, conn, issue: dict, use_cwe: bool = True) -> tuple[list[dict], float]:
    trace = {}
    finding = {"cwe": issue["cwe"], "rule_id": issue["rule_id"], "title": issue["title"], "summary": issue["title"]}
    items = retriever.guidance(conn, [finding], [], trace, use_cwe=use_cwe)
    return items, trace["queries"][0]["best_similarity"]


def score(items: list[dict], expect: list[str]) -> dict:
    hits = [sheet(i["title"]) in expect for i in items]
    return {"top": bool(hits and hits[0]), "any": any(hits), "on_topic": sum(hits) / len(hits) if hits else 0.0,
            "sections": len(items), "chars": sum(len(i["text"]) for i in items),
            "returned": [("[keyword] " if i.get("matched_by") == "keyword" else "") + f"{sheet(i['title'])} › "
                         f"{(i['section'] or 'Introduction').split(' > ')[-1]}" for i in items]}


def summarise(scores: list[dict]) -> dict:
    n = len(scores)
    return {"issues": n, "top": sum(s["top"] for s in scores) / n, "any": sum(s["any"] for s in scores) / n,
            "on_topic": sum(s["on_topic"] for s in scores) / n, "chars": round(sum(s["chars"] for s in scores) / n),
            "none_returned": sum(1 for s in scores if not s["sections"])}


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    issues = json.loads((FIXTURES / "search_cases.json").read_text(encoding="utf-8"))["issues"]
    scored = [i for i in issues if i.get("dedicated", True)]
    with closing(store.connect(config.DB_PATH)) as conn:
        chunks, matrix = store.load_chunks(conn)
        embedder = Embedder()
        methods, per_issue = {}, {}
        for name, settings in METHODS.items():
            settings = dict(settings)
            use_cwe = settings.pop("use_cwe", True)
            retriever = Retriever(embedder, chunks, matrix, **settings)
            results = []
            for issue in issues:
                items, best = search(retriever, conn, issue, use_cwe)
                result = score(items, issue["expect"])
                per_issue.setdefault(issue["rule_id"], {"title": issue["title"], "cwe": issue["cwe"], "expect": issue["expect"],
                                                        "dedicated": issue.get("dedicated", True), "best_similarity": best})[name] = result
                if issue.get("dedicated", True):
                    results.append(result)
            methods[name] = summarise(results)
        amounts = []
        for top_k in (1, 2, 3, 4):
            retriever = Retriever(embedder, chunks, matrix, top_k=top_k, fallback_below=config.KEYWORD_FALLBACK_BELOW,
                                  fallback_results=min(config.KEYWORD_FALLBACK_RESULTS, max(top_k - 1, 0)))
            amounts.append({"sections": top_k, "default": top_k == config.GUIDANCE_TOP_K,
                            **summarise([score(search(retriever, conn, issue)[0], issue["expect"]) for issue in scored])})
        languages = {}
        for issue in scored:
            languages.setdefault(issue["rule_id"].split("/")[0], []).append(per_issue[issue["rule_id"]][DEFAULT])
        by_language = {language: summarise(results) for language, results in sorted(languages.items())}

    missed = [(rule, data) for rule, data in per_issue.items() if data["dedicated"] and not data[DEFAULT]["any"]]
    changed = [(rule, data) for rule, data in per_issue.items() if data["dedicated"]
               and (data[DEFAULT]["any"], data[DEFAULT]["top"]) != (data["similarity only"]["any"], data["similarity only"]["top"])]
    out = ["# OWASP guidance search outside NodeGoat", "",
           f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} by `tests/eval_search.py` from "
           f"`tests/fixtures/search_cases.json`: {len(scored)} issue types in {len(by_language)} languages that the ranking was "
           f"never tuned on, each with the OWASP cheat sheets that are the right place to look (written down before "
           f"the search was run). {len(issues) - len(scored)} more issue types have no cheat sheet of their own and are listed "
           f"at the end, not scored.", "",
           "## 1. Search methods", "",
           "| Method | First section is from an expected sheet | Any returned section is | Share of returned sections on topic | "
           "Average prompt characters |", "|---|---:|---:|---:|---:|"]
    for name, m in methods.items():
        out.append(f"| {name} | {m['top']:.0%} | {m['any']:.0%} | {m['on_topic']:.0%} | {m['chars']:,} |")
    out += ["", "## 2. How many sections to return (service default search)", "",
            "| Sections per finding | Any returned section is from an expected sheet | Share of returned sections on topic | "
            "Average prompt characters |", "|---:|---:|---:|---:|"]
    for a in amounts:
        out.append(f"| {a['sections']}{'  ← default' if a['default'] else ''} | {a['any']:.0%} | {a['on_topic']:.0%} | {a['chars']:,} |")
    out += ["", "## 3. Per language (service default search)", "", "| Language | Issue types | First section right | Any section right | "
            "On topic |", "|---|---:|---:|---:|---:|"]
    for language, m in by_language.items():
        out.append(f"| {language} | {m['issues']} | {m['top']:.0%} | {m['any']:.0%} | {m['on_topic']:.0%} |")
    out += ["", f"## 4. Issue types the default search missed ({len(missed)} of {len(scored)})", ""]
    for rule, data in missed:
        out += [f"- **{data['title']}** ({rule}, {data['cwe']}; best similarity {data['best_similarity']:.3f}). Expected: "
                f"{', '.join(data['expect'])}. Returned: {'; '.join(data[DEFAULT]['returned']) or 'nothing'}"]
    out += ["", f"## 5. Where the keyword fallback changed the result ({len(changed)} of {len(scored)})", ""]
    for rule, data in changed:
        before, after = data["similarity only"], data[DEFAULT]
        verdict = "better" if (after["any"], after["top"]) > (before["any"], before["top"]) else "worse"
        out += [f"- **{data['title']}** ({rule}; best similarity {data['best_similarity']:.3f}): {verdict}. "
                f"Similarity only: {'; '.join(before['returned']) or 'nothing'}. With the fallback: {'; '.join(after['returned'])}"]
    out += ["", "## 6. Issue types without a cheat sheet of their own (not scored)", ""]
    for rule, data in per_issue.items():
        if not data["dedicated"]:
            out += [f"- **{data['title']}** ({rule}, {data['cwe']}; best similarity {data['best_similarity']:.3f}): "
                    f"{'; '.join(data[DEFAULT]['returned']) or 'nothing returned'}"]
    OUT_DIR.mkdir(exist_ok=True)
    (OUT_DIR / "search_results.md").write_text("\n".join(out) + "\n", encoding="utf-8")
    (OUT_DIR / "search_results.json").write_text(json.dumps(
        {"methods": methods, "amounts": amounts, "by_language": by_language, "issues": per_issue}, indent=1, ensure_ascii=False) + "\n",
        encoding="utf-8")
    print("\n".join(out[5:]))
    print(f"\nWrote {OUT_DIR / 'search_results.md'} and search_results.json")


if __name__ == "__main__":
    main()

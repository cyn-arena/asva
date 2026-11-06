#!/usr/bin/env python3
"""Do PyGoat's dependency fixes get better with the service's context? (requirements.txt)

The comparison tests/eval_fixes.py makes for NodeGoat, on PyGoat, the pipeline's second app,
with its real findings (tests/fixtures/pygoat_findings.json, from a pipeline run):

  A  ASVA today: agent/agent_loop.py's requirements.txt prompt with every scanner target
  B  the same prompt with the service's context and one instruction to respect it
  C  the same prompt with the service's compatible targets instead of the scanner's

Each distinct result is built and started with Docker and put through ASVA's PyGoat smoke
test (tools/pygoat_start_check.py): the checks the pipeline's candidate validation makes.
The file the pipeline's own agent produced in that run (PR #276) is checked the same way and
reported as "A in the pipeline". Results are cached by content in evaluation/app_start_checks.json.

    python tests/eval_pygoat_fixes.py --env-file ../.env --pygoat ../target-apps/PyGoat \\
        --smoke ../scripts/pygoat-smoke.py                 # writes evaluation/pygoat_fix_results.md
    ... --skip-llm      # report from saved answers        ... --skip-docker   # no new app checks
"""

import argparse
import json
import re
import os
import sys
import time
from contextlib import closing
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(Path(__file__).parent), str(ROOT / "integration"), str(ROOT / "tools")]

import asva_rag_client  # noqa: E402
import pygoat_start_check  # noqa: E402
from app import config, net, store, versions  # noqa: E402
from app.context import ContextBuilder  # noqa: E402
from app.embed import Embedder  # noqa: E402
from app.retrieve import Retriever  # noqa: E402
from eval_fixes import (CHECKS_FILE, RESPECT_SCA, RUNS_DIR, asva_upgrade_map, call_llm, content_key, load_env,  # noqa: E402
                        plain_rule_map)
from eval_sources import FIXTURES, OUT_DIR, to_request  # noqa: E402
from eval_stack_fixes import version_in  # noqa: E402

FILE = "requirements.txt"
WAYS = {"A": "ASVA today (no context)", "D": "Plain rule, no service (same major version only)",
        "B": "Context in the prompt", "C": "Compatible targets"}
PIPELINE = "A in the pipeline"
FOLDER = RUNS_DIR / "pygoat"


def prompt(content: str, upgrade_map: dict[str, str], extra: str = "", instruction: str = "") -> str:
    """agent/agent_loop.py's requirements.txt prompt, with {extra} where INTEGRATION.md puts the context."""
    summary = json.dumps([{"package": p, "upgrade_to_version": v} for p, v in upgrade_map.items()], indent=2)
    return f"""You are a senior security engineer fixing vulnerable Python dependencies in a requirements.txt file.

File: {FILE}

Required package upgrades:
{summary}
{extra}
Current file content:
{content}

Instructions:
- Update only the listed packages already present in this requirements file to the specified upgrade versions.
- If the current version is already equal to or higher than the specified version, leave it unchanged.
- Preserve unrelated dependencies, comments, extras, environment markers and requirements-file syntax.
- Do NOT convert this file to JSON or add invented dependency entries.
{instruction}- Return ONLY the complete fixed file content. No explanation, no markdown, no code blocks.
"""


def outcome(original: str, result: str, findings: list[dict], upgrades: list[dict]) -> dict:
    moved, majors = [], []
    for u in upgrades:
        before, after = version_in(original, u["name"]), version_in(result, u["name"])
        if after and after != before:
            moved.append(f"{u['name']} {after}" + (" (MAJOR)" if not versions.same_major(before, after) else ""))
            if not versions.same_major(before, after):
                majors.append(u["name"])
    names = {u["name"].lower() for u in upgrades}
    other = [line for line in set(result.split()) ^ set(original.split()) if line.split("==")[0].lower() not in names]
    resolved = 0
    for f in findings:
        name, needed = versions.split_package(f["remediation"].get("upgrade_to"))
        now = version_in(result, name)
        resolved += bool(now and versions.parse(now) and versions.parse(now) >= versions.parse(needed))
    return {"summary": ", ".join(moved) or "no change", "majors": majors, "resolved": resolved, "total": len(findings),
            "other_changes": sorted(other)}


TRIAL_BASE = "rag_with_pyyaml_5.1"  # the candidate that builds and passes (diagnostic/)


def set_version(text: str, name: str, version: str) -> str:
    """requirements.txt with one package pinned to another version (names compared as pip does)."""
    name_pattern = "[-_.]".join(re.escape(part) for part in re.split(r"[-_.]+", name))
    pattern = re.compile(rf"(?im)^({name_pattern}\s*==\s*)\S+")
    return pattern.sub(lambda m: m.group(1) + version, text, count=1)


def major_trials(base: str, upgrades: list[dict]) -> dict[str, tuple[dict, str]]:
    """Each upgrade held back as a major version change, applied on its own (the scanner's target)
    on top of the passing candidate: would it have worked?"""
    trials = {}
    for u in upgrades:
        if u.get("major_change") and (not u.get("compatible_target") or u.get("compatible_scope") == "partial"):
            trials[u["name"]] = (u, set_version(base, u["name"], u["target"]))
    return trials


def verdict(check: dict | None) -> str:
    if check is None:
        return "not checked"
    if not check["built"]:
        return "**does not build**"
    if not check["ready"]:
        return "**builds, does not start**"
    return "builds, starts, smoke test passes" if check["smoke"] == "passed" else "**starts, smoke test fails**"


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--model", default="deepseek-v4.1-flash", help="The pipeline's PyGoat model (pygoat-fix.yml).")
    parser.add_argument("--pygoat", type=Path, help="target-apps/PyGoat (copied, never changed).")
    parser.add_argument("--smoke", type=Path, help="asva/scripts/pygoat-smoke.py.")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--skip-llm", action="store_true")
    parser.add_argument("--skip-docker", action="store_true")
    args = parser.parse_args()

    fixture = json.loads((FIXTURES / "pygoat_findings.json").read_text(encoding="utf-8"))
    entry = next(e for e in fixture["files"] if e["file"] == FILE)
    content = (FIXTURES / "pygoat_files" / FILE).read_text(encoding="utf-8").replace("\r\n", "\n")
    with closing(store.connect(config.DB_PATH)) as conn, net.make_client() as client:
        builder = ContextBuilder(Retriever.from_db(conn, Embedder()), client)
        items, references, warnings, upgrades = builder.build(
            conn, [to_request(f) for f in entry["findings"]], entry["fix_type"], config.DEFAULT_MAX_CHARS)
    response = {"items": items, "references": references, "warnings": warnings, "upgrades": upgrades}
    extra = f"\n{asva_rag_client.prompt_block(response)}\n"
    compatible = asva_rag_client.compatible_upgrades(response)
    prompts = {"A": prompt(content, asva_upgrade_map(entry["findings"])),
               "D": prompt(content, plain_rule_map(entry["findings"])),
               "B": prompt(content, asva_upgrade_map(entry["findings"]), extra, RESPECT_SCA),
               "C": prompt(content, compatible, extra)}

    if not args.skip_llm:
        os.environ["OLLAMA_MODEL"] = args.model
        load_env(args.env_file)
        with httpx.Client(base_url=os.environ["OLLAMA_HOST"].rstrip("/"), timeout=900,
                          headers={"Authorization": f"Bearer {os.environ['OLLAMA_API_KEY']}"}) as llm:
            for way, text in prompts.items():
                folder = FOLDER / way
                folder.mkdir(parents=True, exist_ok=True)
                (folder / "prompt.txt").write_text(text, encoding="utf-8")
                for n in range(1, args.runs + 1):
                    out = folder / f"run{n}.txt"
                    if not out.exists():
                        started = time.time()
                        out.write_text(call_llm(llm, text) + "\n", encoding="utf-8", newline="\n")
                        print(f"  {way} run {n}: answered in {time.time() - started:.0f}s", flush=True)

    answers = {way: [p.read_text(encoding="utf-8") for p in sorted((FOLDER / way).glob("run*.txt"))]
               for way in [*WAYS, "A_ci"] if (FOLDER / way).exists()}
    checks = json.loads(CHECKS_FILE.read_text(encoding="utf-8")) if CHECKS_FILE.exists() else {}
    variants = sorted((FOLDER / "diagnostic").glob("*.txt")) if (FOLDER / "diagnostic").exists() else []
    base_file = FOLDER / "diagnostic" / f"{TRIAL_BASE}.txt"
    trials = major_trials(base_file.read_text(encoding="utf-8"), upgrades) if base_file.exists() else {}
    if trials:
        (FOLDER / "major_trials").mkdir(parents=True, exist_ok=True)
        for name, (_, text) in trials.items():
            (FOLDER / "major_trials" / f"{name}.txt").write_text(text, encoding="utf-8", newline="\n")
    if not args.skip_docker:
        if not (args.pygoat and args.smoke):
            sys.exit("--pygoat and --smoke are needed for the app checks (or pass --skip-docker)")
        todo = ([("baseline", content)] + [(f"{way}{n}", t) for way, texts in answers.items() for n, t in enumerate(texts, 1)]
                + [(path.stem, path.read_text(encoding="utf-8")) for path in variants]
                + [(f"major-{name}", text) for name, (_, text) in trials.items()])
        for key, text in todo:
            cache_key = content_key(FILE, text)
            if cache_key in checks:
                continue
            print(f"  app check {key} ...", flush=True)
            checks[cache_key] = pygoat_start_check.check(args.pygoat, args.smoke, f"pygoat-{key.lower()}", {FILE: text})
            print(f"    {verdict(checks[cache_key])} {checks[cache_key].get('error') or ''}", flush=True)
            CHECKS_FILE.write_text(json.dumps(checks, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")

    rows = {}
    for way, texts in answers.items():
        rows[way] = [{**outcome(content, t, entry["findings"], upgrades), "check": checks.get(content_key(FILE, t))} for t in texts]
    base = checks.get(content_key(FILE, content))
    out = ["# PyGoat fix evaluation: requirements.txt with and without the service", "",
           f"Generated by `tests/eval_pygoat_fixes.py`. Findings: PyGoat pipeline run {fixture['source'].get('pipeline_run')} "
           f"@ {fixture['source']['commit_sha']}, {len(entry['findings'])} dependency findings. LLM: `{args.model}` (the pipeline's "
           f"PyGoat model), {args.runs} runs per way. Each result is built from Dockerfile.asva, started, and put through ASVA's "
           "PyGoat smoke test (`scripts/pygoat-smoke.py`), as the pipeline's candidate validation does.", "",
           f"Unchanged app: {verdict(base)}.", "",
           "| Way | Run | Packages changed | Major version changes | Findings resolved | App |", "|---|---|---|---|---|---|"]
    for way, label in [("A_ci", PIPELINE), *WAYS.items()]:
        for n, row in enumerate(rows.get(way, []), 1):
            error = (row["check"] or {}).get("error")
            out.append(f"| {way if way != 'A_ci' else 'A'}: {label} | {n if way != 'A_ci' else 'PR #276'} | {row['summary']} | "
                       f"{', '.join(row['majors']) or 'none'} | {row['resolved']} of {row['total']} | {verdict(row['check'])}"
                       + (f": {error}" if error else "") + " |")
    if variants:
        out += ["", "## What decides the outcome", "",
                "Variants of the results above that change one line (files in `evaluation/fix_runs/pygoat/diagnostic/`):", "",
                "| Variant | Findings resolved | App |", "|---|---|---|"]
        for path in variants:
            text = path.read_text(encoding="utf-8")
            row = outcome(content, text, entry["findings"], upgrades)
            check = checks.get(content_key(FILE, text))
            error = (check or {}).get("error")
            out.append(f"| {path.stem.replace('_', ' ')} | {row['resolved']} of {row['total']} | {verdict(check)}"
                       + (f": {error[:300]}" if error else "") + " |")
    if trials:
        base_resolved = outcome(content, base_file.read_text(encoding="utf-8"), entry["findings"], upgrades)["resolved"]
        out += ["", "## Would the held-back major upgrades have worked?", "",
                f"Each upgrade that the plain rule and the service hold back (a major version change), applied on its own "
                f"to the candidate that passes (`{TRIAL_BASE}`, {base_resolved} of {len(entry['findings'])} findings), "
                "with the scanner's target. Files in `evaluation/fix_runs/pygoat/major_trials/`. Passing the smoke test "
                "means the app starts and its main pages work, not that every feature does.", "",
                "| Package | Upgrade | Extra findings fixed | App |", "|---|---|---|---|"]
        for name, (u, text) in sorted(trials.items()):
            check = checks.get(content_key(FILE, text))
            extra_fixed = outcome(content, text, entry["findings"], upgrades)["resolved"] - base_resolved
            error = (check or {}).get("error")
            out.append(f"| {name} | {u['current']} → {u['target']} | {extra_fixed} | {verdict(check)}"
                       + (f": {error[:260]}" if error else "") + " |")
    out += ["", "Held back for a person (the service's upgrade data):"] + [f"- {line}" for line in asva_rag_client.held_back(response)]
    out += ["", "Other lines changed by a result (should be none): "
            + ("; ".join(f"{way} run {n}: {', '.join(r['other_changes'])}" for way, rs in rows.items()
                         for n, r in enumerate(rs, 1) if r["other_changes"]) or "none")]
    OUT_DIR.mkdir(exist_ok=True)
    (OUT_DIR / "pygoat_fix_results.md").write_text("\n".join(out) + "\n", encoding="utf-8")
    (OUT_DIR / "pygoat_fix_results.json").write_text(json.dumps({"model": args.model, "rows": rows, "baseline": base},
                                                                indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print("\n".join(out[4:]))


if __name__ == "__main__":
    main()

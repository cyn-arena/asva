#!/usr/bin/env python3
"""Do the fixes get better with the service's context? An end-to-end comparison on NodeGoat's
dependency file (package.json) and container file (docker-compose.yml), with the real LLM and
the same "does the app still start" check as ASVA's PR check.

Three ways of producing each fix:
  A  ASVA today           the agent's current prompts, no context from this service
  B  context in the prompt  the same prompts plus the service's reference block, and one added
                          instruction: do not apply what the references call a major change
                          with no compatible fix
  C  upgrade data applied   the agent takes its versions from the service's upgrade data: only
                          compatible targets are applied, the rest is held back for a person

Each way is run several times (LLM answers vary). Every distinct resulting file is then built
and started with Docker Compose, and counted as working only if /login answers within 90 s.

    python tests/eval_fixes.py --env-file ../.env --nodegoat ../target-apps/NodeGoat
    python tests/eval_fixes.py --skip-llm --nodegoat ../target-apps/NodeGoat   # re-check saved answers
    python tests/eval_fixes.py --skip-llm --skip-docker                              # rebuild the report only

Needs: the local database (python -m app.sync), an OpenAI-compatible LLM endpoint
(OLLAMA_HOST, OLLAMA_API_KEY, OLLAMA_MODEL in the environment or --env-file), and for the
app-start check Docker plus the NodeGoat app folder. Writes evaluation/fix_results.md and
.json; the LLM's answers are kept under evaluation/fix_runs/.

The two prompts are copied from asva/agent/agent_loop.py (build_fix_prompt, 13 Oct 2026) so
that way A is what the pipeline does today. The findings and the two app files are fixtures.
"""

import argparse
import hashlib
import json
import os
import re
import sys
import time
from collections import Counter
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "integration"))
sys.path.insert(0, str(ROOT / "tools"))

import asva_rag_client  # noqa: E402
from app import config, net, store, versions  # noqa: E402
from app.context import ContextBuilder  # noqa: E402
from app.embed import Embedder  # noqa: E402
from app.retrieve import Retriever  # noqa: E402
from eval_sources import to_request  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures"
OUT_DIR = ROOT / "evaluation"
RUNS_DIR = OUT_DIR / "fix_runs"
CHECKS_FILE = OUT_DIR / "app_start_checks.json"
WAYS = {"A": "ASVA today (no context)", "D": "Plain rule, no service (same major version only)",
        "B": "Context in the prompt", "C": "Upgrade data applied"}
CASES = {"package.json": "sca", "docker-compose.yml": "container"}
LINES_TO_CHECK = ("5.0", "6.0", "7.0", "8.0")


# -- ASVA's prompts (agent/agent_loop.py), with {extra} where INTEGRATION.md puts the context ----

def asva_upgrade_map(findings: list[dict]) -> dict[str, str]:
    """The direct dependencies ASVA asks the LLM to set, from the scanner's upgrade targets."""
    upgrade_map: dict[str, str] = {}
    for f in findings:
        upgrade = f["remediation"].get("upgrade_to") or ""
        if not f["location"].get("package") or "@" not in upgrade:
            continue
        name, version = upgrade.split("@")[0], upgrade.split("@")[1]
        if name not in upgrade_map or versions.is_newer(version, upgrade_map[name]):
            upgrade_map[name] = version
    return upgrade_map


def sca_prompt(content: str, upgrade_map: dict[str, str], extra: str = "", instruction: str = "") -> str:
    summary = json.dumps([{"package": p, "upgrade_to_version": v} for p, v in upgrade_map.items()], indent=2)
    return f"""You are a senior security engineer fixing vulnerable npm dependencies.

File: package.json

Direct dependencies to upgrade (update these exact package names to the specified versions):
{summary}
{extra}
Current file content:
{content}

Instructions:
- Update ONLY the packages listed above in the dependencies or devDependencies sections.
- Set each package to EXACTLY the version specified in upgrade_to_version.
- If the current version is already equal to or higher than the specified version, leave it unchanged.
- Do NOT add, remove, or rename any other packages.
- Preserve all formatting, indentation, and JSON structure exactly.
{instruction}- Return ONLY the complete fixed file content. No explanation, no markdown, no code blocks.
"""


def container_prompt(content: str, findings: list[dict], extra: str = "", instruction: str = "",
                     exact_image: str | None = None) -> str:
    images = sorted({f"{f['location']['image_name']}:{f['location']['image_tag']}" for f in findings})
    summary = json.dumps([{"package": f["location"].get("package"), "upgrade_to": f["remediation"].get("upgrade_to"),
                           "cve": f["identifiers"].get("cve"), "title": f["title"]} for f in findings], indent=2)
    update = (f"- Update the image to exactly {exact_image}." if exact_image else
              "- Update each image to the latest stable version that resolves the listed OS package vulnerabilities.")
    return f"""You are a senior security engineer fixing vulnerable container images in the file that defines them.

File: docker-compose.yml

Vulnerable container images identified in the scan:
{json.dumps(images, indent=2)}

Vulnerable OS packages found inside those images:
{summary}
{extra}
Current file content:
{content}

Instructions:
- Find where docker-compose.yml uses the vulnerable image(s) listed above (e.g. an `image:` entry in a Compose file, or a `FROM` line in a Dockerfile).
{update}
- If a listed image is built from this file rather than referenced in it, update the base image in its `FROM` line instead.
- Do NOT change anything else in the file.
- Preserve all formatting, indentation, and structure exactly.
{instruction}- Return ONLY the complete fixed file content. No explanation, no markdown, no code blocks.
"""


RESPECT_SCA = ("- The reference material is from trusted sources. Where it says an upgrade is a MAJOR version change with "
               "no compatible fix, do NOT apply that upgrade: leave that package's version exactly as it is. Where it "
               "names a version that resolves findings without a major version change, set the package to that version "
               "instead of the listed one.\n")
RULE_CONTAINER = "- Keep each image within its current major version: never move it to a new major version.\n"
RESPECT_CONTAINER = ("- The reference material is from trusted sources. If it says there is no compatible fix (only new "
                     "major versions resolve the findings), do NOT change the image: return the file exactly as it is.\n")


# -- the LLM ------------------------------------------------------------------------------------

def load_env(path: Path | None) -> None:
    if path:
        from dotenv import dotenv_values
        for key, value in dotenv_values(path).items():
            if key.startswith("OLLAMA_") and value:
                os.environ.setdefault(key, value)


def call_llm(client: httpx.Client, prompt: str) -> str:
    """OpenAI-compatible streaming chat call, as asva/llm/llm_client.py makes it."""
    payload = {"model": os.environ["OLLAMA_MODEL"], "messages": [{"role": "user", "content": prompt}], "stream": True}
    parts, finished = [], None
    with client.stream("POST", "/v1/chat/completions", json=payload) as response:
        response.raise_for_status()
        for line in response.iter_lines():
            if not line.startswith("data:"):
                continue
            data = line[len("data:"):].strip()
            if data == "[DONE]":
                break
            for choice in json.loads(data).get("choices") or []:
                parts.append(choice.get("delta", {}).get("content") or "")
                finished = choice.get("finish_reason") or finished
    if finished != "stop":
        raise RuntimeError(f"the model did not finish its answer (finish_reason={finished})")
    text = "".join(parts).strip()
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:]).strip()
    return text


# -- the plain rule (way D): no service, no sources ----------------------------------------------

def installed_versions(findings: list[dict]) -> dict[str, str]:
    """Installed version per package, from the findings alone (vulnerable package and dependency path)."""
    found: dict[str, str] = {}
    for f in findings:
        for spec in [f["location"].get("package"), *((f.get("dependency") or {}).get("path") or [])]:
            name, version = versions.split_package(spec)
            if name and version:
                found.setdefault(name, version)
    return found


def _semver_same_major(a: str | None, b: str | None) -> bool:
    """Same major version by the version number alone (0.x by minor), as a plain rule would check."""
    x, y = versions.parse(a), versions.parse(b)
    return bool(x and y and x[0] == y[0] and (x[0] != 0 or x[1] == y[1]))


def plain_rule_map(findings: list[dict]) -> dict[str, str]:
    """The scanner's targets, keeping only those that stay in the installed major version: the
    rule "never apply a major version upgrade automatically", with no other knowledge."""
    installed = installed_versions(findings)
    return {name: target for name, target in asva_upgrade_map(findings).items()
            if installed.get(name) and versions.is_newer(target, installed[name]) and _semver_same_major(installed[name], target)}


# -- what a result means --------------------------------------------------------------------------

def spec_version(spec: str | None) -> str | None:
    match = re.search(r"\d+(?:\.\d+)*", spec or "")
    return match.group(0) if match else None


def sca_outcome(original: str, result: str, findings: list[dict], upgrades: list[dict]) -> dict:
    installed = {u["name"]: u["current"] for u in upgrades if u["kind"] == "package"}
    try:
        before, after = json.loads(original), json.loads(result)
    except ValueError:
        return {"valid": False, "summary": "not valid JSON", "changed": {}, "major": [], "fixed": 0, "total": len(findings)}
    deps = lambda doc: {**doc.get("devDependencies", {}), **doc.get("dependencies", {})}  # noqa: E731
    changed = {name: deps(after).get(name) for name in deps(before) if deps(before)[name] != deps(after).get(name)}
    other = sorted(k for k in set(before) | set(after) if k not in ("dependencies", "devDependencies") and before.get(k) != after.get(k))
    major = sorted(name for name, spec in changed.items()
                   if installed.get(name) and not versions.same_major(installed[name], spec_version(spec)))
    fixed = held = 0
    for f in findings:
        name, needed = versions.split_package(f["remediation"].get("upgrade_to"))
        now = spec_version(deps(after).get(name))
        if installed.get(name) and versions.parse(installed[name]) == versions.parse(needed):
            held += 1   # already at the scanner's target: a bump of package.json cannot fix it
        elif name in changed and now and versions.parse(now) >= versions.parse(needed):
            fixed += 1
    summary = ", ".join(f"{name} {spec}" for name, spec in sorted(changed.items())) or "no change"
    return {"valid": True, "summary": summary, "changed": changed, "major": major, "fixed": fixed, "total": len(findings),
            "not_fixable_by_bump": held, "other_changes": other}


def container_outcome(original: str, result: str, upgrades: list[dict]) -> dict:
    image = next(u for u in upgrades if u["kind"] == "image")
    tag = lambda text: (re.search(r"image:\s*" + re.escape(image["name"]) + r":(\S+)", text) or [None, None])[1]  # noqa: E731
    before, after = tag(original), tag(result)
    candidates = image.get("candidates") or []
    unpinned = after == "latest"   # whatever is newest on the day the image is pulled
    line = candidates[-1] if unpinned and candidates else next((c for c in candidates if c["tag"] == after), None)
    cves = len(image["fixes"])
    resolved = cves if line and line.get("cves_checked") and line["cves_resolved"] == line["cves_checked"] else 0
    other = [l for l in result.strip().splitlines() if l not in original.splitlines() and "image:" not in l]
    note = " (unchanged)" if after == before else f" (unpinned tag; {line.get('version') or line['tag']} today)" if unpinned and line else ""
    return {"valid": after is not None, "summary": f"{image['name']}:{after}{note}",
            "changed": {} if after == before else {image["name"]: after},
            "major": [image["name"]] if after and after != before and not versions.same_major(before, after) else [],
            "fixed": resolved if after != before else 0, "total": cves, "other_changes": other,
            "end_of_life": bool(line and line.get("end_of_life"))}


# -- running --------------------------------------------------------------------------------------

def service_response(case: str, findings: list[dict], fix_type: str) -> dict:
    with closing(store.connect(config.DB_PATH)) as conn, net.make_client() as client:
        builder = ContextBuilder(Retriever.from_db(conn, Embedder()), client)
        items, references, warnings, upgrades = builder.build(conn, [to_request(f) for f in findings], fix_type, config.DEFAULT_MAX_CHARS)
    return {"items": items, "references": references, "warnings": warnings, "upgrades": upgrades}


def prompts_for(case: str, content: str, findings: list[dict], response: dict) -> dict[str, str | None]:
    """The prompt per way; None means the agent makes no change without asking the LLM."""
    block = asva_rag_client.prompt_block(response)
    extra = f"\n{block}\n" if block else ""
    if case == "package.json":
        compatible = {u["name"]: u["compatible_target"] for u in response["upgrades"]
                      if u["kind"] == "package" and u.get("compatible_target")}
        rule = plain_rule_map(findings)
        return {"A": sca_prompt(content, asva_upgrade_map(findings)),
                "D": sca_prompt(content, rule) if rule else None,
                "B": sca_prompt(content, asva_upgrade_map(findings), extra, RESPECT_SCA),
                "C": sca_prompt(content, compatible, extra) if compatible else None}
    image = next(u for u in response["upgrades"] if u["kind"] == "image")
    exact = f"{image['name']}:{image['compatible_target']}" if image.get("compatible_target") else None
    return {"A": container_prompt(content, findings),
            "D": container_prompt(content, findings, instruction=RULE_CONTAINER),
            "B": container_prompt(content, findings, extra, RESPECT_CONTAINER),
            "C": container_prompt(content, findings, extra, exact_image=exact) if exact else None}


def run_llm(runs: int, cases: dict, env_file: Path | None) -> None:
    load_env(env_file)
    missing = [k for k in ("OLLAMA_HOST", "OLLAMA_API_KEY", "OLLAMA_MODEL") if not os.environ.get(k)]
    if missing:
        sys.exit(f"LLM settings missing: {', '.join(missing)} (set them or pass --env-file)")
    with httpx.Client(base_url=os.environ["OLLAMA_HOST"].rstrip("/"), timeout=600,
                      headers={"Authorization": f"Bearer {os.environ['OLLAMA_API_KEY']}"}) as client:
        for case, data in cases.items():
            for way, prompt in data["prompts"].items():
                folder = RUNS_DIR / way / case.replace(".", "_")
                folder.mkdir(parents=True, exist_ok=True)
                (folder / "prompt.txt").write_text(prompt or "(no LLM call: nothing compatible to apply, the file is left unchanged)",
                                                   encoding="utf-8")
                for n in range(1, runs + 1):
                    out = folder / f"run{n}{Path(case).suffix}"
                    if out.exists():
                        continue
                    if prompt is None:
                        out.write_text(data["content"], encoding="utf-8", newline="\n")
                        print(f"  {way} {case} run {n}: no LLM call (held back)")
                        continue
                    started = time.time()
                    answer = call_llm(client, prompt)
                    out.write_text(answer + "\n", encoding="utf-8", newline="\n")
                    print(f"  {way} {case} run {n}: {len(answer)} chars in {time.time() - started:.0f}s")


def app_checks(nodegoat: Path | None, wanted: dict[str, tuple[str, dict]]) -> dict:
    """Run (or reuse) the app-start check for each distinct candidate: key -> result."""
    done = json.loads(CHECKS_FILE.read_text(encoding="utf-8")) if CHECKS_FILE.exists() else {}
    todo = {key: value for key, value in wanted.items() if key not in done}
    if todo and nodegoat:
        from app_start_check import check
        for key, (name, files) in todo.items():
            print(f"  app-start check: {name} ...", flush=True)
            done[key] = check(nodegoat, name, files)
            print(f"    -> {'starts' if done[key]['ready'] else 'DOES NOT START'}" + (f" ({done[key]['error']})" if done[key].get("error") else ""))
            CHECKS_FILE.write_text(json.dumps(done, indent=1), encoding="utf-8")
    return done


def content_key(file: str, content: str) -> str:
    return hashlib.sha1(f"{file}\n{content.strip()}".encode()).hexdigest()[:16]


# -- report ---------------------------------------------------------------------------------------

def short_error(error: str | None) -> str:
    """The message of a logged error (a MongoError is logged as a long JSON object)."""
    message = re.search(r'"message":"([^"]+)"', error or "")
    return message.group(1) if message else (error or "no answer on /login")


def verdict(check: dict | None) -> str:
    if check is None:
        return "not checked"
    return f"starts ({check['ready_after']} s)" if check["ready"] else "**does not start**"


def markdown(report: dict) -> str:
    out = ["# Fix evaluation: do fixes get better with the service's context?", "",
           f"Generated {report['generated_at']} by `tests/eval_fixes.py`. LLM: {report['model']}, {report['runs']} runs per way. "
           f"Findings: NodeGoat scan {report['scan']}. \"Starts\" is ASVA's PR-check test: the app is built and started with "
           f"Docker Compose and must answer on /login within 90 seconds.", "",
           "## Summary", "", "| File | " + " | ".join(f"{way}: {name}" for way, name in WAYS.items()) + " |",
           "|---|" + "---|" * len(WAYS)]
    for case, data in report["cases"].items():
        cells = []
        for way in WAYS:
            verdicts: Counter = Counter()
            for row in data["ways"].get(way, []):
                if row["check"] is None:
                    verdicts[f"{row['summary']}: not checked"] += row["runs"]
                elif not row["check"]["ready"]:
                    verdicts["**breaks the app**"] += row["runs"]
                elif row["changed"]:
                    verdicts[f"app starts, {row['fixed']} of {row['total']} findings fixed"] += row["runs"]
                else:
                    verdicts["no change made, app unaffected"] += row["runs"]
            cells.append("; ".join(f"{text} ({runs} of {report['runs']} runs)" for text, runs in verdicts.items()) or "-")
        out.append(f"| {case} | " + " | ".join(cells) + " |")
    out.append("")
    for case, data in report["cases"].items():
        kind = "dependencies" if data["kind"] == "sca" else "container image"
        out += [f"## {case} ({kind}, {data['findings']} findings)", "",
                "| Way | What the fix did (runs) | Major version changes applied | App after the fix | Findings resolved by a fix that works |",
                "|---|---|---|---|---|"]
        for way, rows in data["ways"].items():
            for row in rows:
                works = row["check"] is not None and row["check"]["ready"]
                effective = (f"{row['fixed']} of {row['total']}" if works else f"0 of {row['total']}") if row["check"] else "-"
                if row["changed"] == {} and works:
                    effective = f"0 of {row['total']} (nothing applied, nothing broken)"
                out.append(f"| {way}: {WAYS[way]} | {row['summary']} ({row['runs']} of {report['runs']}) | "
                           f"{', '.join(row['major']) or 'none'} | {verdict(row['check'])} | {effective} |")
        for way, rows in data["ways"].items():
            for row in rows:
                if row["check"] and not row["check"]["ready"]:
                    out += ["", f"Why way {way} ({row['summary']}) does not start: `{short_error(row['check'].get('error'))}`"]
        if data["kind"] == "sca":
            out += ["", "Versions installed in the built app, read from the running container:"]
            for way, rows in data["ways"].items():
                installed: Counter = Counter()
                for row in rows:
                    if row["check"] and row["check"].get("installed"):
                        installed[", ".join(row["check"]["installed"])] += row["runs"]
                out += [f"- {way} ({runs} of {report['runs']} runs): {listed}" for listed, runs in installed.items()]
            out += ["", "Note: \"findings resolved\" here means the scanner's target is set in package.json. npm also keeps "
                        "nested copies (express 4.16.4 brings its own body-parser 1.18.3 and qs 6.5.2), so fewer are really gone: "
                        "measured against the lockfile, and matching Snyk's own rescan, way C fixes 6 of these 26, and 9 with a "
                        "lockfile refresh. See [nodegoat_lockfile.md](nodegoat_lockfile.md)."]
            if data.get("not_fixable_by_bump"):
                out += ["", f"{data['not_fixable_by_bump']} of the {data['findings']} findings cannot be fixed by any version bump in "
                            f"package.json: their package is already at the scanner's target, and the vulnerable packages come in "
                            f"through it (lockfile refresh or npm overrides needed)."]
        if data.get("held"):
            out += ["", "Held back for a person in way C, with the service's reason:"]
            out += [f"- {line}" for line in data["held"]]
        out.append("")
    if report.get("lines"):
        out += ["## Which MongoDB lines the app starts on (as it is, driver 2.2.36)", "",
                "| Image | App | Checked CVEs resolved by its base OS | Support |", "|---|---|---|---|"]
        for line in report["lines"]:
            out.append(f"| mongo:{line['tag']} | {verdict(line['check'])} | {line['resolved']} | {line['support']} |")
        failed = next((line["check"] for line in report["lines"] if line["check"] and not line["check"]["ready"]), None)
        if failed:
            out += ["", f"The lines it does not start on fail with: `{short_error(failed.get('error'))}`"]
        out.append("")
    return "\n".join(out) + "\n"


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--runs", type=int, default=3, help="LLM runs per way and file (default 3).")
    parser.add_argument("--env-file", type=Path, help="A .env file with OLLAMA_HOST, OLLAMA_API_KEY and OLLAMA_MODEL.")
    parser.add_argument("--nodegoat", type=Path, help="The NodeGoat app folder, for the app-start check.")
    parser.add_argument("--skip-llm", action="store_true", help="Use the answers already saved under evaluation/fix_runs.")
    parser.add_argument("--skip-docker", action="store_true", help="Do not run new app-start checks.")
    args = parser.parse_args()

    fixture = json.loads((FIXTURES / "nodegoat_findings.json").read_text(encoding="utf-8"))
    cases = {}
    for entry in fixture["files"]:
        if entry["file"] in CASES:
            content = (FIXTURES / "nodegoat_files" / entry["file"]).read_text(encoding="utf-8").replace("\r\n", "\n")
            response = service_response(entry["file"], entry["findings"], entry["fix_type"])
            cases[entry["file"]] = {"entry": entry, "content": content, "response": response,
                                    "prompts": prompts_for(entry["file"], content, entry["findings"], response)}
    if not args.skip_llm:
        print("LLM runs:")
        run_llm(args.runs, cases, args.env_file)
    load_env(args.env_file)

    # group identical answers, then check each distinct candidate once
    wanted, report_cases = {}, {}
    for case, data in cases.items():
        entry, upgrades = data["entry"], data["response"]["upgrades"]
        ways = {}
        for way in WAYS:
            folder = RUNS_DIR / way / case.replace(".", "_")
            answers = [p.read_text(encoding="utf-8") for p in sorted(folder.glob("run*"))] if folder.exists() else []
            groups: dict[str, dict] = {}
            for answer in answers:
                outcome = (sca_outcome(data["content"], answer, entry["findings"], upgrades) if CASES[case] == "sca"
                           else container_outcome(data["content"], answer, upgrades))
                group = groups.setdefault(outcome["summary"], {**outcome, "runs": 0, "key": content_key(case, answer), "answer": answer})
                group["runs"] += 1
            ways[way] = sorted(groups.values(), key=lambda g: -g["runs"])
            for group in ways[way]:
                if group["valid"]:
                    name = f"{way}-{case.split('.')[0]}-{group['key'][:6]}"
                    wanted[group["key"]] = (name, {} if group["answer"].strip() == data["content"].strip() else {case: group["answer"]})
        held = [f"{u['name']} {u.get('current')}: {u['note']}" for u in upgrades
                if not u.get("compatible_target") and u.get("note")]
        cannot = next((g.get("not_fixable_by_bump") for rows in ways.values() for g in rows if g.get("not_fixable_by_bump")), 0)
        report_cases[case] = {"kind": CASES[case], "findings": len(entry["findings"]), "ways": ways, "held": held,
                              "not_fixable_by_bump": cannot}

    compose = cases["docker-compose.yml"]["content"]
    image = next(u for u in cases["docker-compose.yml"]["response"]["upgrades"] if u["kind"] == "image")
    line_keys = {}
    for tag in LINES_TO_CHECK:
        content = compose.replace("image: mongo:4.4", f"image: mongo:{tag}")
        line_keys[tag] = content_key("docker-compose.yml", content)
        wanted.setdefault(line_keys[tag], (f"line-mongo-{tag}", {"docker-compose.yml": content}))
    wanted.setdefault(content_key("docker-compose.yml", compose), ("unchanged", {}))

    checks = app_checks(None if args.skip_docker else args.nodegoat, wanted)
    for data in report_cases.values():
        for rows in data["ways"].values():
            for row in rows:
                row["check"] = checks.get(row.pop("key"))
                row.pop("answer")
    lines = []
    for tag in LINES_TO_CHECK:
        candidate = next((c for c in image.get("candidates") or [] if c["tag"] == tag), {})
        support = "past end of life" if candidate.get("end_of_life") else (
            f"until {candidate['supported_until']}" if candidate.get("supported_until") else "unknown")
        resolved = f"{candidate['cves_resolved']} of {candidate['cves_checked']}" if candidate.get("cves_checked") else "unknown"
        lines.append({"tag": tag, "check": checks.get(line_keys[tag]), "resolved": resolved, "support": support})

    report = {"generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
              "model": os.environ.get("OLLAMA_MODEL", "unknown"), "runs": args.runs,
              "scan": f"{fixture['source']['scan_run_id']} @ {fixture['source']['commit_sha']}",
              "cases": report_cases, "lines": lines}
    OUT_DIR.mkdir(exist_ok=True)
    (OUT_DIR / "fix_results.json").write_text(json.dumps(report, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    (OUT_DIR / "fix_results.md").write_text(markdown(report), encoding="utf-8")
    print()
    print(markdown(report))
    print(f"Wrote {OUT_DIR / 'fix_results.md'} and fix_results.json; the LLM's answers are in {RUNS_DIR}")


if __name__ == "__main__":
    main()

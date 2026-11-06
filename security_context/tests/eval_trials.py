#!/usr/bin/env python3
"""Option B in practice: follow the service's trial plan the way a reviewer would, and measure it.

The plan lists the upgrades held back from the safe candidate, in the order to try them, each with
the companion upgrades it needs (app/trials.py). This script carries out every trial on its own on
top of the safe candidate, then all the trials that passed together, and checks each result the
way the pipeline does:

  PyGoat    build Dockerfile.asva, start, ASVA's smoke test (tools/pygoat_start_check.py); a finding
            is fixed when the pinned version reaches the scanner's target
  NodeGoat  npm writes the lockfile; build, start, /login (tools/app_start_check.py); a finding is
            fixed when every installed copy is at or above OSV.dev's fixed version (the count that
            matched Snyk's own rescan, tests/eval_nodegoat_lockfile.py)

Safe candidates: PyGoat, the service's compatible versions with PyYAML kept at 5.1 (5.4 does not
build on Python 3.11: see evaluation/pygoat_fix_results.md); NodeGoat, the service's compatible
upgrades with the lockfile from npm (evaluation/fix_runs/nodegoat_lockfile/rag/, written by
tests/eval_nodegoat_lockfile.py).

    python tests/eval_trials.py --asva ..            # writes evaluation/trial_results.md

Needs npm and Docker. The asva folder is only read.
"""

import argparse
import json
import shutil
import subprocess
import sys
import tempfile
from contextlib import closing
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(Path(__file__).parent), str(ROOT / "integration"), str(ROOT / "tools")]

import asva_rag_client  # noqa: E402
import pygoat_start_check  # noqa: E402
from app import config, net, store, versions  # noqa: E402
from app.context import ContextBuilder  # noqa: E402
from app.embed import Embedder  # noqa: E402
from app.retrieve import Retriever  # noqa: E402
from eval_fixes import CHECKS_FILE, content_key  # noqa: E402
from eval_nodegoat_lockfile import NPM_ARGS, fix_table, in_app, npm, status  # noqa: E402
from eval_pygoat_fixes import outcome, set_version, verdict  # noqa: E402
from eval_sources import FIXTURES, OUT_DIR, to_request  # noqa: E402

RUNS = OUT_DIR / "fix_runs" / "trials"


def service(fixture: str, manifest: dict) -> tuple[dict, list[dict], list[dict]]:
    entry = next(e for e in json.loads((FIXTURES / fixture).read_text(encoding="utf-8"))["files"] if e["finding_type"] == "sca")
    request = [to_request(f) for f in entry["findings"]]
    with closing(store.connect(config.DB_PATH)) as conn, net.make_client() as client:
        builder = ContextBuilder(Retriever.from_db(conn, Embedder()), client)
        items, refs, warnings, upgrades = builder.build(conn, request, entry["fix_type"], config.DEFAULT_MAX_CHARS)
        trials = builder.plan_trials(conn, request, upgrades, refs, manifest, warnings)
    return entry, {"upgrades": upgrades, "references": refs, "trials": trials}, request


def load_checks() -> dict:
    return json.loads(CHECKS_FILE.read_text(encoding="utf-8")) if CHECKS_FILE.exists() else {}


def save_check(checks: dict, key: str, result: dict) -> None:
    checks[key] = result
    CHECKS_FILE.write_text(json.dumps(checks, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


# -- PyGoat ---------------------------------------------------------------------------------------

def pygoat(asva: Path, skip_docker: bool) -> dict:
    app = asva / "target-apps" / "PyGoat"
    original = (FIXTURES / "pygoat_files" / "requirements.txt").read_text(encoding="utf-8").replace("\r\n", "\n")
    entry, response, _ = service("pygoat_findings.json", {"file": "requirements.txt", "content": original})
    base = (OUT_DIR / "fix_runs" / "pygoat" / "diagnostic" / "rag_with_pyyaml_5.1.txt").read_text(encoding="utf-8")
    folder = RUNS / "pygoat"
    folder.mkdir(parents=True, exist_ok=True)
    checks = load_checks()

    def run(label: str, text: str) -> dict:
        (folder / f"{label}.txt").write_text(text, encoding="utf-8", newline="\n")
        key = content_key("requirements.txt", text)
        if key not in checks and not skip_docker:
            print(f"  PyGoat {label} ...", flush=True)
            save_check(checks, key, pygoat_start_check.check(app, asva / "scripts" / "pygoat-smoke.py", f"trial-{label}",
                                                             {"requirements.txt": text}))
        return {"label": label, "resolved": outcome(original, text, entry["findings"], response["upgrades"])["resolved"],
                "check": checks.get(key)}

    def apply(text: str, trial: dict) -> str:
        text = set_version(text, trial["name"], trial["target"])
        for companion in trial["also_needs"]:
            if companion.get("suggest"):
                text = set_version(text, companion["name"], companion["suggest"])
        return text

    rows = [run("0_safe_candidate", base)]
    for trial in response["trials"]:
        rows.append({**run(f"{trial['order']}_{trial['name']}", apply(base, trial)), "trial": trial})
    passed = [r["trial"] for r in rows[1:] if r["check"] and r["check"]["ready"] and r["check"]["smoke"] == "passed"]
    combined = base
    for trial in passed:
        combined = apply(combined, trial)
    final = run("all_passing_trials", combined) if passed else None
    return {"entry": entry, "response": response, "rows": rows, "final": final, "passed": passed}


# -- NodeGoat -------------------------------------------------------------------------------------

def nodegoat(asva: Path, skip_docker: bool, plain_paths: bool = False) -> dict:
    app = asva / "target-apps" / "NodeGoat"
    base_dir = OUT_DIR / "fix_runs" / "nodegoat_lockfile" / "rag"
    base = {name: (base_dir / name).read_text(encoding="utf-8") for name in ("package.json", "package-lock.json")}
    names = sorted({f["location"]["package"].rsplit("@", 1)[0] for e in json.loads(
        (FIXTURES / "nodegoat_branch_findings.json").read_text(encoding="utf-8"))["files"] if e["finding_type"] == "sca"
        for f in e["findings"]})
    # what ASVA would send once the npm path has written the safe candidate's lockfile
    manifest = {"file": "package.json", "content": base["package.json"],
                "dev_only": asva_rag_client.npm_dev_only(base["package-lock.json"]),
                **({} if plain_paths else {"copies": asva_rag_client.npm_copies(base["package-lock.json"], names)})}
    entry, response, request = service("nodegoat_branch_findings.json", manifest)
    findings = entry["findings"]
    fixed_in = fix_table(findings, response["references"])
    app_labels = in_app(findings, json.loads((app / "package-lock.json").read_text(encoding="utf-8")))
    checks = load_checks()

    def run(label: str, files: dict) -> dict:
        folder = RUNS / ("nodegoat_scanner_paths" if plain_paths else "nodegoat") / label
        folder.mkdir(parents=True, exist_ok=True)
        for name, text in files.items():
            (folder / name).write_text(text, encoding="utf-8", newline="\n")
        key = content_key("nodegoat-deps", json.dumps(files, sort_keys=True))
        if key not in checks and not skip_docker:
            from app_start_check import check
            print(f"  NodeGoat {label} ...", flush=True)
            save_check(checks, key, check(app, f"trial-{label}", files))
        lock = json.loads(files["package-lock.json"])
        result = status(findings, lock, fixed_in, app_labels)
        fixed = [x.split(" (")[0] for x in result["fixed"]]
        # copies bundled inside an optional package (fsevents: macOS only) are never installed in the
        # Linux image, and npm cannot change them; Snyk still reports them from the lockfile
        installed = {**lock, "packages": {p: e for p, e in lock["packages"].items() if not (e.get("inBundle") and e.get("optional"))}}
        in_image = [x.split(" (")[0] for x in status(findings, installed, fixed_in, app_labels)["fixed"]]
        return {"label": label, "in_app": sum(x in app_labels for x in fixed), "in_dev": sum(x not in app_labels for x in fixed),
                "in_image": sum(x in app_labels for x in in_image), "check": checks.get(key)}

    def apply(files: dict, trial: dict) -> dict:
        work = Path(tempfile.mkdtemp(prefix="asva-rag-trial-"))
        try:
            for name, text in files.items():
                (work / name).write_text(text, encoding="utf-8", newline="\n")
            if trial["kind"] == "lockfile_refresh":
                names = sorted({versions.split_package(f["package"])[0] for f in request if (f.get("cve") or f.get("rule_id")) in trial["fixes"]})
                npm(["update", *names, *NPM_ARGS], work)
            else:
                doc = json.loads(files["package.json"])
                section = next((s for s in ("dependencies", "devDependencies") if trial["name"] in doc.get(s, {})), None)
                if section:
                    doc[section][trial["name"]] = trial["target"]
                    (work / "package.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
                    npm(["install", *NPM_ARGS], work)
                else:  # a development tool's own dependency, not declared: add it as a devDependency
                    npm(["install", f"{trial['name']}@{trial['target']}", "--save-dev", *NPM_ARGS], work)
            return {name: (work / name).read_text(encoding="utf-8") for name in files}
        finally:
            shutil.rmtree(work, ignore_errors=True)

    rows = [run("0_safe_candidate", base)]
    for trial in response["trials"]:
        rows.append({**run(f"{trial['order']}_{trial['kind']}_{trial['name']}", apply(base, trial)), "trial": trial})
    passed = [r["trial"] for r in rows[1:] if r["check"] and r["check"]["ready"]
              and (r["in_app"] > rows[0]["in_app"] or r["in_dev"] > rows[0]["in_dev"])]
    combined = base
    for trial in passed:
        combined = apply(combined, trial)
    final = run("all_passing_trials", combined) if passed else None
    return {"entry": entry, "response": response, "rows": rows, "final": final, "passed": passed, "in_app": len(app_labels)}


# -- report ---------------------------------------------------------------------------------------

def describe(trial: dict | None) -> str:
    if not trial:
        return "safe candidate (the service's compatible upgrades)"
    what = f"{trial['name']} {trial.get('current') or ''} → {trial['target']}" if trial.get("target") else "lockfile refresh"
    also = ", ".join(f"{c['name']} → {c['suggest']}" for c in trial["also_needs"] if c.get("suggest"))
    return f"{trial['order']}. {what}" + (f" (with {also})" if also else "") + (" [dev tools]" if trial.get("dev_only") else "")


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--asva", required=True, type=Path)
    parser.add_argument("--skip-docker", action="store_true")
    parser.add_argument("--only", choices=["pygoat", "nodegoat"])
    parser.add_argument("--scanner-paths", action="store_true",
                        help="NodeGoat: plan from the scanner's one path per finding instead of every copy in the lockfile")
    args = parser.parse_args()

    out = ["# Option B: following the trial plan", "",
           "Written by `tests/eval_trials.py`. Each trial is applied on its own to the safe candidate, with the companion "
           "upgrades the plan names; then all trials that passed are applied together. Files in `evaluation/fix_runs/trials/`.", ""]
    if args.only in (None, "pygoat"):
        py = pygoat(args.asva, args.skip_docker)
        total = len(py["entry"]["findings"])
        out += ["## PyGoat (requirements.txt)", "", asva_rag_client.trial_plan(py["response"]), "",
                "| Candidate | Findings fixed | App |", "|---|---|---|"]
        for row in py["rows"] + ([py["final"]] if py["final"] else []):
            label = describe(row.get("trial")) if row["label"] != "all_passing_trials" else "**all passing trials together**"
            error = (row["check"] or {}).get("error")
            out.append(f"| {label} | {row['resolved']} of {total} | {verdict(row['check'])}" + (f": {error[:200]}" if error else "") + " |")
        out.append("")
    if args.only in (None, "nodegoat"):
        ng = nodegoat(args.asva, args.skip_docker, args.scanner_paths)
        out += ["## NodeGoat (package.json and package-lock.json)", "", asva_rag_client.trial_plan(ng["response"]), "",
                f"| Candidate | Fixed, of {ng['in_app']} in the app (as Snyk counts) | Not in the Linux image any more | "
                "Fixed, in dev tools only | App |", "|---|---|---|---|---|",]
        for row in ng["rows"] + ([ng["final"]] if ng["final"] else []):
            label = describe(row.get("trial")) if row["label"] != "all_passing_trials" else "**all passing trials together**"
            check = row["check"]
            app = "not checked" if check is None else ("starts" if check["ready"] else f"**does not start**: {str(check.get('error'))[:160]}")
            out.append(f"| {label} | {row['in_app']} | {row['in_image']} | {row['in_dev']} | {app} |")
        out += ["", "\"Not in the Linux image any more\" also counts findings whose only vulnerable copies are bundled inside an "
                "optional package that is not installed on Linux (fsevents, a macOS file watcher). npm cannot update those "
                "copies, and Snyk still reports them from the lockfile. Checked in the built image of the last row: "
                "node_modules/fsevents does not exist.", ""]
    (OUT_DIR / "trial_results.md").write_text("\n".join(out) + "\n", encoding="utf-8")
    print("\n".join(out))


if __name__ == "__main__":
    main()

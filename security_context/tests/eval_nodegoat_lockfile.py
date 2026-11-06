#!/usr/bin/env python3
"""How many of NodeGoat's dependency findings are really fixed, and does the app still start?

ASVA's npm path (agent/npm_remediation.py) edits package.json and lets npm write the lockfile.
npm installs nested copies (express 4.16.4 brings its own body-parser 1.18.3), so a finding counts
as fixed here only if EVERY installed copy of the vulnerable package is at or above the version
OSV.dev lists as fixing it: the view Snyk takes when it rescans the lockfile.

Candidates, each built from a throwaway copy of NodeGoat:
  pipeline   the pipeline's own dependency candidate (--pr-dir: package.json + package-lock.json of
             that PR), also used to check this count against Snyk's rescan of it (--rescan)
  rag        the service's compatible upgrades in package.json, lockfile by npm (what the npm path
             would produce with the service's upgrade data)
  rag+refresh  the same, plus `npm update` of the vulnerable packages that only come in through
             other packages (newer versions within the ranges their parents allow)

    python tests/eval_nodegoat_lockfile.py --nodegoat ../target-apps/NodeGoat \\
        --pr-dir data/pipeline_runs/nodegoat_39018400601/pr274 \\
        --rescan data/pipeline_runs/nodegoat_39018400601/nodegoat-after-fix-asva_sca_23be8e20/findings/ranked_unified_findings.json

Writes evaluation/nodegoat_lockfile.md; lockfiles in evaluation/fix_runs/nodegoat_lockfile/. Needs
npm and Docker (--skip-docker: no app checks). The NodeGoat folder is only read.
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
from app import config, net, store, versions  # noqa: E402
from app.context import ContextBuilder  # noqa: E402
from app.embed import Embedder  # noqa: E402
from app.retrieve import Retriever  # noqa: E402
from app.sources import osv  # noqa: E402
from eval_fixes import CHECKS_FILE, content_key  # noqa: E402
from eval_sources import FIXTURES, OUT_DIR, to_request  # noqa: E402

NPM_ARGS = ["--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund", "--lockfile-version=2"]
KEEP = OUT_DIR / "fix_runs" / "nodegoat_lockfile"


def npm(args: list[str], cwd: Path) -> None:
    executable = shutil.which("npm") or shutil.which("npm.cmd")
    done = subprocess.run([executable, *args], cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if done.returncode:
        raise SystemExit(f"npm {' '.join(args)} failed: {(done.stderr or done.stdout)[-800:]}")


def installed(lock: dict, name: str, production_only: bool = False) -> list[str]:
    """Every installed version of a package in a version-2 lockfile (only what `npm install
    --production` installs, if asked: entries not marked dev)."""
    return [entry.get("version") for path, entry in lock.get("packages", {}).items()
            if path.split("node_modules/")[-1] == name and entry.get("version")
            and not (production_only and entry.get("dev"))]


def finding_id(f: dict) -> str:
    return f["identifiers"].get("cve") or f["identifiers"].get("rule_id")


def in_app(findings: list[dict], lock: dict) -> set[str]:
    """Finding labels whose vulnerable package version the production image installs (lockfile
    entries not marked dev; NodeGoat's Dockerfile runs `npm install --production`)."""
    labels = set()
    for f in findings:
        name, version = versions.split_package(f["location"].get("package"))
        entries = [e for p, e in lock.get("packages", {}).items()
                   if p.split("node_modules/")[-1] == name and e.get("version") == version]
        if any(not e.get("dev") for e in entries):
            labels.add(f"{name} {finding_id(f)}")
    return labels


def status(findings: list[dict], lock: dict, fixed_in: dict, app: set[str] = frozenset()) -> dict[str, list[str]]:
    """fixed / still vulnerable (with the copies left) / fix unknown. A finding in a package the app
    runs is judged on the copies the production image installs; a dev-tool finding on all copies."""
    out = {"fixed": [], "vulnerable": [], "unknown": []}
    for f in findings:
        name = versions.split_package(f["location"].get("package"))[0]
        label = f"{name} {finding_id(f)}"
        fix, copies = fixed_in.get((name, finding_id(f))), installed(lock, name, production_only=label in app)
        if not copies:
            out["fixed"].append(label + " (package no longer installed)")
        elif not fix:
            out["unknown"].append(label)
        elif all(versions.parse(v) >= versions.parse(fix) for v in copies):
            out["fixed"].append(label)
        else:
            out["vulnerable"].append(f"{label}: needs {fix}, has {', '.join(sorted(set(copies)))}")
    return out


def fix_table(findings: list[dict], refs: list[dict]) -> dict[tuple[str, str], str | None]:
    """(package, finding id) -> the version that fixes it: the service's OSV.dev references, else
    OSV.dev asked directly, else the scanner's own target when it names the package itself."""
    fixed_in = {}
    for f in findings:
        name = versions.split_package(f["location"].get("package"))[0]
        match = next((r for r in refs if r["type"] == "advisory" and r.get("package") == name
                      and (finding_id(f) in (r.get("aliases") or []) or r["id"] == finding_id(f))), None)
        fixed_in[(name, finding_id(f))] = match and match.get("fixed_in")
    with closing(store.connect(config.DB_PATH)) as conn, net.make_client() as client:
        for f in findings:
            name, version = versions.split_package(f["location"].get("package"))
            if fixed_in[(name, finding_id(f))] is None:
                found = osv.advisories(conn, client, name, version, "npm", []) or []
                hit = next((a for a in found if finding_id(f) in a["aliases"] or a["id"] == finding_id(f)), None)
                target_name, target = versions.split_package(f["remediation"].get("upgrade_to"))
                fixed_in[(name, finding_id(f))] = (hit and hit["fixed"]) or (target if target_name == name else None)
    return fixed_in


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--nodegoat", required=True, type=Path)
    parser.add_argument("--fixture", default="nodegoat_branch_findings.json")
    parser.add_argument("--pr-dir", type=Path, help="package.json + package-lock.json of the pipeline's dependency PR.")
    parser.add_argument("--rescan", type=Path, help="ranked_unified_findings.json of the pipeline's rescan of that PR.")
    parser.add_argument("--skip-docker", action="store_true")
    args = parser.parse_args()

    entry = next(e for e in json.loads((FIXTURES / args.fixture).read_text(encoding="utf-8"))["files"]
                 if e["finding_type"] == "sca")
    findings = entry["findings"]
    with closing(store.connect(config.DB_PATH)) as conn, net.make_client() as client:
        builder = ContextBuilder(Retriever.from_db(conn, Embedder()), client)
        items, refs, warnings, upgrades = builder.build(conn, [to_request(f) for f in findings], entry["fix_type"], 2500)
    compatible = asva_rag_client.compatible_upgrades({"upgrades": upgrades})
    fixed_in = fix_table(findings, refs)
    manifest = json.loads((args.nodegoat / "package.json").read_text(encoding="utf-8"))
    direct = {n for s in ("dependencies", "devDependencies") for n in manifest.get(s, {})}
    indirect = sorted({versions.split_package(f["location"]["package"])[0] for f in findings} - direct)

    work = Path(tempfile.mkdtemp(prefix="asva-rag-lock-"))
    for name in ("package.json", "package-lock.json"):
        shutil.copyfile(args.nodegoat / name, work / name)
    for name, version in compatible.items():
        section = next((s for s in ("dependencies", "devDependencies") if name in manifest.get(s, {})), None)
        if section:
            manifest[section][name] = version
    (work / "package.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    npm(["install", *NPM_ARGS], work)
    candidates = {"unchanged": {name: (args.nodegoat / name).read_text(encoding="utf-8") for name in ("package.json", "package-lock.json")}}
    if args.pr_dir:
        candidates["pipeline (PR, every scanner target)"] = {name: (args.pr_dir / name).read_text(encoding="utf-8")
                                                             for name in ("package.json", "package-lock.json")}
    candidates["rag (compatible upgrades)"] = {name: (work / name).read_text(encoding="utf-8") for name in ("package.json", "package-lock.json")}
    npm(["update", *indirect, *NPM_ARGS], work)
    candidates["rag + refreshed indirect packages"] = {name: (work / name).read_text(encoding="utf-8")
                                                      for name in ("package.json", "package-lock.json")}
    shutil.rmtree(work, ignore_errors=True)

    checks = json.loads(CHECKS_FILE.read_text(encoding="utf-8")) if CHECKS_FILE.exists() else {}
    app_labels = in_app(findings, json.loads(candidates["unchanged"]["package-lock.json"]))
    rows = {}
    for label, files in candidates.items():
        folder = KEEP / label.split(" (")[0].replace(" + ", "_plus_").replace(" ", "_")
        folder.mkdir(parents=True, exist_ok=True)
        for name, text in files.items():
            (folder / name).write_text(text, encoding="utf-8", newline="\n")
        key = content_key("nodegoat-deps", json.dumps(files, sort_keys=True))
        if key not in checks and not args.skip_docker:
            from app_start_check import check
            print(f"  app-start check: {label} ...", flush=True)
            checks[key] = check(args.nodegoat, "deps-" + folder.name, {} if label == "unchanged" else files)
            CHECKS_FILE.write_text(json.dumps(checks, indent=1), encoding="utf-8")
        rows[label] = {"status": status(findings, json.loads(files["package-lock.json"]), fixed_in, app_labels),
                       "check": checks.get(key)}

    out = ["# NodeGoat: which dependency findings are really fixed", "",
           f"Written by `tests/eval_nodegoat_lockfile.py` from `tests/fixtures/{args.fixture}` ({len(findings)} findings). "
           "Fixed = every installed copy of the vulnerable package in the lockfile is at or above the version OSV.dev lists as "
           "fixing it. App = the PR check's test (build, start, /login answers within 90 s).", "",
           f"{len(app_labels)} of the {len(findings)} findings are in packages the production image installs (NodeGoat's Dockerfile "
           f"runs `npm install --production`); the other {len(findings) - len(app_labels)} are in development tools only.", "",
           f"| Candidate | Fixed, of {len(app_labels)} in the app | Fixed, of {len(findings) - len(app_labels)} in dev tools | "
           "Still vulnerable | Fixed version unknown | App |", "|---|---:|---:|---:|---:|---|"]
    for label, row in rows.items():
        s, c = row["status"], row["check"]
        fixed = [x.split(" (")[0] for x in s["fixed"]]
        app = "not checked" if c is None else ("starts" if c["ready"] else f"**does not start**: {str(c.get('error'))[:160]}")
        out.append(f"| {label} | {sum(x in app_labels for x in fixed)} | {sum(x not in app_labels for x in fixed)} | "
                   f"{len(s['vulnerable'])} | {len(s['unknown'])} | {app} |")
    if args.rescan and args.pr_dir:
        after = json.loads(args.rescan.read_text(encoding="utf-8"))
        still = {finding_id(f) for f in after if f["finding_type"] == "sca"}
        snyk_gone = {f"{versions.split_package(f['location']['package'])[0]} {finding_id(f)}" for f in findings if finding_id(f) not in still}
        ours = {x.split(" (")[0] for x in rows["pipeline (PR, every scanner target)"]["status"]["fixed"]}
        out += ["", "**Check against Snyk.** The pipeline rescanned its own dependency PR with Snyk. Findings gone according to "
                f"Snyk: {len(snyk_gone)}; according to the count above: {len(ours)}; in both: {len(snyk_gone & ours)}.",
                f"Only Snyk: {', '.join(sorted(snyk_gone - ours)) or 'none'}. Only this count: {', '.join(sorted(ours - snyk_gone)) or 'none'}."]
    best = list(rows)[-1]
    out += ["", f"## In the app, still vulnerable after '{best}'", ""] + [
        f"- {line}" for line in rows[best]["status"]["vulnerable"] if line.split(":")[0] in app_labels]
    out += ["", "In the app, fixed version unknown: " + ("; ".join(x for x in rows[best]["status"]["unknown"] if x in app_labels) or "none")]
    out += ["", f"Indirect packages refreshed: {', '.join(indirect)}"]
    (OUT_DIR / "nodegoat_lockfile.md").write_text("\n".join(out) + "\n", encoding="utf-8")
    print("\n".join(out))


if __name__ == "__main__":
    main()

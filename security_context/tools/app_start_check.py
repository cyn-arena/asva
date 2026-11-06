#!/usr/bin/env python3
"""Does NodeGoat still start with a candidate fix? The check ASVA's PR check makes
(nodegoat-pr-check.yml): build and start the app with Docker Compose, then wait up to 90
seconds for /login to answer.

It works on a throwaway copy of the app, never on the checkout it is given, and removes its
containers afterwards. Needs Docker and a free port 4000.

    python tools/app_start_check.py --nodegoat ../target-apps/NodeGoat --name mongo-6.0 --mongo 6.0
    python tools/app_start_check.py --nodegoat ../target-apps/NodeGoat --name my-fix --package-json fixed/package.json
"""

import argparse
import json
import shutil
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path

WAIT_SECONDS = 90          # the PR check's limit
EXTENDED_SECONDS = 150     # waited anyway, to tell "slow" from "broken"
PROJECT = "asva-rag-trial"
COMPOSE = ["docker", "compose", "-p", PROJECT, "-f", "docker-compose.yml", "-f", "docker-compose.pr-check.yml"]
REPORTED = ("mongodb", "body-parser", "express", "marked", "underscore")
ERROR_MARKERS = ("Error", "ERROR", "error:", "Unsupported", "Cannot find", "npm ERR")


def _run(command: list[str], cwd: Path, timeout: int = 1800) -> subprocess.CompletedProcess:
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)


def _answers() -> bool:
    try:
        with urllib.request.urlopen("http://localhost:4000/login", timeout=3) as response:
            return response.status == 200
    except Exception:
        return False


def check(nodegoat: Path, name: str, files: dict[str, str] | None = None, work_dir: Path | None = None) -> dict:
    """Start a copy of the app with `files` (app-relative path -> new content) replaced.
    -> {"ready", "ready_after", "installed", "error", ...}; `ready` is the PR check's verdict."""
    work = Path(work_dir or tempfile.mkdtemp(prefix="asva-rag-trial-")) / name
    if work.exists():
        shutil.rmtree(work)
    shutil.copytree(nodegoat, work, ignore=shutil.ignore_patterns("node_modules", ".git", "*.sarif.json"))
    for relative, content in (files or {}).items():
        (work / relative).write_text(content, encoding="utf-8", newline="\n")

    result = {"name": name, "changed_files": sorted(files or {})}
    _run(COMPOSE + ["down", "-v", "--remove-orphans"], work)
    try:
        up = _run(COMPOSE + ["up", "-d", "--build"], work)
        if up.returncode != 0:
            tail = (up.stderr or up.stdout).strip().splitlines()[-12:]
            return {**result, "ready": False, "ready_after": None, "error": "the image did not build: " + " | ".join(tail)[-600:]}
        started, ready_after = time.time(), None
        while time.time() - started < EXTENDED_SECONDS:
            if _answers():
                ready_after = round(time.time() - started, 1)
                break
            time.sleep(2)
        log = _run(COMPOSE + ["logs", "--no-color", "--tail", "40", "web"], work).stdout
        errors = [line.split("|", 1)[-1].strip() for line in log.splitlines() if any(m in line for m in ERROR_MARKERS)]
        versions = _run(COMPOSE + ["exec", "-T", "web", "node", "-e",
                                   "for (const p of " + json.dumps(list(REPORTED)) + ") { try { console.log(p + '@' + "
                                   "require(p + '/package.json').version) } catch (e) { console.log(p + '@?') } }"], work)
        return {**result, "ready": ready_after is not None and ready_after <= WAIT_SECONDS, "ready_after": ready_after,
                "installed": versions.stdout.split(),
                "error": None if ready_after is not None else (errors[-1][:400] if errors else "no answer on /login")}
    finally:
        _run(COMPOSE + ["down", "-v", "--remove-orphans"], work)
        shutil.rmtree(work, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--nodegoat", required=True, type=Path, help="The NodeGoat app folder (it is copied, not changed).")
    parser.add_argument("--name", default="trial")
    parser.add_argument("--package-json", type=Path, help="A package.json to try in place of the app's.")
    parser.add_argument("--mongo", help="A mongo image tag to try in place of the one in docker-compose.yml.")
    args = parser.parse_args()

    files = {}
    if args.package_json:
        files["package.json"] = args.package_json.read_text(encoding="utf-8")
    if args.mongo:
        compose = (args.nodegoat / "docker-compose.yml").read_text(encoding="utf-8")
        files["docker-compose.yml"] = compose.replace("image: mongo:4.4", f"image: mongo:{args.mongo}")
    print(json.dumps(check(args.nodegoat, args.name, files), indent=1))


if __name__ == "__main__":
    main()

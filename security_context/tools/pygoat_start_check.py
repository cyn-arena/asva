#!/usr/bin/env python3
"""Does PyGoat still build, start and work with a candidate fix? The checks ASVA's PyGoat
pipeline makes (pygoat-baseline.yml, pygoat-pr-check.yml): build the image from
Dockerfile with Docker Compose (compose.asva.yml), wait for /login/, then run ASVA's
smoke test scripts/pygoat-smoke.py (login page, register, logout, login, a lab page, static
assets).

It works on a throwaway copy of the app, never on the folders it is given, and removes its
containers and image afterwards. Needs Docker and a free port 8001.

    python tools/pygoat_start_check.py --pygoat ../target-apps/PyGoat --smoke ../scripts/pygoat-smoke.py
    python tools/pygoat_start_check.py ... --name my-fix --requirements fixed/requirements.txt
"""

import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

WAIT_SECONDS = 120         # compose.asva.yml's health check gives up after about 90 s
PROJECT = "asva-rag-pygoat"
COMPOSE = ["docker", "compose", "-p", PROJECT, "-f", "compose.asva.yml"]
BASE_URL = "http://127.0.0.1:8001"
REPORTED = ("Django", "Pillow", "PyYAML", "urllib3", "requests", "cryptography", "Werkzeug", "PyJWT", "sqlparse",
            "django-allauth", "oauthlib", "certifi")


def _run(command: list[str], cwd: Path, timeout: int = 2400) -> subprocess.CompletedProcess:
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)


def _answers() -> bool:
    try:
        with urllib.request.urlopen(f"{BASE_URL}/login/", timeout=3) as response:
            return response.status == 200
    except Exception:
        return False


def build_failure(output: str) -> str:
    """The package pip was installing when the image build failed, and pip's reason."""
    lines = output.splitlines()
    failed_at = next((i for i, line in enumerate(lines) if "did not run successfully" in line
                      or "ResolutionImpossible" in line or "Could not find a version" in line
                      or "No matching distribution" in line or "conflicting dependencies" in line), len(lines) - 1)
    collecting = next((re.search(r"Collecting (\S+)", lines[i]).group(1) for i in range(failed_at, -1, -1)
                       if "Collecting " in lines[i]), None)
    reason = re.sub(r"^#\d+ [\d.]+\s*", "", lines[failed_at]).strip() if lines else "no output"
    conflict = [re.sub(r"^#\d+ [\d.]+\s*", "", l).strip() for l in lines if "depends on" in l or "requires" in l.lower()][-3:]
    return (f"pip failed at {collecting}: " if collecting else "") + reason[:300] + (" | " + " | ".join(conflict)[:400] if conflict else "")


def check(pygoat: Path, smoke: Path, name: str, files: dict[str, str] | None = None) -> dict:
    """Build and start a copy of PyGoat with `files` (app-relative path -> new content) replaced,
    then run the smoke test. -> {"built", "ready", "smoke", "failed_checks", "installed", "error"};
    `ready` and `smoke == "passed"` together are the pipeline's verdict."""
    work = Path(tempfile.mkdtemp(prefix="asva-rag-pygoat-")) / name
    shutil.copytree(pygoat, work, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.sarif.json", "*.sqlite3"))
    for relative, content in (files or {}).items():
        (work / relative).write_text(content, encoding="utf-8", newline="\n")
    result = {"name": name, "changed_files": sorted(files or {}), "built": False, "ready": False, "smoke": None,
              "failed_checks": [], "installed": [], "error": None}
    _run(COMPOSE + ["down", "-v", "--remove-orphans"], work)
    try:
        started = time.time()
        up = _run(COMPOSE + ["up", "-d", "--build"], work)
        result["build_seconds"] = round(time.time() - started)
        if up.returncode != 0:
            return {**result, "error": "the image did not build: " + build_failure(up.stderr + "\n" + up.stdout)}
        result["built"] = True
        started, ready_after = time.time(), None
        while time.time() - started < WAIT_SECONDS:
            if _answers():
                ready_after = round(time.time() - started, 1)
                break
            time.sleep(2)
        freeze = _run(COMPOSE + ["exec", "-T", "web", "python", "-m", "pip", "freeze"], work).stdout.split()
        wanted = {n.lower() for n in REPORTED}
        result["installed"] = [line for line in freeze if line.split("==")[0].lower() in wanted]
        if ready_after is None:
            log = _run(COMPOSE + ["logs", "--no-color", "--tail", "60", "web"], work).stdout.strip().splitlines()
            errors = [l.split("|", 1)[-1].strip() for l in log if re.search(r"Error|Exception|Traceback", l)]
            return {**result, "error": (errors[-1] if errors else "no answer on /login/")[:500]}
        result.update(ready=True, ready_after=ready_after)
        report = work.parent / f"{name}-smoke.json"
        _run([sys.executable, str(Path(smoke).resolve()), "--base-url", BASE_URL, "--output", str(report)], work, timeout=300)
        smoke_result = json.loads(report.read_text(encoding="utf-8")) if report.exists() else {}
        failed = [f"{c['name']}: {c.get('detail')}" for c in smoke_result.get("checks", []) if c.get("status") != "passed"]
        return {**result, "smoke": smoke_result.get("result", "not run"), "failed_checks": failed,
                "error": failed[0][:500] if failed else None}
    finally:
        _run(COMPOSE + ["down", "-v", "--remove-orphans", "--rmi", "local"], work)
        shutil.rmtree(work.parent, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--pygoat", required=True, type=Path, help="The PyGoat app folder (it is copied, not changed).")
    parser.add_argument("--smoke", required=True, type=Path, help="ASVA's scripts/pygoat-smoke.py.")
    parser.add_argument("--name", default="trial")
    parser.add_argument("--requirements", type=Path, help="A requirements.txt to try in place of the app's.")
    args = parser.parse_args()
    files = {"requirements.txt": args.requirements.read_text(encoding="utf-8")} if args.requirements else {}
    print(json.dumps(check(args.pygoat, args.smoke, args.name, files), indent=1))


if __name__ == "__main__":
    main()

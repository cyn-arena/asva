"""
agent/app_check.py -- does the app still build, start and work with these files changed?

The same kind of check the pipeline's PR checks make after a PR is opened, run earlier, so a broken
candidate can be caught before there is a PR. It works on a throwaway copy of the app, so the fix
branch and working tree are never touched, and it removes its containers afterwards.

Nothing here knows any particular app. Each app says how it is checked through settings, usually in
its fix workflow, and brings its own tests:

  ASVA_APP_COMPOSE_FILES      compose files in the app's folder, space-separated
  ASVA_APP_READY_URL          answers with HTTP 200 once the app is ready
  ASVA_APP_SMOKE_COMMAND      the app's smoke test
  ASVA_APP_SMOKE_RUNS         how many times to run it (default 3): an app with several workers can
                              pass by luck when requests keep reaching the same one, so raise this
                              for one whose smoke test is quick
  ASVA_APP_SECURITY_COMMAND   optional: runs the security tests aimed at this batch (see below)

Commands run from the repo root with BASE_URL set. A command fails with a non-zero exit, and its
lines starting FAILED or ERROR say why (otherwise the end of its output). Placeholders: {url} the
app's address, {app} the throwaway copy, {temp} a temporary folder, {tests} the security tests to
run, joined with " or ". "python" means the Python running this agent.

Security tests also get TARGET=candidate, and ASVA_APP_PATH and ASVA_CANDIDATE_SHA pointing at the
copy, which gets a throwaway git repo of its own so a test can insist on an exact commit.

A check only speaks for what it covers: build, start and the app's own tests, not every feature.
"""

from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from gitops import config

ROOT = Path(__file__).resolve().parent.parent
PROJECT = "asva-test-first"
BUILD_TIMEOUT = 1200
COMMAND_TIMEOUT = 600
WAIT_SECONDS = 90
DETAIL_CHARS = 1500
WIDE = "400"  # tests that cut their failure summary to the terminal width should not, for an LLM retry

_COPY_IGNORE = shutil.ignore_patterns(".git", "node_modules", "__pycache__", "*.sarif.json", "*.sqlite3")


@dataclass(frozen=True)
class Result:
    passed: bool
    stage: str   # build | start | smoke | passed | unavailable (the check itself could not run)
    detail: str = ""
    log: str = ""  # more of what went wrong (the end of the app's log), for an LLM retry


def _setting(name: str) -> str:
    return os.environ.get(name, "").strip()


def supported() -> bool:
    """This app has said how it is checked."""
    return all(_setting(name) for name in ("ASVA_APP_COMPOSE_FILES", "ASVA_APP_READY_URL", "ASVA_APP_SMOKE_COMMAND"))


def has_security_command() -> bool:
    return bool(_setting("ASVA_APP_SECURITY_COMMAND"))


def _run(command: list[str], cwd: Path, timeout: int = BUILD_TIMEOUT, env: dict | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(command, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=timeout, env=env)


def _answers(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            return response.status == 200
    except Exception:  # noqa: BLE001 -- not up yet, whatever the reason
        return False


def build_failure(output: str) -> str:
    """Why the image build failed. When it was pip, the package it was installing too, unless the
    reason already names the one it could not find."""
    lines = output.splitlines()
    failed_at = next((i for i, line in enumerate(lines) if "did not run successfully" in line
                      or "ResolutionImpossible" in line or "Could not find a version" in line
                      or "No matching distribution" in line or "conflicting dependencies" in line), None)
    if failed_at is None:
        failed_at = next((i for i, line in enumerate(lines) if re.search(r"\berror\b|failed to", line, re.I)), len(lines) - 1)
    reason = re.sub(r"^#\d+ [\d.]+\s*", "", lines[failed_at]).strip() if lines else "no output"
    if "Could not find a version" in reason or "No matching distribution" in reason:
        return reason[:DETAIL_CHARS]
    collecting = next((m.group(1) for i in range(failed_at, -1, -1) if (m := re.search(r"Collecting (\S+)", lines[i]))), None)
    return ((f"pip failed at {collecting}: " if collecting else "") + reason)[:DETAIL_CHARS]


def _start_failure(compose: list[str], work: Path, fallback: str) -> Result:
    log = _run([*compose, "logs", "--no-color", "--tail", "40"], work, timeout=60).stdout.splitlines()
    errors = [line.split("|", 1)[-1].strip() for line in log if re.search(r"Error|Exception|Traceback", line)]
    tail = "\n".join(line.split("|", 1)[-1].rstrip() for line in log[-25:])
    return Result(False, "start", (errors[-1] if errors else fallback)[:DETAIL_CHARS], tail)


def _command(template: str, values: dict[str, str]) -> list[str]:
    """A command from a setting, with its placeholders filled in."""
    parts = shlex.split(template)
    for placeholder, value in values.items():
        parts = [part.replace("{" + placeholder + "}", value) for part in parts]
    if parts and parts[0] in ("python", "python3"):
        parts[0] = sys.executable
    return parts


def _failures(done: subprocess.CompletedProcess) -> str:
    """Why a test command failed, or "" when it passed."""
    if done.returncode == 0:
        return ""
    lines = f"{done.stdout}\n{done.stderr}".splitlines()
    failed = [line.strip() for line in lines if line.startswith(("FAILED", "ERROR"))]
    return " | ".join(failed or [line for line in lines if line.strip()][-5:] or [f"exit code {done.returncode}"])[:DETAIL_CHARS]


def _smoke(values: dict[str, str], env: dict[str, str]) -> str:
    runs = int(_setting("ASVA_APP_SMOKE_RUNS") or 3)
    for _ in range(max(runs, 1)):
        failed = _failures(_run(_command(_setting("ASVA_APP_SMOKE_COMMAND"), values), ROOT, COMMAND_TIMEOUT, env))
        if failed:
            return failed
    return ""


def _security(tests: list[str], values: dict[str, str], env: dict[str, str], work: Path) -> str:
    git = ["git", "-c", "user.name=asva", "-c", "user.email=asva@localhost"]
    _run([*git, "init", "-q"], work, timeout=60)
    _run([*git, "add", "-A"], work, timeout=120)
    _run([*git, "commit", "-q", "-m", "candidate"], work, timeout=60)
    sha = _run(["git", "rev-parse", "HEAD"], work, timeout=60).stdout.strip()
    command = _command(_setting("ASVA_APP_SECURITY_COMMAND"), {**values, "tests": " or ".join(tests)})
    return _failures(_run(command, ROOT, COMMAND_TIMEOUT, {**env, "TARGET": "candidate", "ASVA_APP_PATH": str(work),
                                                           "ASVA_CANDIDATE_SHA": sha}))


def check(files: dict[str, str], repo_dir: str = ".", security_tests: list[str] | None = None) -> Result:
    """Build and start a copy of the app with `files` (app-relative path -> content) replaced, then
    run its smoke test and any `security_tests`. "unavailable" means the check could not run, which
    says nothing about the files."""
    if not supported():
        return Result(False, "unavailable", f"no app check settings for {config.FIX_PATH_PREFIX or 'this app'}")
    compose = ["docker", "compose", "-p", PROJECT]
    for name in _setting("ASVA_APP_COMPOSE_FILES").split():
        compose += ["-f", name]
    ready_url = _setting("ASVA_APP_READY_URL")
    parts = urllib.parse.urlsplit(ready_url)
    base_url = f"{parts.scheme}://{parts.netloc}"
    temp = Path(tempfile.mkdtemp(prefix="asva-app-check-"))
    work = temp / "app"
    try:
        shutil.copytree(Path(repo_dir) / config.FIX_PATH_PREFIX, work, ignore=_COPY_IGNORE)
        for relative, content in files.items():
            (work / relative).write_text(content, encoding="utf-8", newline="\n")
        _run([*compose, "down", "-v", "--remove-orphans"], work, timeout=120)
        built = _run([*compose, "build"], work)
        if built.returncode != 0:
            return Result(False, "build", build_failure(f"{built.stderr}\n{built.stdout}"))
        up = _run([*compose, "up", "-d"], work)
        if up.returncode != 0:  # compose gives up here when a container it waits for is unhealthy
            return _start_failure(compose, work, (up.stderr.strip().splitlines() or ["compose up failed"])[-1])
        started = time.monotonic()
        while not _answers(ready_url):
            if time.monotonic() - started > WAIT_SECONDS:
                return _start_failure(compose, work, f"no answer on {ready_url}")
            time.sleep(2)
        values = {"url": base_url, "app": str(work), "temp": str(temp)}
        env = {**os.environ, "BASE_URL": base_url, "COLUMNS": WIDE}
        failed = _smoke(values, env)
        if security_tests and has_security_command():
            failed = " | ".join(f for f in (failed, _security(security_tests, values, env, work)) if f)
        if not failed:
            return Result(True, "passed")
        log = _run([*compose, "logs", "--no-color", "--tail", "25"], work, timeout=60).stdout.splitlines()
        return Result(False, "smoke", failed, "\n".join(line.split("|", 1)[-1].rstrip() for line in log))
    except (OSError, subprocess.SubprocessError, shutil.Error, ValueError) as e:
        return Result(False, "unavailable", str(e)[:DETAIL_CHARS])
    finally:
        try:
            _run([*compose, "down", "-v", "--remove-orphans"], work, timeout=120)
        except (OSError, subprocess.SubprocessError):
            pass
        shutil.rmtree(temp, ignore_errors=True)

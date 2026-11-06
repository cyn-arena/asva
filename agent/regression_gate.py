"""
agent/regression_gate.py -- ASVA pre-commit validity gate.

Wired in as gitops.git_gh_ops.submit_fix_batch's `test_fn`: runs after a candidate fix is
written to the working tree, before it is committed. This is a FAST, SYNTAX-ONLY check --
it answers "does this file still parse/build?", not "is this fix correct" or "does the app
still work" (that heavier question belongs to the separate smoke-test suite run against a
live NodeGoat instance).

Filename/extension -> validator:
    *.js                              node --check <file>
    *.py                              python -m py_compile <file>
    docker-compose.yml / .yaml        docker compose -f <file> config
    compose.yml / .yaml               (same)

Any other file (a Dockerfile, a Kubernetes manifest, ...) has no validator and passes
through unchecked -- nothing to validate is not a failure. A required toolchain that is
missing (e.g. no `node` on PATH) fails CLOSED by
default, the same philosophy as the gitleaks secrets gate (secrets_scan/gitleaks_gate.py): a
fix that cannot be verified is treated as not safe to commit, not silently let through. Set
REGRESSION_GATE_FAIL_OPEN=1 to make a missing toolchain pass instead, for a runner that
deliberately never touches that file type.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Callable, Optional

from gitops.git_gh_ops import repo_path

FAIL_OPEN = os.environ.get("REGRESSION_GATE_FAIL_OPEN", "").strip().lower() in ("1", "true", "yes")

_COMPOSE_FILENAMES = {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}


def _check_node(path: Path) -> bool:
    proc = subprocess.run(["node", "--check", str(path)], capture_output=True, text=True)
    return proc.returncode == 0


def _check_python(path: Path) -> bool:
    proc = subprocess.run(["python", "-m", "py_compile", str(path)], capture_output=True, text=True)
    return proc.returncode == 0


def _check_docker_compose(path: Path) -> bool:
    proc = subprocess.run(["docker", "compose", "-f", str(path), "config"],
                           capture_output=True, text=True)
    return proc.returncode == 0


_VALIDATORS_BY_SUFFIX: dict[str, Callable[[Path], bool]] = {
    ".js": _check_node,
    ".py": _check_python,
}


def _validator_for(full_path: Path) -> Optional[Callable[[Path], bool]]:
    if full_path.name in _COMPOSE_FILENAMES:
        return _check_docker_compose
    return _VALIDATORS_BY_SUFFIX.get(full_path.suffix)


def check(path: str, repo_dir: str = ".") -> bool:
    """True if `path` (app-relative, e.g. "app/routes/x.js") still parses/builds; False if
    it doesn't, or if the validator's toolchain is unavailable and fail-open isn't set. A
    file type with no validator always passes -- there's nothing to check.

    Maps `path` through `repo_path()` (ASVA_FIX_PATH_PREFIX) before joining with
    `repo_dir`, same as every other disk-path resolution in the pipeline (write_file,
    revert_uncommitted, process_batch) -- without this, the gate checks a path that
    doesn't exist whenever FIX_PATH_PREFIX is set (e.g. this project's own
    target-apps/NodeGoat), and fails closed on every real fix."""
    full_path = Path(repo_dir) / repo_path(path)
    validator = _validator_for(full_path)
    if validator is None:
        return True

    try:
        return validator(full_path)
    except FileNotFoundError as e:
        print(
            f"[regression_gate] toolchain for {full_path.name!r} not available ({e}); "
            f"{'passing through (fail-open)' if FAIL_OPEN else 'failing closed'}",
            file=sys.stderr,
        )
        return FAIL_OPEN

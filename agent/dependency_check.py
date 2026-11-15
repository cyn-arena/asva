"""
agent/dependency_check.py -- does a fix import a package the app does not have?

A fix that adds `require("express-rate-limit")` to an app that never installed it still parses,
so the validity gate passes it, and the app then fails to start ("Cannot find module"). The
test-first app check (agent/test_first.py) catches that, but it finds one file per Docker build
and has two retries, so a fix that adds the package to three or more files still fails.

This check is static and fast. After the fixes are generated, it compares the packages each
fixed file newly imports with what the app has installed, and sends every offending file back to
the LLM at once, with the reason and the list of installed packages. It runs before test-first,
also in dry runs, and the evaluation scorer (scripts/compare_dry_runs.py) uses it too.

What counts as installed, looked up from the fixed file's folder upwards inside the app:
  JavaScript  the nearest package.json (all dependency sections) and, when its folder has a
              package-lock.json, every package npm installs at the top of node_modules (indirect
              dependencies included); Node's built-in modules.
  Python      the distributions in the requirements*.txt files of the nearest folder that has
              one, by their import names, with the packages common frameworks always bring
              (Flask brings werkzeug and itsdangerous); the standard library.
  Both        a package another file under the same manifest already imports: it must be there.
Only imports the fix adds are checked; local modules (inside the app) never count. A file with
no manifest above it is not checked. Off with ASVA_DEPENDENCY_CHECK=0.
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import sys
from pathlib import Path
from typing import Callable

from agent import repo_context

NODE_BUILTINS = frozenset("""
assert async_hooks buffer child_process cluster console constants crypto dgram diagnostics_channel
dns domain events fs http http2 https inspector module net os path perf_hooks process punycode
querystring readline repl stream string_decoder sys timers tls trace_events tty url util v8 vm
wasi worker_threads zlib test
""".split())

_PY_STDLIB = frozenset(getattr(sys, "stdlib_module_names", ())) | {"__future__"}
_PY_REQ_FILE = re.compile(r"^requirements[\w.-]*\.txt$", re.IGNORECASE)
_PY_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
MAX_LISTED = 60   # installed packages named in the retry prompt

# Import names that pip always installs with a framework (its own dependencies), so a fix may use
# them although requirements.txt names only the framework. Keyed by the framework's import name.
PY_INSTALLED_WITH = {
    "flask": ("werkzeug", "itsdangerous", "jinja2", "click", "markupsafe", "blinker"),
    "django": ("asgiref", "sqlparse"),
    "requests": ("urllib3", "idna", "certifi", "charset_normalizer"),
    "fastapi": ("starlette", "pydantic"),
    "jinja2": ("markupsafe",),
}


def enabled() -> bool:
    return os.environ.get("ASVA_DEPENDENCY_CHECK", "1").strip() != "0"


# ---------------------------------------------------------------------------------------
# What the app has installed
# ---------------------------------------------------------------------------------------

def _manifest_dir(path: str, app_root: Path, language: str) -> str | None:
    """App-relative folder of the manifest that governs `path` ("" = app root), or None."""
    folder = posixpath.dirname(path)
    while True:
        base = app_root / folder if folder else app_root
        if language == "javascript" and (base / "package.json").is_file():
            return folder
        if language == "python" and base.is_dir() and any(_PY_REQ_FILE.match(p.name) for p in base.iterdir()):
            return folder
        if not folder:
            return None
        folder = posixpath.dirname(folder)


def _js_installed(base: Path) -> tuple[set[str], str]:
    names: set[str] = set()
    try:
        manifest = json.loads((base / "package.json").read_text(encoding="utf-8"))
        for section in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
            names.update((manifest.get(section) or {}).keys())
    except (OSError, ValueError):
        pass
    lock = base / "package-lock.json"
    try:
        data = json.loads(lock.read_text(encoding="utf-8"))
        for key in (data.get("packages") or {}):
            if key.startswith("node_modules/") and "/node_modules/" not in key[len("node_modules/"):]:
                names.add(key[len("node_modules/"):])
        names.update((data.get("dependencies") or {}).keys())   # lockfile v1
    except (OSError, ValueError):
        pass
    return names, "package.json"


def _py_installed(base: Path) -> tuple[set[str], str]:
    names: set[str] = set()
    files = sorted(p for p in base.iterdir() if _PY_REQ_FILE.match(p.name))
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line or line.startswith(("-", "git+", "http")):
                continue
            m = _PY_REQ_LINE.match(line)
            if m:
                names.update(repo_context.python_import_names(m.group(1)))
    for name in list(names):
        names.update(PY_INSTALLED_WITH.get(name, ()))
    return names, (files[0].name if files else "requirements.txt")


def _is_builtin(package: str, language: str) -> bool:
    if language == "javascript":
        return package.startswith("node:") or package.split("/")[0] in NODE_BUILTINS
    return package in _PY_STDLIB


# ---------------------------------------------------------------------------------------
# What a fix imports
# ---------------------------------------------------------------------------------------

def _packages(path: str, text: str, index: repo_context.ImportIndex) -> set[str]:
    """Third-party package names `text` (the file at `path`) imports; local modules left out."""
    resolver = repo_context.resolver_for(path)
    if resolver is None:
        return set()
    text = text.replace("\r\n", "\n")
    try:
        refs = resolver.scan(resolver.strip_comments(text), text.split("\n"))
    except Exception:  # noqa: BLE001 -- an odd file is not checked rather than failing the run
        return set()
    known = set(index.files)
    resolver.prepare(known)
    out = set()
    for ref in refs:
        if ref.is_local:
            continue
        target = resolver.resolve(path, ref.spec, known)
        if target is None and ref.alt_spec:
            target = resolver.resolve(path, ref.alt_spec, known)
        if target:
            continue
        name = resolver.package_name(ref.spec)
        if name:
            out.add(name)
    return out


def _used_elsewhere(index: repo_context.ImportIndex, package: str, path: str, scope: str) -> bool:
    prefix = f"{scope}/" if scope else ""
    return any(f != path and f.startswith(prefix) for f, _ in index.package_usage.get(package, []))


def undeclared_imports(
    files: dict[str, str],
    app_root: str | Path,
    index: repo_context.ImportIndex | None = None,
) -> dict[str, dict]:
    """{path: {"packages": [...], "manifest": "package.json", "installed": [...]}} for each
    fixed file (app-relative path -> new content) that newly imports a package the app does
    not have. Files the check cannot judge are left out."""
    app_root = Path(app_root)
    if index is None:
        index = repo_context.build_import_index(app_root)
    found: dict[str, dict] = {}
    for path, content in files.items():
        path = posixpath.normpath(path.replace("\\", "/"))
        resolver = repo_context.resolver_for(path)
        if resolver is None:
            continue
        language = resolver.language
        scope = _manifest_dir(path, app_root, language)
        if scope is None:
            continue
        original_file = app_root / path
        original = original_file.read_text(encoding="utf-8", errors="replace") if original_file.is_file() else ""
        added = _packages(path, content, index) - _packages(path, original, index)
        if not added:
            continue
        base = app_root / scope if scope else app_root
        installed, manifest = (_js_installed if language == "javascript" else _py_installed)(base)
        missing = sorted(p for p in added if not _is_builtin(p, language) and p not in installed
                         and not _used_elsewhere(index, p, path, scope))
        if missing:
            found[path] = {"packages": missing,
                           "manifest": posixpath.join(scope, manifest) if scope else manifest,
                           "installed": sorted(installed), "language": language}
    return found


def reason(path: str, problem: dict) -> str:
    """The explanation the LLM gets with its retry."""
    pkgs = ", ".join(f"`{p}`" for p in problem["packages"])
    runtime = "Node.js" if problem["language"] == "javascript" else "Python"
    installed = problem["installed"]
    listed = ", ".join(installed[:MAX_LISTED]) + (f", and {len(installed) - MAX_LISTED} more" if len(installed) > MAX_LISTED else "")
    return (f"{path} imports {pkgs}, which the app does not have installed (not in "
            f"{problem['manifest']}), so the app would fail to start. Do not add dependencies: fix "
            f"the vulnerability using only {runtime}'s built-in modules and the packages the app "
            f"already has." + (f" Installed: {listed}." if listed else ""))


# ---------------------------------------------------------------------------------------
# In the fix run: send offending files back before the app is built
# ---------------------------------------------------------------------------------------

def repair(
    entry: dict,
    repo_dir: str,
    make_refix: Callable[[dict], Callable | None] | None,
    *,
    rounds: int = 2,
) -> dict:
    """Check a generated batch (`entry` from agent_loop.process_batch) and ask the LLM to redo
    every file that imports a package the app lacks, all of them in the same round. What is
    still missing after `rounds` goes to the PR as a "Check before merging" note."""
    if not enabled() or not entry.get("files"):
        return entry
    from gitops import config
    app_root = repo_context.app_root_for(repo_dir, config.FIX_PATH_PREFIX)
    try:
        index = repo_context.build_import_index(app_root)
        files = {f["path"]: f["content"] for f in entry["files"]}
        missing = undeclared_imports(files, app_root, index)
    except Exception as e:  # noqa: BLE001 -- the check must never cost the fix
        print(f"    [deps] [WARN] dependency check skipped ({e})")
        return entry
    if not missing:
        return entry
    for path, problem in missing.items():
        print(f"    [deps] {path} imports {', '.join(problem['packages'])}, not installed "
              f"({problem['manifest']})")
    batch = entry.get("batch") or {}
    findings = {fe["file"]: fe.get("findings", []) for fe in batch.get("files_to_fix", [])}
    refix = make_refix(entry) if make_refix else None
    for round_number in range(1, rounds + 1):
        if refix is None:
            break
        changed = False
        for path, problem in list(missing.items()):
            content = refix(path, findings.get(path, []), round_number,
                            reason=reason(path, problem), source="dependencies")
            if content:
                for f in entry["files"]:
                    if f["path"] == path:
                        f["content"] = content
                changed = True
        if not changed:
            break
        files = {f["path"]: f["content"] for f in entry["files"]}
        missing = undeclared_imports({p: files[p] for p in missing if p in files}, app_root, index)
        print(f"    [deps] after retry {round_number}: "
              + ("all fixed" if not missing else f"{len(missing)} file(s) still import missing packages"))
        if not missing:
            break
    entry.setdefault("dependency_check", {})["unresolved"] = {p: v["packages"] for p, v in missing.items()}
    for path, problem in missing.items():
        pkgs = ", ".join(f"`{p}`" for p in problem["packages"])
        batch.setdefault("review_notes", {}).setdefault(path, []).append(
            f"Imports {pkgs}, which the app does not install ({problem['manifest']}). The app will "
            f"not start until it is added there or the fix is rewritten without it.")
    return entry

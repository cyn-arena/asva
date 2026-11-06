"""Scanner-directed upgrades for an npm app, with npm generating the lockfile.

On for an app that sets ASVA_SCA_FIX_MODE=npm. ASVA_NPM_VERSION pins the npm it must run with;
the lockfile stays at the version the app already uses.
"""

import copy
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time

from gitops import config
from gitops.dependency_validation import validate_pair

_PACKAGE = re.compile(r"(?:@[a-z0-9._-]+/)?[a-z0-9][a-z0-9._-]*")
_VERSION = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)")
_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")


def enabled(batch: dict) -> bool:
    return batch.get("batch_type") == "sca" and os.environ.get("ASVA_SCA_FIX_MODE", "llm") == "npm"


def upgrade_plan(batch: dict, manifest: dict, lock: dict) -> tuple[dict, list[dict]]:
    """Accept only exact stable versions of existing direct dependencies.

    A scanner may recommend upgrading a direct parent of a vulnerable transitive
    dependency. Use the package named by upgrade_to, rather than the vulnerable leaf.
    """
    upgrades, unresolved = {}, []
    for entry in batch.get("files_to_fix", []):
        if entry.get("file") not in ("package.json", "package-lock.json"):
            raise ValueError("npm trial supports only root dependency manifests")
        for finding in entry.get("findings", []):
            spec = (finding.get("remediation") or {}).get("upgrade_to")
            name, separator, version = str(spec or "").rpartition("@")
            section = next((s for s in _SECTIONS if name in manifest.get(s, {})), None)
            if (not separator or not _PACKAGE.fullmatch(name)
                    or not _VERSION.fullmatch(version) or not section):
                unresolved.append({"finding_id": finding.get("finding_id"),
                                   "reason": "No supported exact direct-dependency upgrade",
                                   "upgrade_to": spec})
                continue
            current = lock.get("packages", {}).get("node_modules/" + name, {}).get("version", "")
            declared = str(manifest[section][name])
            # Never downgrade a resolved or explicitly declared newer release.
            target = tuple(map(int, version.split(".")))
            if any(_VERSION.fullmatch(v) and tuple(map(int, v.split("."))) >= target
                   for v in (current, declared)):
                continue
            previous = upgrades.get(name)
            if previous is None or target > tuple(map(int, previous["to"].split("."))):
                upgrades[name] = {"section": section, "from": declared, "to": version}
    return upgrades, unresolved


def _run_npm(executable: str, args: list[str], work: Path, env: dict[str, str]) -> str:
    proc = subprocess.run([executable, *args], cwd=work, env=env, capture_output=True,
                          text=True, timeout=300)
    if proc.returncode:
        detail = " ".join((proc.stderr or proc.stdout).split())[-2000:]
        raise ValueError(f"npm exited {proc.returncode}: {detail}")
    return proc.stdout.strip()


def generate(batch: dict, repo_dir: str, update: list[str] | None = None) -> dict:
    """Produce a coordinated candidate in scratch space; never edit scanned source.

    `update` (a trial from agent/test_first.py): packages to refresh with `npm update` within the
    ranges the packages above them allow, for what only comes in through other packages."""
    pinned = os.environ.get("ASVA_NPM_VERSION", "").strip()
    report = {"method": "npm", "npm_version": pinned or None, "upgrades": {}, "unresolved": []}
    copied_batch = copy.deepcopy(batch)
    copied_batch["remediation_method"] = "npm"
    result = {"batch": copied_batch, "files": [], "generation": report}
    started = time.perf_counter()
    print(f"    [npm] Batch {batch.get('batch_id')}")
    try:
        root = Path(repo_dir).resolve()
        app = (root / config.FIX_PATH_PREFIX).resolve()
        if not app.is_relative_to(root):
            raise ValueError("Application path escapes scanned source")
        manifest = json.loads((app / "package.json").read_text(encoding="utf-8"))
        lock_text = (app / "package-lock.json").read_text(encoding="utf-8")
        lock = json.loads(lock_text)
        validate_pair(manifest, lock)
        upgrades, unresolved = upgrade_plan(batch, manifest, lock)
        report.update(upgrades=upgrades, unresolved=unresolved)
        copied_batch["npm_upgrades"] = upgrades
        copied_batch["npm_unresolved_count"] = len(unresolved)
        print(f"    [npm] Planned upgrades: {len(upgrades)}; unsupported recommendations: {len(unresolved)}")
        if not upgrades and not update:
            report.update(status="no_candidate", message="No supported dependency upgrades to apply")
            return result
        for name, upgrade in upgrades.items():
            manifest[upgrade["section"]][name] = upgrade["to"]
        manifest_text = json.dumps(manifest, indent=2) + "\n"
        npm = shutil.which("npm")
        if not npm:
            raise ValueError("Pinned npm toolchain is unavailable")
        with tempfile.TemporaryDirectory(prefix="asva-npm-") as scratch:
            work = Path(scratch)
            # No GitHub/AI credentials or user npm configuration enter this subprocess.
            env = {k: os.environ[k] for k in ("PATH", "SystemRoot", "SYSTEMROOT", "COMSPEC")
                   if k in os.environ}
            env.update(HOME=scratch, USERPROFILE=scratch, TEMP=scratch, TMP=scratch,
                       npm_config_cache=str(work / "cache"))
            installed = _run_npm(npm, ["--version"], work, env)
            if pinned and installed != pinned:
                raise ValueError(f"npm {pinned} is required for this app, found {installed}")
            report["npm_version"] = installed
            lockfile_version = f"--lockfile-version={lock['lockfileVersion']}"
            (work / "package.json").write_text(manifest_text, encoding="utf-8")
            (work / "package-lock.json").write_text(lock_text, encoding="utf-8")
            for name in ("user.npmrc", "global.npmrc"):
                (work / name).write_text("", encoding="utf-8")
            _run_npm(npm, ["install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
                 lockfile_version, "--registry=https://registry.npmjs.org/",
                 "--userconfig=" + str(work / "user.npmrc"),
                 "--globalconfig=" + str(work / "global.npmrc")], work, env)
            if update:
                _run_npm(npm, ["update", *update, "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund",
                     lockfile_version, "--registry=https://registry.npmjs.org/",
                     "--userconfig=" + str(work / "user.npmrc"),
                     "--globalconfig=" + str(work / "global.npmrc")], work, env)
            if json.loads((work / "package.json").read_text(encoding="utf-8")) != manifest:
                raise ValueError("npm unexpectedly modified the requested manifest")
            generated = (work / "package-lock.json").read_text(encoding="utf-8")
            new_lock = json.loads(generated)
            validate_pair(manifest, new_lock)
            for name, upgrade in upgrades.items():
                if new_lock["packages"].get("node_modules/" + name, {}).get("version") != upgrade["to"]:
                    raise ValueError(f"npm did not resolve the requested version of {name}")
            result["files"] = [{"path": "package.json", "content": manifest_text},
                               {"path": "package-lock.json", "content": generated}]
        report.update(status="generated", message="Dependency pair generated; candidate checks still required")
    except (OSError, ValueError, TypeError, KeyError, AttributeError, subprocess.SubprocessError) as exc:
        result["files"] = []
        report.update(status="error", message=str(exc)[:2500])
    finally:
        report["duration_seconds"] = round(time.perf_counter() - started, 2)
        print(f"    [npm] {report['status']} in {report['duration_seconds']}s: {report['message']}")
    return result

"""
agent/base_image.py -- try a newer OS under an image the app builds itself (ITP2 3.3).

A container finding can have no fix on the image's OS release while a newer release has one. Triage
drops those, as the scanner marks them not fixable, so they never reach the fix stage. When
ASVA_BASE_IMAGE_FIX=1, the RAG's OS data (security_context/app/sources/osv.py) says which newer
releases fix the critical and high ones, and this adds a container batch that changes the OS release
named in the container file's FROM line. No LLM: the edit is mechanical.

agent/test_first.py then builds, starts and tests it, and the scanner compares the new image with
today's: a newer OS brings vulnerabilities of its own. It only becomes a PR if critical does not go up
and the total goes down. A rise in high is shown to the reviewer rather than stopping it, as the
scanner can rate the same vulnerability differently on another OS. If the scan can't run, the PR says
so. It needs test-first and the app's check settings. A whole OS is a big change
for a test to speak for, so the PR says so. An image the app doesn't build, or a FROM line that names
no OS release (`python:3.11-slim`), is left alone.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from agent import app_check, rag_client
from gitops import config
from gitops.post_pr_summary import distinct, severity_counts

METHOD = "base_image"
PR_LABEL = "OS upgrade"
MAX_LOOKUPS = 30  # the RAG checks at most this many CVEs against the OS's fix data per request
MAX_OPTIONS = 1   # only the next release with fixes: further on, OS data lists releases that aren't out yet
_FROM = re.compile(r"^(\s*FROM\s+(?:--\S+\s+)*)(\S+)", re.I | re.M)


def enabled() -> bool:
    return os.environ.get("ASVA_BASE_IMAGE_FIX", "").strip() == "1"


def _package(finding: dict) -> str:
    return ((finding.get("location") or {}).get("package") or "").rsplit("@", 1)[0].split("/")[0]


def _cve(finding: dict) -> str:
    return (finding.get("identifiers") or {}).get("cve") or ""


def _release_key(release: str) -> tuple[int, ...]:
    return tuple(int(part) for part in release.split("."))


def with_release(text: str, current: str, newer: str) -> str | None:
    """The container file with one OS release name swapped in its FROM lines, or None if they don't name it."""
    pattern = re.compile(rf"(?<![A-Za-z0-9.]){re.escape(current)}(?![A-Za-z0-9.])")
    changed = _FROM.sub(lambda m: m.group(1) + pattern.sub(newer, m.group(2)), text)
    return changed if changed != text else None


def options(findings: list[dict], answer: dict | None, text: str) -> list[dict]:
    """The next OS releases that fix these findings, the smallest step first, up to MAX_OPTIONS: each with
    the container file as it would be and the findings it fixes. [] when the sources don't say, or the file can't name it."""
    found: dict[str, dict] = {}
    for reference in (answer or {}).get("references") or []:
        if reference.get("type") != "os_release_fix" or not reference.get("release_name"):
            continue
        for finding in findings:
            if not _cve(finding) or not reference["id"].endswith(_cve(finding)) or reference.get("package") != _package(finding):
                continue
            for release in reference.get("newer_release_fixes") or {}:
                name = (reference.get("newer_release_names") or {}).get(release)
                changed = name and with_release(text, reference["release_name"], name)
                if changed:
                    found.setdefault(release, {"release": release, "name": name, "text": changed, "fixes": []})["fixes"].append(finding)
    return [found[release] for release in sorted(found, key=_release_key)][:MAX_OPTIONS]


def _key(finding: dict) -> tuple[str, str]:
    return _cve(finding), _package(finding)


def _no_fix_here(all_findings: list[dict]) -> list[dict]:
    """Critical and high OS package findings with no fix on this release, once per vulnerability."""
    seen, wanted = set(), []
    for finding in all_findings:
        if (finding.get("finding_type") == "container" and (finding.get("location") or {}).get("kind") == "os_package"
                and finding.get("severity") in ("critical", "high")
                and not (finding.get("remediation") or {}).get("fixable") and _key(finding) not in seen):
            seen.add(_key(finding))
            wanted.append(finding)
    return wanted


def prepare(batch_dir: Path, repo_dir: str, findings_path: str | None, container_file: str | None) -> Path | None:
    """Write the batch if a newer OS release could help. Only a help, so a problem here warns and the run goes on."""
    if not (enabled() and findings_path and container_file and app_check.supported() and rag_client.enabled()):
        return None
    try:
        batches = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(batch_dir.glob("*.json"))]
        if not batches or any(b.get("batch_type") == "container" for b in batches):
            return None
        source = Path(repo_dir) / config.FIX_PATH_PREFIX / container_file
        if not source.is_file():
            return None
        data = json.loads(Path(findings_path).read_text(encoding="utf-8"))
        data = data if isinstance(data, list) else data.get("findings") or []
        wanted = _no_fix_here(data)[:MAX_LOOKUPS]
        answer = rag_client.response(wanted, "version_upgrade")
        found = options(wanted, answer, source.read_text(encoding="utf-8"))
        if not found:
            print(f"  base image  : no newer OS release to try for {container_file}")
            return None
        repo, sha = batches[0].get("repo_name", "repo"), batches[0].get("commit_sha", "")
        first = found[0]["fixes"]
        batch = {"batch_id": f"{repo}_container_{sha}", "batch_type": "container", "repo_name": repo, "commit_sha": sha,
                 "scan_run_id": batches[0].get("scan_run_id"), "generated_at": batches[0].get("generated_at"),
                 "remediation_method": METHOD, "pr_choice": PR_LABEL, "os_findings_today": severity_counts(distinct(data, "container")), "total_files": 1, "total_findings": len(first), "base_image_options": found,
                 "files_to_fix": [{"file": container_file, "fix_type": "version_upgrade", "finding_type": "container",
                                   "findings": first, "finding_count": len(first)}]}
        path = batch_dir / f"{batch['batch_id']}.json"
        path.write_text(json.dumps(batch, indent=2), encoding="utf-8")
        print(f"  base image  : will try {', '.join(o['name'] for o in found)} for {container_file}")
        return path
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"  [WARN] base image: not tried ({e})")
        return None


def scan_candidate(text: str, container_file: str, repo_dir: str) -> dict[str, int] | None:
    """The scanner's counts for OS packages in the image built from `text`, the way the pipeline
    scans an app's image. None if the build or scanner could not run, which says nothing about the image."""
    from normaliser.normaliser import process_sarif_file

    image = "asva-base-image-check:candidate"
    temp = Path(tempfile.mkdtemp(prefix="asva-base-image-"))
    try:
        work = temp / "app"
        shutil.copytree(Path(repo_dir) / config.FIX_PATH_PREFIX, work, ignore=app_check._COPY_IGNORE)
        (work / container_file).write_text(text, encoding="utf-8", newline="\n")
        built = subprocess.run(["docker", "build", "-f", container_file, "-t", image, "."], cwd=work, capture_output=True, timeout=app_check.BUILD_TIMEOUT)
        if built.returncode:
            print(f"    [base image] could not build the image to scan it: exit code {built.returncode}")
            return None
        sarif = temp / "container.sarif.json"
        scanned = subprocess.run(["snyk", "container", "test", image, f"--file={container_file}", f"--sarif-file-output={sarif}"],
                                 cwd=work, capture_output=True, timeout=app_check.BUILD_TIMEOUT)
        if scanned.returncode not in (0, 1) or not sarif.exists():
            print(f"    [base image] the scanner could not run: exit code {scanned.returncode}")
            return None
        return severity_counts(distinct(process_sarif_file(sarif, strict=True), "container"))
    except (OSError, ValueError, TypeError, subprocess.SubprocessError) as e:
        print(f"    [base image] the scan could not run: {e}")
        return None
    finally:
        subprocess.run(["docker", "rmi", "-f", image], capture_output=True, check=False)
        shutil.rmtree(temp, ignore_errors=True)


def worth_opening(today: dict[str, int], after: dict[str, int]) -> bool:
    return after["critical"] <= today["critical"] and after["total"] < today["total"]


def generate(batch: dict) -> dict:
    option = batch["base_image_options"][0]
    path = batch["files_to_fix"][0]["file"]
    print(f"    [base image] {path}: {option['name']} first")
    return {"batch": batch, "files": [{"path": path, "content": option["text"]}],
            "generation": {"method": METHOD, "status": "generated", "message": f"{len(batch['base_image_options'])} OS release(s) to test"}}

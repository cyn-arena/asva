"""Scan pinned initial or candidate source without starting the app or generating fixes.

The tool versions an app's dependency scan needs are its own, given by its workflow: --npm-version,
--python-image, --pip-version and --system-packages. An unset version is not checked or pinned.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile

from agent.candidate_source import verify
from normaliser.normaliser import process_sarif_file, deduplicate, sort_findings, assign_priorities, build_ranked_unified
from scripts.dashboard_evidence import identifier, write, candidate_run_id


def sarif_valid(path):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return isinstance(data, dict) and isinstance(data.get("runs"), list) and bool(data["runs"]) and all(
        isinstance(run, dict) and isinstance(run.get("results"), list) for run in data["runs"])


def execute(args, cwd, log):
    with Path(log).open("w", encoding="utf-8") as output:
        return subprocess.run(args, cwd=cwd, stdout=output, stderr=subprocess.STDOUT,
                              timeout=900, check=False).returncode


def rescan(*, app, app_path, sha, batch_id, pr_url, run_id, output, ecosystem,
           manifest, container_file, container_mode, compose_files=(),
           npm_version="", python_image="", pip_version="", system_packages="",
           run_attempt="1", scan_kind="after_fix", run=execute, verify_source=verify):
    """Run independent scans; failed builds never suppress source analysis."""
    out = Path(output).resolve()
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        raise ValueError("Candidate scan destination must be empty (stale reports are unsafe)")
    scans = {kind: {"status": "not_available", "detail": "Scan was not attempted"}
             for kind in ("sast", "sca", "container")}
    if scan_kind not in ("initial", "after_fix"):
        raise ValueError("Unsupported scan kind")
    report = {"app": app, "batch_id": identifier(batch_id), "pr_url": pr_url,
              "commit_sha": sha, "run_id": str(run_id), "scan_kind": scan_kind,
              "run_attempt": str(run_attempt),
              "source_verified": False, "scans": scans, "normalise": "not_available",
              "container_scope": container_mode}
    if scan_kind == "after_fix":
        report["after_fix_of"] = str(run_id)
    report["scan_policy"] = {"sast": "source checkout before dependency installation",
                             "sca_manifest": manifest,
                             "snyk_version": Path(__file__).with_name("snyk-version.txt").read_text().strip().lstrip("v")}

    def attempt(name, command, cwd, sarif=None):
        try:
            code = run(command, cwd, out / f"{name}.log")
        except (OSError, ValueError, subprocess.SubprocessError) as exc:
            if sarif:
                scans[name] = {"status": "failed", "detail": f"Command could not run: {exc}"}
            return False
        if not sarif:
            return code == 0
        # Report the command's own failure (e.g. dependency installation) before the
        # missing report it causes; the log names the failing step.
        if code not in (0, 1):
            detail = f"Command exited with code {code}; see {name}.log"
        else:
            try:
                detail = None if sarif_valid(sarif) else f"Scanner did not produce valid SARIF; see {name}.log"
            except (OSError, ValueError) as exc:
                detail = f"Scanner did not produce valid SARIF ({type(exc).__name__}); see {name}.log"
        scans[name] = {"status": "failed" if detail else "completed", "exit_code": code, "detail": detail}
        return detail is None

    try:
        source = verify_source(app_path, sha)
        report["source_verified"] = True
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        report["source_error"] = str(exc)
        write(out / "scan-status.json", report)
        return report

    version_ok = attempt("snyk-version", ["snyk", "--version"], source)
    actual_version = (out / "snyk-version.log").read_text().strip() if version_ok else "unavailable"
    report["snyk_version"] = actual_version
    if actual_version != report["scan_policy"]["snyk_version"]:
        report["toolchain_error"] = "Pinned Snyk CLI unavailable; see snyk-version.log"
        write(out / "scan-status.json", report)
        return report

    attempt("sast", ["snyk", "code", "test", f"--sarif-file-output={out / 'sast.sarif.json'}"],
            source, out / "sast.sarif.json")

    image = f"asva-candidate:{identifier(batch_id).lower()}"
    images = []
    if container_mode == "application":
        built = attempt("image-build", ["docker", "build", "-f", container_file, "-t", image, "."], source)
        images = [image] if built else []
        if not built:
            scans["container"]["detail"] = "Candidate image build failed; see image-build.log"

    # Install only in a disposable copy. Source scans and the candidate checkout
    # continue to read the immutable commit, even if package installation fails.
    with tempfile.TemporaryDirectory(prefix="asva-candidate-") as scratch:
        deps = Path(scratch) / "app"
        shutil.copytree(source, deps, ignore=shutil.ignore_patterns("node_modules", ".git", "*.sarif.json"))
        if ecosystem == "npm":
            report["dependency_install"] = f"npm{'@' + npm_version if npm_version else ''} ci --ignore-scripts"
            version_ok = attempt("npm-version", ["npm", "--version"], deps)
            version = (out / "npm-version.log").read_text(encoding="utf-8").strip() if version_ok else "unavailable"
            report["npm_version"] = version
            installed = version_ok and (not npm_version or version == npm_version) and attempt(
                "install", ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"], deps)
            if installed:
                attempt("sca", ["snyk", "test", f"--file={manifest}",
                                f"--sarif-file-output={out / 'sca.sarif.json'}"], deps, out / "sca.sarif.json")
            else:
                scans["sca"]["detail"] = "Pinned npm unavailable or frozen dependency installation failed; see npm-version.log / install.log"
        else:
            # No migrations, collectstatic or Gunicorn: source dependency evidence
            # is still possible when the candidate application image cannot build.
            snyk = shutil.which("snyk") or "snyk"
            packages = " ".join(shlex.quote(name) for name in system_packages.split())
            install_steps = ((f"apt-get update && apt-get install --no-install-recommends -y {packages} && " if packages else "")
                             + (f"python -m pip install pip=={shlex.quote(pip_version)} && " if pip_version else ""))
            dependency_command = ["docker", "run", "--rm", "--entrypoint", "sh",
                "-e", "SNYK_TOKEN", "-e", "SNYK_CFG_ORG",
                "-v", f"{Path(snyk).resolve()}:/opt/asva-snyk:ro",
                "-v", f"{deps}:/app", "-v", f"{out}:/reports", "-w", "/app", python_image,
                "-c", install_steps + 'python -m pip install -r "$1"'
                      ' && /opt/asva-snyk test --file="$1" --package-manager=pip --command=python'
                      ' --sarif-file-output=/reports/sca.sarif.json', "asva-sca", manifest]
            report["dependency_install"] = {"image": python_image, "pip": pip_version or "as in the image", "manifest": manifest,
                                            "scope": "dependency-only fallback"}
            if images:
                dependency_command = ["docker", "run", "--rm", "--entrypoint", "/opt/asva-snyk",
                    "-e", "SNYK_TOKEN", "-e", "SNYK_CFG_ORG",
                    "-v", f"{Path(snyk).resolve()}:/opt/asva-snyk:ro", "-v", f"{out}:/reports",
                    image, "test", f"--file={manifest}", "--package-manager=pip", "--command=python",
                    "--sarif-file-output=/reports/sca.sarif.json"]
                report["dependency_install"] = {"image": image, "manifest": manifest, "scope": "candidate image"}
            if images or python_image:
                attempt("sca", dependency_command, source, out / "sca.sarif.json")
            else:
                scans["sca"]["detail"] = "No candidate image, and this app's workflow sets no --python-image to scan with"

    if container_mode != "application":
        config = out / "compose.json"
        command = ["docker", "compose"]
        for file in compose_files:
            command.extend(["-f", file])
        try:
            with config.open("w", encoding="utf-8") as stream:
                subprocess.run([*command, "config", "--format", "json"], cwd=source, stdout=stream,
                               stderr=subprocess.PIPE, check=True, timeout=60)
            services = json.loads(config.read_text(encoding="utf-8"))["services"]
            images = list(dict.fromkeys(s["image"] for s in services.values() if not s.get("build") and s.get("image")))
            # Match the initial scan's first third-party service scope.
            images = images[:1]
            if not images:
                scans["container"]["detail"] = "No third-party image found in the candidate Compose configuration"
            elif not attempt("image-pull", ["docker", "pull", images[0]], source):
                images = []
                scans["container"]["detail"] = "Candidate third-party image could not be pulled; see image-pull.log"
        except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
            images = []
            scans["container"]["detail"] = f"Could not resolve Compose image: {exc}"
        finally:
            # Resolved Compose configuration can contain environment values.
            config.unlink(missing_ok=True)
    if images:
        report["container_image"] = images[0]
        attempt("container", ["snyk", "container", "test", images[0],
                f"--sarif-file-output={out / 'container.sarif.json'}"], source, out / "container.sarif.json")

    findings = []
    completed = [kind for kind, status in scans.items() if status["status"] == "completed"]
    try:
        for kind in completed:
            findings.extend(process_sarif_file(out / f"{kind}.sarif.json", strict=True))
        if completed:
            for finding in findings:
                finding.update(app=app, scan_run_id=str(run_id))
                if scan_kind == "after_fix":
                    finding.update(after_fix_of=str(run_id), batch_id=batch_id, candidate_sha=sha,
                                   scan_run_id=candidate_run_id(run_id, batch_id, sha, run_attempt))
            write(out / "findings/ranked_unified_findings.json",
                  build_ranked_unified(assign_priorities(sort_findings(deduplicate(findings)))))
            report["normalise"] = "completed"
    except (OSError, ValueError, TypeError) as exc:
        report.update(normalise="failed", normalise_error=str(exc))
    report["findings_status"] = ("completed" if len(completed) == 3 else "partial") if report["normalise"] == "completed" else "not_available"
    write(out / "scan-status.json", report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("app", "app-path", "sha", "batch-id", "pr-url", "run-id", "output", "manifest", "container-file"):
        parser.add_argument(f"--{name}", required=True)
    parser.add_argument("--ecosystem", choices=("npm", "pip"), required=True)
    parser.add_argument("--container-mode", choices=("application", "third-party"), required=True)
    parser.add_argument("--compose-file", action="append", dest="compose_files", default=[])
    for name in ("npm-version", "python-image", "pip-version", "system-packages"):
        parser.add_argument(f"--{name}", default="")
    parser.add_argument("--run-attempt", default=os.environ.get("GITHUB_RUN_ATTEMPT", "1"))
    parser.add_argument("--scan-kind", choices=("initial", "after_fix"), default="after_fix")
    args = parser.parse_args()
    report = rescan(**vars(args))
    return 0 if report["normalise"] == "completed" and all(
        s["status"] == "completed" for s in report["scans"].values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())

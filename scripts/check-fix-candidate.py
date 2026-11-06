"""Validate the checked-out candidate and record its independent after-fix scan."""
import argparse
import datetime
import json
import os
from pathlib import Path
import subprocess
import sys


def command(args, cwd=None):
    return subprocess.run(args, cwd=cwd).returncode


def capture_compose_diagnostics(compose, output):
    """Retain exited-container tracebacks before teardown; errors must not hide validation."""
    output.mkdir(parents=True, exist_ok=True)
    for filename, arguments in (
        ("pygoat-container-status.log", ["ps", "--all"]),
        ("pygoat-container.log", ["logs", "--no-color", "--tail", "200"]),
    ):
        path = output / filename
        try:
            with path.open("w", encoding="utf-8") as log:
                result = subprocess.run([*compose, *arguments], stdout=log, stderr=subprocess.STDOUT,
                                        timeout=30, check=False)
                log.write(f"\nDiagnostic command exit code: {result.returncode}\n")
        except (OSError, subprocess.TimeoutExpired) as exc:
            with path.open("a", encoding="utf-8") as log:
                log.write(f"\nCould not complete diagnostics: {exc}\n")
        print(f"\n--- {filename} ---", flush=True)
        print(path.read_text(encoding="utf-8", errors="replace"), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", choices=("pygoat", "nodegoat"), default="pygoat")
    parser.add_argument("--batch-id", required=True)
    parser.add_argument("--sha", required=True)
    args = parser.parse_args()
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if sha != args.sha:
        raise ValueError("Checked-out revision differs from the candidate SHA")
    batch_path = Path("asva-results/remediation/fix_batches") / (args.batch_id + ".json")
    batch = json.loads(batch_path.read_text(encoding="utf-8"))
    folder = Path("asva-results/candidates") / args.batch_id
    scans = folder / "scan"
    scans.mkdir(parents=True, exist_ok=True)
    validation = Path("asva-results/validation") / (args.batch_id + ".json")
    title = "PyGoat" if args.app == "pygoat" else "NodeGoat"
    os.environ["SOURCE_SHA"] = sha
    compose = ["docker", "compose", "-f", "target-apps/PyGoat/compose.asva.yml"]
    checks = []
    started = False
    scan_started_at = None
    try:
        if args.app == "pygoat":
            started = command([*compose, "up", "-d", "--build", "--wait", "--wait-timeout", "120"]) == 0
            smoke_file = folder / "smoke.json"
            command([sys.executable, "scripts/pygoat-smoke.py", "--output", str(smoke_file)])
            smoke = json.loads(smoke_file.read_text(encoding="utf-8"))
            checks.extend(smoke["checks"])
            image_built = command(["docker", "build", "-f", "target-apps/PyGoat/Dockerfile.asva", "-t", "asva-pygoat:scan", f"target-apps/{title}"]) == 0
        else:
            previous = json.loads(validation.read_text(encoding="utf-8"))
            started = previous["app_started"]
            checks.extend(previous["checks"])
            image_built = False
        # Match the initial scan's dependency preparation before scanning source.
        installed = True
        if args.app == "nodegoat":
            installed = command(["npm", "install", "--ignore-scripts"], "target-apps/NodeGoat") == 0
            checks.append({"name": "scan dependencies installed", "kind": "scan_preparation",
                           "status": "passed" if installed else "failed", "detail": None if installed else "npm install failed"})
        scan_started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        sast = command(["snyk", "code", "test", f"--sarif-file-output={scans.resolve() / 'sast.sarif.json'}"], f"target-apps/{title}") if installed else 2
        sca, container = 2, 2
        if args.app == "nodegoat":
            if installed:
                sca = command(["snyk", "test", f"--sarif-file-output={scans.resolve() / 'sca.sarif.json'}"], "target-apps/NodeGoat")
            config = json.loads(subprocess.check_output(["docker", "compose", "-f", "target-apps/NodeGoat/docker-compose.yml",
                                                        "-f", "target-apps/NodeGoat/docker-compose.pr-check.yml", "config", "--format", "json"], text=True))
            image = config["services"]["mongo"]["image"]
            if command(["docker", "pull", image]) == 0:
                container = command(["snyk", "container", "test", image, f"--sarif-file-output={scans / 'container.sarif.json'}"])
        elif image_built:
            sca = command(["docker", "run", "--rm", "--entrypoint", "/opt/asva-snyk", "-e", "SNYK_TOKEN", "-e", "SNYK_CFG_ORG",
                           "-v", f"{Path.home() / '.local/bin/snyk'}:/opt/asva-snyk:ro", "-v", f"{scans.resolve()}:/reports",
                           "asva-pygoat:scan", "test", "--file=requirements.txt", "--package-manager=pip", "--command=python", "--sarif-file-output=/reports/sca.sarif.json"])
            container = command(["snyk", "container", "test", "asva-pygoat:scan", "--file=target-apps/PyGoat/Dockerfile.asva",
                                 f"--sarif-file-output={scans / 'container.sarif.json'}"])
        complete = all(code in (0, 1) and (scans / f"{kind}.sarif.json").is_file()
                       for kind, code in (("sast", sast), ("sca", sca), ("container", container)))
        statuses = {}
        for kind, code in (("sast", sast), ("sca", sca), ("container", container)):
            path = scans / f"{kind}.sarif.json"
            valid = False
            if path.exists():
                try:
                    valid = bool(json.loads(path.read_text(encoding="utf-8")).get("runs"))
                except (ValueError, OSError):
                    pass
            statuses[kind] = {"exit_code": code, "status": "completed" if code in (0, 1) and valid else "failed"}
        complete = complete and all(value["status"] == "completed" for value in statuses.values())
        logical_id = f"{os.environ['GITHUB_RUN_ID']}-after-fix-{args.batch_id}"
        (scans / "scan-status.json").write_text(json.dumps({"app": args.app, "run_id": logical_id,
            "commit_sha": sha, "scans": statuses}, indent=2), encoding="utf-8")
        normalised = False
        if complete:
            normalised = command([sys.executable, "normaliser/normaliser.py", "--inputs",
                                  *[str(scans / f"{kind}.sarif.json") for kind in ("sast", "sca", "container")],
                                  "--output-dir", str(folder / "findings"), "--scan-run-id", logical_id,
                                  "--app-prefix", f"target-apps/{title}"]) == 0
        def key(finding):
            return (finding["identifiers"]["rule_id"], finding["location"]["file"] if finding["finding_type"] == "sast" else finding["location"]["package"])
        if normalised:
            remaining = json.loads((folder / "findings/ranked_unified_findings.json").read_text(encoding="utf-8"))
            active = {key(f) for f in remaining}
            targeted = {key(f) for entry in batch["files_to_fix"] for f in entry["findings"]}
            still_present = sorted(targeted & active)
            checks.append({"name": "targeted scanner findings absent from candidate", "kind": "security_scan",
                           "status": "failed" if still_present else "passed", "detail": json.dumps(still_present)})
        else:
            checks.append({"name": "candidate rescan completed", "kind": "security_scan", "status": "failed", "detail": "Missing or failed scan/normalisation"})
        if not any(c.get("kind") == "app_start" for c in checks):
            checks.insert(0, {"name": "app starts up", "kind": "app_start", "status": "passed" if started else "failed", "detail": None if started else "App did not become ready"})
        report = {"app": args.app, "batch_id": args.batch_id, "phase": "post_fix", "tested_sha": sha, "commit_sha": sha,
                  "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(), "app_started": started,
                  "result": "passed" if started and all(c["status"] == "passed" for c in checks) else "failed",
                  "misuse_tests": "completed" if any(c.get("kind") == "misuse" for c in checks) else "not_available", "checks": checks}
        validation.parent.mkdir(parents=True, exist_ok=True)
        validation.write_text(json.dumps(report, indent=2), encoding="utf-8")
        candidate_validation = folder / "validation"
        candidate_validation.mkdir(exist_ok=True)
        (candidate_validation / (args.batch_id + ".json")).write_text(json.dumps(report, indent=2), encoding="utf-8")
        (folder / "candidate.json").write_text(json.dumps({"commit_sha": sha, "scan_started_at": scan_started_at, "outcomes": {
            "scan": "success" if complete else "failure", "normalise": "success" if normalised else "failure",
            "validate": "success" if report["result"] == "passed" else "failure"}}, indent=2), encoding="utf-8")
        return 0 if report["result"] == "passed" else 1
    finally:
        if args.app == "pygoat":
            try:
                capture_compose_diagnostics(compose, folder / "validation")
            finally:
                command([*compose, "down", "-v"])


if __name__ == "__main__":
    sys.exit(main())

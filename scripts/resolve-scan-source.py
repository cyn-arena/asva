"""Select the application revision and PR target belonging to a NodeGoat scan."""
import argparse
import json
import os
import re
import subprocess


def read_scan_run(run_id, repository):
    if not re.fullmatch(r"[0-9]+", run_id):
        raise ValueError("A numeric scan run ID is required")
    return json.loads(subprocess.check_output(
        ["gh", "run", "view", run_id, "--repo", repository,
         "--json", "headBranch,headSha,event"], text=True, encoding="utf-8"))


def resolve_source(*, use_current_artifacts, source_branch, source_sha,
                   scan_run_id, repository, ref_type, lookup=read_scan_run):
    if use_current_artifacts and ref_type != "branch":
        raise ValueError("Current-run remediation requires a branch run")
    if use_current_artifacts and (source_branch or source_sha):
        if not source_branch or not source_sha:
            raise ValueError("Provide both source_branch and source_sha")
        branch, sha = source_branch, source_sha
    else:
        # Historical artifacts must use their own run's source, regardless of caller inputs.
        run = lookup(scan_run_id, repository)
        if run.get("event") not in ("push", "workflow_dispatch"):
            raise ValueError("Only branch push/manual scan runs are supported")
        branch, sha = run.get("headBranch", ""), run.get("headSha", "")
    if not branch or branch.startswith(("-", "@")) or "\n" in branch or "\r" in branch:
        raise ValueError("Scan source must name a branch")
    if not re.fullmatch(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", sha or ""):
        raise ValueError("Scan source must identify a full commit SHA")
    return branch, sha


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--use-current-artifacts", choices=("true", "false"), required=True)
    parser.add_argument("--source-branch", default="")
    parser.add_argument("--source-sha", default="")
    parser.add_argument("--scan-run-id", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--ref-type", required=True)
    args = parser.parse_args()
    try:
        branch, sha = resolve_source(
            use_current_artifacts=args.use_current_artifacts == "true",
            source_branch=args.source_branch, source_sha=args.source_sha,
            scan_run_id=args.scan_run_id, repository=args.repository, ref_type=args.ref_type)
        subprocess.run(["git", "check-ref-format", "--branch", branch],
                       check=True, stdout=subprocess.DEVNULL)
    except (ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Could not resolve scanned source: {error}\n")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(f"branch={branch}\nsha={sha}\n")
    with open(os.environ["GITHUB_ENV"], "a", encoding="utf-8") as environment:
        environment.write(f"GITHUB_BASE_BRANCH={branch}\nASVA_SCANNED_SHA={sha}\n")
    print(f"Fix source: {branch} @ {sha}; PR target: {branch}")


if __name__ == "__main__":
    main()

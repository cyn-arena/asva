"""Resolve explicit candidate source independently of the validation tooling."""
from pathlib import Path
import argparse
import os
import re
import subprocess


def verify(app_path, expected_sha):
    app = Path(app_path).resolve(strict=True)
    if not re.fullmatch(r"[0-9a-f]{40}", expected_sha or ""):
        raise ValueError("Candidate validation requires the full expected commit SHA")
    actual = subprocess.check_output(["git", "-C", str(app), "rev-parse", "HEAD"], text=True).strip()
    if actual != expected_sha:
        raise ValueError(f"Candidate SHA mismatch: expected {expected_sha}, checked out {actual}")
    dirty = subprocess.check_output(
        ["git", "-C", str(app), "status", "--porcelain", "--untracked-files=no", "--", "."], text=True)
    if dirty:
        raise ValueError("Candidate application has tracked changes")
    return app


def application_path(default):
    configured = os.environ.get("ASVA_APP_PATH")
    candidate = os.environ.get("TARGET") == "candidate"
    if candidate and not configured:
        raise ValueError("ASVA_APP_PATH is required for candidate source checks")
    if candidate:
        return verify(configured, os.environ.get("ASVA_CANDIDATE_SHA"))
    return Path(configured).resolve(strict=True) if configured else Path(default)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app-path", required=True)
    parser.add_argument("--sha", required=True)
    args = parser.parse_args()
    print(verify(args.app_path, args.sha))

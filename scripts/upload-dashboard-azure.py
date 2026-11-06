"""Publish a dashboard run using Azure CLI login; upload the manifest last."""
import argparse
import json
from pathlib import Path
import re
import subprocess


def upload_run(run_dir, account, container, *, execute=subprocess.run):
    root = Path(run_dir).resolve()
    manifest_path = root / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    app, run_id = manifest["app"], manifest["run_id"]
    if any(not re.fullmatch(r"[A-Za-z0-9_-]+", segment) for segment in (app, run_id)):
        raise ValueError("Unsafe app or run ID")
    artifacts = manifest["artifacts"]
    referenced = [artifacts[key] for key in ("findings", "triage", "fixes", "remediation", "baseline_validation", "normalisation_audit", "scan_status") if key in artifacts]
    referenced += [*artifacts.get("scan", {}).values(), *artifacts.get("fix_batches", []), *artifacts.get("validation", [])]
    for rel in referenced:
        path = (root / rel).resolve()
        if not path.is_relative_to(root) or not path.is_file():
            raise ValueError(f"Missing or unsafe artifact: {rel}")
    files = sorted(path for path in root.rglob("*") if path.is_file() and path != manifest_path)
    if any(not path.resolve().is_relative_to(root) for path in files):
        raise ValueError("Run contains a file outside its directory")
    # Fail immediately on upload errors, leaving the manifest unpublished on a first run.
    # Re-running the same Actions run replaces its own blobs at the same prefix.
    for path in [*files, manifest_path]:
        name = f"{app}/{run_id}/{path.relative_to(root).as_posix()}"
        execute(["az", "storage", "blob", "upload", "--account-name", account,
                 "--container-name", container, "--name", name, "--file", str(path),
                 "--auth-mode", "login", "--overwrite", "true",
                 "--content-type", "application/json" if path.suffix == ".json" else "text/plain", "--only-show-errors", "--output", "none"],
                check=True)
        print(f"Uploaded {container}/{name}")
    return f"{app}/{run_id}/manifest.json"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--account", required=True)
    parser.add_argument("--container", required=True)
    args = parser.parse_args()
    prefix = upload_run(args.run_dir, args.account, args.container)
    print(f"Dashboard manifest ready: {prefix}")


if __name__ == "__main__":
    main()

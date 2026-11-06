"""Download available evidence from this run, including earlier successful attempts."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess


def gh_json(*args):
    return json.loads(subprocess.check_output(["gh", *args], text=True, encoding="utf-8"))


def collect(app, repository, run_id, output):
    root = Path(output)
    root.mkdir(parents=True, exist_ok=True)
    pages = gh_json("api", "--paginate", "--slurp", f"repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100")
    artifacts = [artifact for page in pages for artifact in page["artifacts"]]
    # Artifact names encode producing attempt; legacy NodeGoat names have no suffix.
    selected = {}
    for artifact in artifacts:
        name = artifact["name"]
        if artifact["expired"] or not name.startswith(app + "-") or "dashboard" in name:
            continue
        key = name
        if name.rsplit("-", 1)[-1].isdigit():
            key = name.rsplit("-", 1)[0]
        if key not in selected or artifact["created_at"] > selected[key]["created_at"]:
            selected[key] = artifact
    for artifact in selected.values():
        name = artifact["name"]
        temp = root.parent / "downloads" / str(artifact["id"])
        subprocess.run(["gh", "run", "download", run_id, "--repo", repository,
                        "--name", name, "--dir", str(temp)], check=True)
        if name == "nodegoat-scan-results" or name.startswith(f"{app}-scan-"):
            destination = root / "scan"
        elif name.startswith(f"{app}-fix-") and name != "nodegoat-fix-output":
            destination = root / "remediation"
        elif name.startswith(f"{app}-validation-") or name.startswith(f"{app}-baseline-"):
            destination = root / "validation"
        else:
            destination = root
        shutil.copytree(temp, destination, dirs_exist_ok=True)
    # Legacy filenames/locations remain accepted while NodeGoat migrates.
    if (root / "scan/image.sarif.json").exists():
        shutil.copyfile(root / "scan/image.sarif.json", root / "scan/container.sarif.json")
    if (root / "fix_batches").exists():
        shutil.copytree(root / "fix_batches", root / "remediation/fix_batches", dirs_exist_ok=True)
    for name in ("pygoat-validation.json", "nodegoat-validation.json"):
        if (root / "validation" / name).exists():
            (root / "validation" / name).replace(root / "validation/baseline.json")
    (root / "evidence-artifacts.json").write_text(json.dumps([
        {"name": a["name"], "id": a["id"]} for a in selected.values()], indent=2), encoding="utf-8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    collect(args.app, args.repository, args.run_id, args.output)

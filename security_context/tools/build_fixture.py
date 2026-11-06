#!/usr/bin/env python3
"""Rebuild a demo/evaluation fixture from ASVA's findings (one-off maintenance).

The demo (tests/query_rag.py) and the evaluations only ever read the fixtures this writes;
nothing in the service or its tests reads the asva folder at runtime. Run it again only when
the scan results change:

    python tools/build_fixture.py --asva ..                       # NodeGoat, from asva/samples/fix_batches
    python tools/build_fixture.py --asva .. --app pygoat \\
        --run-dir data/pipeline_runs/pygoat_39018400376                 # PyGoat, from a pipeline run

Each finding is copied from ASVA's triage batches as the agent would send it, plus
`sarif_cwes`: the CWE ids Snyk put on that rule in the SARIF files. ASVA's normaliser does
not pass those on for dependency and container findings yet.

The batches and SARIF files come from the asva checkout (samples/fix_batches/, samples/scans/) or, with
--run-dir, from a downloaded pipeline run (gh run download): <app>-fix-output/fix_batches and
<app>-scan-results. It also copies the app files the fix evaluations give the LLM and build
(tests/fixtures/<app>_files/). The asva folder is only read.
"""

import argparse
import json
import re
import shutil
from datetime import date
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
APPS = {  # --app -> (folder under asva/target-apps, files copied for the fix evaluations)
    "nodegoat": ("NodeGoat", ("package.json", "docker-compose.yml")),
    "pygoat": ("PyGoat", ("requirements.txt", "Dockerfile.asva", "compose.asva.yml")),
}
KEEP = ("finding_type", "severity", "score", "has_real_score", "title", "summary", "description",
        "identifiers", "location", "remediation", "ecosystem", "dependency")
CWE = re.compile(r"^CWE-\d+$")


def rule_cwes(sarif_files: list[Path]) -> dict[str, list[str]]:
    """rule id -> CWE ids, from each rule's properties.cwe (Snyk Code) or properties.tags."""
    found: dict[str, list[str]] = {}
    for path in sarif_files:
        for run in json.loads(path.read_text(encoding="utf-8")).get("runs", []):
            for rule in run.get("tool", {}).get("driver", {}).get("rules", []):
                properties = rule.get("properties", {})
                cwes = [c for c in (properties.get("cwe") or []) + (properties.get("tags") or []) if CWE.match(str(c))]
                if cwes:
                    found[rule["id"]] = list(dict.fromkeys(cwes))
    return found


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--asva", required=True, type=Path, help="Path to an ASVA checkout (read only).")
    parser.add_argument("--app", choices=sorted(APPS), default="nodegoat")
    parser.add_argument("--run-dir", type=Path, help="A downloaded pipeline run to read batches and SARIF files from.")
    parser.add_argument("--name", help="Fixture name if not the app's (e.g. nodegoat_branch): <name>_findings.json.")
    args = parser.parse_args()

    folder, app_files = APPS[args.app]
    if args.run_dir:
        batch_dir = args.run_dir / f"{args.app}-fix-output" / "fix_batches"
        sarif_files = sorted((args.run_dir / f"{args.app}-scan-results").glob("*.sarif.json"))
    else:
        batch_dir, sarif_files = args.asva / "samples" / "fix_batches", sorted((args.asva / "samples" / "scans").glob("*.sarif.json"))
    cwes = rule_cwes(sarif_files)
    files, batches, source = [], [], {}
    for path in sorted(batch_dir.glob("*.json")):
        batch = json.loads(path.read_text(encoding="utf-8"))
        batches.append(batch["batch_id"])
        source = {"scan_run_id": batch["scan_run_id"], "commit_sha": batch["commit_sha"]}
        for entry in batch["files_to_fix"]:
            findings = [{**{k: f.get(k) for k in KEEP}, "sarif_cwes": cwes.get(f["identifiers"]["rule_id"], [])}
                        for f in entry["findings"]]
            files.append({"file": entry["file"], "batch_id": batch["batch_id"], "finding_type": entry["finding_type"],
                          "fix_type": entry["fix_type"], "findings": findings})

    order = {"sast": 0, "sca": 1, "container": 2}
    files.sort(key=lambda e: order.get(e["finding_type"], 9))
    out = FIXTURES / f"{args.name or args.app}_findings.json"
    fixture = {
        "description": f"Real {folder} findings from the ASVA pipeline, hardcoded for the RAG demo and evaluation. "
                       "Built by tools/build_fixture.py from ASVA's triage batches (normalised + triaged Snyk findings) "
                       "plus each rule's CWE ids from the Snyk SARIF files ('sarif_cwes'). "
                       "Nothing reads the asva folder at runtime.",
        "extracted_at": date.today().isoformat(),
        "source": {**source, "batches": batches, "sarif": [p.name for p in sarif_files],
                   **({"pipeline_run": args.run_dir.name} if args.run_dir else {})},
        "files": files,
    }
    out.write_text(json.dumps(fixture, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {out} ({out.stat().st_size:,} bytes)")
    copies = FIXTURES / f"{args.name or args.app}_files"
    copies.mkdir(exist_ok=True)
    for name in app_files:
        shutil.copyfile(args.asva / "target-apps" / folder / name, copies / name)
    print(f"Copied {', '.join(app_files)} to {copies}")
    for entry in files:
        with_cwe = sum(1 for f in entry["findings"] if f["sarif_cwes"])
        print(f"  {entry['finding_type']:10} {entry['file']:40} {len(entry['findings']):3} finding(s), {with_cwe} with SARIF CWEs")


if __name__ == "__main__":
    main()

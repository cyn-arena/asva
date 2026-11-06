#!/usr/bin/env python3
"""Run the ITP2 Task 1 or Task 6 evaluation end to end and write a results report.

  python scripts/run_evaluation.py --task 1                 # 3.1: with vs without related files
  python scripts/run_evaluation.py --task 6                 # 3.6: batch size x pass
  python scripts/run_evaluation.py --task 6 --rescan        # + Snyk re-scan of every run
  python scripts/run_evaluation.py --task 1 --app pygoat    # any app under target-apps/

The target app is --app (a folder name under target-apps/, case-insensitive) or, without it,
ASVA_FIX_PATH_PREFIX from .env. Each app gets its own folder, eval_results/<app>/, so runs on
different apps never mix.

What it does, following the "Outcomes (or Acceptance Criteria)" in the ITP2 task document:

  Task 1  "Evaluated outcomes of code remediation results (esp. on quality of code fixes)
          with and without use of related/dependent files excluding libraries."
          -> one pass, run without repo context (ITP1 behaviour) and with it.
  Task 6  "Evaluated outcomes ... when/if (i) increase or reduce the batch size (ii) in each
          pass#, with reference to Attention Dilution."
          -> two passes (local without context, integration with context) at each
             --limits value of files per prompt; the state after each pass is scored.

Steps: build the evaluation batches, run every condition --repeats times with
`agent_loop.py --dry-run` (no git, no PRs), score them with compare_dry_runs.py, and write
eval_results/<app>/task<N>_results.md (+ .json). Runs that already finished are skipped, so an
interrupted evaluation can simply be started again. Needs the LLM settings in .env.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from gitops import config  # noqa: E402  (loads .env)

_spec = importlib.util.spec_from_file_location("compare_dry_runs", REPO_ROOT / "scripts" / "compare_dry_runs.py")
compare_dry_runs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(compare_dry_runs)

PY = sys.executable

# Environment for the agent/batch subprocesses; main() points ASVA_FIX_PATH_PREFIX at the app.
SUB_ENV = dict(os.environ)


def resolve_app(app: str | None) -> str:
    """target-apps/<App> for --app (case-insensitive), else ASVA_FIX_PATH_PREFIX."""
    if not app:
        return config.FIX_PATH_PREFIX
    apps = REPO_ROOT / "target-apps"
    for d in sorted(apps.iterdir()) if apps.is_dir() else []:
        if d.is_dir() and d.name.lower() == app.lower():
            return f"target-apps/{d.name}"
    known = ", ".join(d.name for d in apps.iterdir() if d.is_dir()) if apps.is_dir() else "none"
    sys.exit(f"[ERROR] no target app {app!r} under target-apps/ (found: {known})")


def _run(cmd: list[str], log: Path | None = None) -> int:
    """Run a command from the repo root, streaming output to the console (and a log)."""
    print("  $ " + " ".join(cmd[1:] if cmd[0] == PY else cmd))
    with subprocess.Popen(cmd, cwd=REPO_ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True, encoding="utf-8", errors="replace", env=SUB_ENV) as proc:
        lines = []
        for line in proc.stdout:
            lines.append(line)
            if line.lstrip().startswith(("[WARN]", "[FATAL]", "[ERROR]", "Passes:", "wrote ", "review note")):
                print("    " + line.rstrip())
        code = proc.wait()
    if log is not None:
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text("".join(lines), encoding="utf-8")
    return code


# ---------------------------------------------------------------------------------------
# Batches
# ---------------------------------------------------------------------------------------

def _batch_fits_app(batch: Path, app_root: Path) -> bool:
    """True if every file the batch fixes exists in this app (a NodeGoat batch names
    package.json / app/routes/x.js, a PyGoat one requirements.txt / introduction/x.py)."""
    try:
        files = [fe["file"] for fe in json.loads(batch.read_text(encoding="utf-8")).get("files_to_fix", [])]
    except (ValueError, KeyError, OSError):
        return False
    return bool(files) and all((app_root / f).exists() for f in files)


def build_batches(task: int, batch_dir: Path, app_root: Path, sast_scan: str | None = None,
                  sca_batch: str | None = None) -> list[Path]:
    batch_dir.mkdir(parents=True, exist_ok=True)
    exp = batch_dir / "asva_exp_sast.json"
    if not exp.exists():
        cmd = [PY, "scripts/make_experiment_batch.py", "--max-files", "20", "--out-dir", str(batch_dir),
               "--path-prefix", SUB_ENV.get("ASVA_FIX_PATH_PREFIX", "")]
        if sast_scan:
            cmd += ["--scan", sast_scan]
        if _run(cmd) != 0:
            sys.exit("[ERROR] could not build the experiment batch (see the message above)")
    if task == 1:
        # The IDOR logic batch comes from NodeGoat's annotated misuse-case suite; it only
        # applies when the annotated files exist in this app.
        idor = batch_dir / "asva_logic_offline0_test_idor_allocations.json"
        if not idor.exists() and (app_root / "app" / "routes" / "allocations.js").exists():
            if _run([PY, "scripts/make_logic_batch.py", "--test", "test_idor_allocations",
                     "--out-dir", str(batch_dir)]) != 0:
                sys.exit("[ERROR] could not build the IDOR logic batch")
        # A dependency batch for this app: --sca-batch, else the first samples/fix_batches/ SCA batch
        # whose manifest is in this app
        candidates = [Path(sca_batch)] if sca_batch else sorted((REPO_ROOT / "samples" / "fix_batches").glob("*_sca_*.json"))
        for sca in candidates:
            if not sca.exists() or not _batch_fits_app(sca, app_root):
                if sca_batch:
                    sys.exit(f"[ERROR] --sca-batch {sca} is missing or names files not in {app_root}")
                continue
            if not (batch_dir / sca.name).exists():
                (batch_dir / sca.name).write_bytes(sca.read_bytes())
            break
    return sorted(b for b in batch_dir.glob("*.json") if _batch_fits_app(b, app_root))


# ---------------------------------------------------------------------------------------
# Conditions
# ---------------------------------------------------------------------------------------

def conditions(task: int, limits: list[int]) -> list[dict]:
    """name (run folder prefix), a readable description, agent flags, and which output
    folders to score (label -> sub-folder)."""
    if task == 1:
        return [
            {"name": "without", "desc": "without repo context (ITP1 baseline)",
             "flags": ["--no-repo-context"], "score": {"without": ""}},
            {"name": "with", "desc": "with repo context",
             "flags": [], "score": {"with": ""}},
        ]
    return [
        {"name": f"{n}f", "desc": f"up to {n} file{'s' if n != 1 else ''} per prompt, 2 passes",
         "flags": ["--passes", "2", "--files-per-prompt", str(n)],
         "score": {f"{n}f-pass1": "after_pass1", f"{n}f-pass2": "after_pass2"}}
        for n in limits
    ]


def _log_stats(log: Path) -> dict:
    text = log.read_text(encoding="utf-8", errors="replace") if log.exists() else ""
    return {
        "llm_calls": len(re.findall(r"Querying LLM", text)),
        "truncation_warnings": len(re.findall(r"\[WARN\] (?:prompt is ~|reply may need ~)", text)),
        "cut_off_replies": len(re.findall(r"\[WARN\] reply was cut off", text)),
        "review_notes": len(re.findall(r"review note \(", text)),
        "integration_skipped": len(re.findall(r"Integration pass skipped", text)),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--task", type=int, choices=(1, 6), required=True)
    parser.add_argument("--repeats", type=int, default=3, help="Runs per condition (default 3)")
    parser.add_argument("--limits", type=int, nargs="+", default=[1, 5, 10],
                        help="Task 6: files-per-prompt limits to compare (default 1 5 10)")
    parser.add_argument("--rescan", action="store_true",
                        help="Also re-scan every run with Snyk Code (needs `snyk auth` or SNYK_TOKEN)")
    parser.add_argument("--app", default=None,
                        help="Target app folder under target-apps/ (e.g. nodegoat, pygoat). "
                             "Default: ASVA_FIX_PATH_PREFIX from .env")
    parser.add_argument("--sast-scan", default=None,
                        help="Snyk Code SARIF for the app. Default: samples/scans/<app>-sast.sarif.json")
    parser.add_argument("--sca-batch", default=None,
                        help="Task 1: dependency batch for the app. Default: the first "
                             "samples/fix_batches/*_sca_*.json whose manifest is in the app")
    parser.add_argument("--out", default=None,
                        help="Output folder. Default: eval_results/<app>")
    args = parser.parse_args()

    prefix = resolve_app(args.app)
    if not prefix:
        sys.exit("[ERROR] no target app: pass --app (e.g. --app nodegoat) or set "
                 "ASVA_FIX_PATH_PREFIX in .env")
    SUB_ENV["ASVA_FIX_PATH_PREFIX"] = prefix
    app_name = Path(prefix).name.lower()
    out = Path(args.out) if args.out else REPO_ROOT / "eval_results" / app_name
    batch_dir = out / "batches" / f"task{args.task}"
    run_root = out / "runs" / f"task{args.task}"
    app_root = compare_dry_runs.app_root_for(REPO_ROOT, prefix)
    if not app_root.is_dir():
        sys.exit(f"[ERROR] app folder not found: {app_root}")

    print("=" * 70)
    print(f"ASVA evaluation: Task {args.task} on {prefix}")
    print("=" * 70)
    num_ctx = os.environ.get("OLLAMA_NUM_CTX", "").strip()
    if args.task == 6 and not num_ctx:
        print("[WARN] OLLAMA_NUM_CTX is not set. Multi-file prompts may be cut off by the model's "
              "default context window, which would invalidate the batch-size comparison.")
    if args.rescan:
        from tests.rescan._snyk_rescan import is_authenticated
        if not is_authenticated():
            sys.exit("[ERROR] --rescan needs an authenticated snyk CLI (`snyk auth` or SNYK_TOKEN)")

    print("\nBatches")
    batches = build_batches(args.task, batch_dir, app_root, args.sast_scan, args.sca_batch)
    if not batches:
        sys.exit("[ERROR] no evaluation batches for this app")
    for b in batches:
        print(f"  {b.relative_to(REPO_ROOT) if b.is_relative_to(REPO_ROOT) else b}")

    conds = conditions(args.task, args.limits)
    stats: dict[str, list[dict]] = {}
    print(f"\nRuns ({len(conds)} condition(s) x {args.repeats} repeat(s))")
    for i in range(1, args.repeats + 1):
        for c in conds:
            run_dir = run_root / f"{c['name']}_{i}"
            done = run_dir / ".done"
            log = run_dir / "agent.log"
            what = f"{c['desc']}, repeat {i} of {args.repeats} (folder {run_dir.name})"
            if done.exists():
                print(f"- {what}: already done, skipping")
            else:
                print(f"- {what}")
                start = time.time()
                code = _run([PY, "agent/agent_loop.py", "--batch-dir", str(batch_dir),
                             "--repo-dir", str(REPO_ROOT), "--dry-run", "--output-dir", str(run_dir),
                             *c["flags"]], log=log)
                if code != 0:
                    sys.exit(f"[ERROR] agent exited with {code}; see {log}. Fix the cause and rerun "
                             f"this command: finished runs are kept.")
                done.write_text(f"{time.time() - start:.0f}s\n", encoding="utf-8")
            entry = _log_stats(log)
            entry["seconds"] = done.read_text().strip() if done.exists() else "?"
            stats.setdefault(c["name"], []).append(entry)

    print("\nScoring")
    batch_dicts = [json.loads(b.read_text(encoding="utf-8")) for b in batches]
    specs = [(label, run_root / f"{c['name']}_{i}" / sub)
             for c in conds for label, sub in c["score"].items()
             for i in range(1, args.repeats + 1)]
    runs, rows = compare_dry_runs.compare(
        specs, batch_dicts, app_root,
        scan_fn=compare_dry_runs.snyk_scan if args.rescan else None,
    )
    print(compare_dry_runs.format_table(rows))

    seams = [f"- `{label}` {Path(r['dir']).parent.name if r['dir'].endswith(('after_pass1', 'after_pass2')) else Path(r['dir']).name}, {bid}: {p}"
             for label, label_runs in runs.items() for r in label_runs
             for bid, res in r["results"].items() for p in res["seams"]]
    report = render_report(args, rows, stats, seams, batch_dicts, num_ctx, prefix)
    out.mkdir(parents=True, exist_ok=True)
    md = out / f"task{args.task}_results.md"
    md.write_text(report, encoding="utf-8")
    (out / f"task{args.task}_results.json").write_text(
        json.dumps({"rows": rows, "runs": runs, "stats": stats}, indent=2), encoding="utf-8")
    print(f"\nwrote {md}")


def render_report(args, rows, stats, seams, batches, num_ctx, prefix="") -> str:
    title = {1: "Task 1 (3.1): remediation with and without related files",
             6: "Task 6 (3.6): attention dilution by batch size and pass"}[args.task]
    criterion = {
        1: "Evaluated outcomes of code remediation results (esp. on quality of code fixes) with "
           "and without use of related/dependent files excluding libraries.",
        6: "Evaluated outcomes of code remediation results when/if: (i) increase or reduce the "
           "batch size (ii) in each pass#, with reference to Attention Dilution.",
    }[args.task]
    lines = [
        f"# {title}",
        "",
        f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} by `scripts/run_evaluation.py`.",
        "",
        f"**Acceptance criterion:** {criterion}",
        "",
        "## Setup",
        "",
        f"- Target app: `{prefix}`",
        f"- Model: `{os.environ.get('OLLAMA_MODEL', '?')}`; context window (OLLAMA_NUM_CTX): "
        f"{num_ctx or 'not set (server default)'}; reply cap (ASVA_LLM_NUM_PREDICT): "
        f"{os.environ.get('ASVA_LLM_NUM_PREDICT') or 'not set (server default)'}",
        f"- Runs per condition: {args.repeats}" + (f"; files-per-prompt limits: {args.limits}" if args.task == 6 else ""),
        f"- Independent re-scan (Snyk Code): {'yes' if args.rescan else 'no'}",
        "- Batches: " + "; ".join(
            f"`{b['batch_id']}` ({b.get('total_files', len(b.get('files_to_fix', [])))} files, "
            f"{b.get('total_findings', '?')} findings)" for b in batches),
    ]
    if args.task == 1:
        lines.append("- Conditions: `without` = no repo context (ITP1 prompt); `with` = importers, "
                     "call sites, local imports and the scanner's data flow (code from other files "
                     "on the flow included, libraries excluded).")
    else:
        lines.append("- Conditions: `Nf` = at most N files per prompt. `pass1` = local pass, no "
                     "additional context. `pass2` = integration pass on the pass-1 result, with "
                     "repo context (RAG and memory join when tasks 3.3 and 3.5 land).")
    lines += ["", "## Results", "", compare_dry_runs.format_markdown(rows), ""]
    lines += [
        "Higher is better: fixed, syntax ok, scan fixed. Lower is better: no-op, flagged kept, "
        "broken seams, scan new. Values are averaged over the runs of each condition.",
        "",
        "## Run statistics",
        "",
        "| condition | LLM calls per run | seconds per run | truncation warnings | cut-off replies | review notes | integration skipped |",
        "|---|---|---|---|---|---|---|",
    ]
    for name, entries in stats.items():
        def avg(k):
            vals = [e[k] for e in entries if isinstance(e[k], int)]
            return f"{sum(vals) / len(vals):.1f}" if vals else "-"
        secs = ", ".join(e["seconds"] for e in entries)
        lines.append(f"| {name} | {avg('llm_calls')} | {secs} | {avg('truncation_warnings')} | "
                     f"{avg('cut_off_replies')} | {avg('review_notes')} | {avg('integration_skipped')} |")
    lines += ["", "## Cross-file breaks found", ""]
    lines += seams or ["None."]
    lines += [
        "",
        "## Notes for interpretation",
        "",
        f"- {args.repeats} run(s) per condition on one small app is directional evidence, not a "
        "benchmark. Report means and note where runs disagree.",
        "- A truncation warning means a prompt may not have fit the model's context window, and a "
        "cut-off reply means the model stopped before finishing (files in it are incomplete); "
        "treat those conditions' results with caution.",
        "- The direct proof that a vulnerability is closed is the misuse-case suite against a "
        "deployed candidate (`pytest -m api`).",
    ]
    if args.task == 6:
        lines.append("- Limits at or above the number of vulnerable files all send one prompt with "
                     "every file, so they are identical runs.")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()

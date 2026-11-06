#!/usr/bin/env python3
"""Compare fix-agent dry runs side by side (ITP2 3.1 / 3.6 evaluation).

Each run is an `agent_loop.py --dry-run --output-dir DIR` output. A run directory can be the
final output (DIR) or the state after one pass (DIR/after_pass1, DIR/after_pass2). Give every
run a label; runs sharing a label are repeats of the same condition and are averaged, since
the LLM is nondeterministic and one run proves little.

  python scripts/compare_dry_runs.py --batch eval_results/batches/task6/asva_exp_sast.json \\
      --run 10f-pass1=eval_results/runs/task6/10f_1/after_pass1 \\
      --run 10f-pass2=eval_results/runs/task6/10f_1/after_pass2 ...

Metrics per label and batch (all offline, no running app needed):

  fixed          files the run produced a fix for / files it should have fixed
  no-op          produced fixes that are identical to the original file
  syntax ok      produced files that still parse: .js via `node --check`, .py via Python's
                 parser, .json via json parse
  flagged kept   scanner-flagged lines (SAST findings with a line number) still present
                 verbatim in the fix -- a fix that never touched the flagged line is suspect
  broken seams   cross-file breaks the fix introduced: a method a caller uses that the fix
                 removed or renamed, or a new call into another file that doesn't exist there
                 (checked per batch, since each batch is its own PR)
  lines changed  average changed lines per produced fix (smaller = more focused)

With --rescan (needs the snyk CLI, authenticated: `snyk auth` or SNYK_TOKEN), each run's
fixed files are also put back into a copy of the app and re-scanned with Snyk Code:

  scan fixed     share of the scanner's findings in the batch's files that are gone after
                 the fix (matched by rule and file, so moved lines don't count as fixed)
  scan new       findings of a rule/file pair that the fix added (new vulnerabilities)

Lower is better for no-op, flagged kept, broken seams and scan new; higher is better for
fixed, syntax ok and scan fixed. The offline metrics are directional signals; the re-scan is
an independent scanner's verdict. Only the misuse-case suite against a deployed candidate
shows the app's behaviour.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import difflib
import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Callable, Iterator

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from gitops import config  # noqa: E402  (loads .env, for ASVA_FIX_PATH_PREFIX)
from agent.repo_context import (  # noqa: E402
    DEFAULT_EXCLUDE_DIRS,
    JavaScriptResolver,
    _tracked_names,
    app_root_for,
    build_import_index,
    resolver_for,
)

_JS = JavaScriptResolver()
_IDENT = r"[A-Za-z_$][\w$]*"
_NODE = shutil.which("node")


# ---------------------------------------------------------------------------------------
# Per-file checks
# ---------------------------------------------------------------------------------------

def _syntax_ok(path: Path) -> bool | None:
    if path.suffix == ".json":
        try:
            json.loads(path.read_text(encoding="utf-8"))
            return True
        except ValueError:
            return False
    if path.suffix in (".js", ".cjs") and _NODE:
        return subprocess.run([_NODE, "--check", str(path)], capture_output=True).returncode == 0
    if path.suffix == ".py":
        try:
            ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            return True
        except (SyntaxError, ValueError):
            return False
    return None  # no validator (or node not installed)


def _changed_lines(original: str, fixed: str) -> int:
    return sum(
        1 for line in difflib.unified_diff(original.splitlines(), fixed.splitlines(), lineterm="")
        if line[:1] in "+-" and not line.startswith(("+++", "---"))
    )


def _flagged_lines_kept(findings: list[dict], original: str, fixed: str) -> tuple[int, int]:
    """(flagged lines still present verbatim, flagged lines checked)."""
    orig_lines = original.splitlines()
    fixed_set = {line.strip() for line in fixed.splitlines()}
    kept = total = 0
    for f in findings:
        line_no = (f.get("location") or {}).get("line")
        if not isinstance(line_no, int) or not 1 <= line_no <= len(orig_lines):
            continue
        text = orig_lines[line_no - 1].strip()
        if not text:
            continue
        total += 1
        kept += text in fixed_set
    return kept, total


# ---------------------------------------------------------------------------------------
# Cross-file seam check
# ---------------------------------------------------------------------------------------

def _defines(code: str, member: str, path: str = ".js") -> bool:
    """Whether `code` (the file at `path`) still defines `member`; the check is the file's
    language resolver's (JS: methods/exports/functions; Python: def/class/assignment)."""
    resolver = resolver_for(path) or _JS
    return resolver.defines(code, member)


def _member_uses(info, bindings: tuple[str, ...]) -> set[str]:
    names = _tracked_names(info, bindings)
    if not names:
        return set()
    pat = re.compile(r"(?<![\w$])(" + "|".join(re.escape(n) for n in names) + rf")\.({_IDENT})")
    return {m.group(2) for line in info.code_lines for m in pat.finditer(line)}


def _direct_names(ref, target: str) -> set[str]:
    """Names imported directly out of the target module (`from .models import Blogs`,
    `const { BenefitsDAO } = require(...)`, `import { a } from`), which the target must keep
    defining. A Python name that is itself a submodule of the target isn't one of them."""
    if target.endswith(".py"):
        if ref.alt_spec is None or ref.spec.endswith((".", "*")):
            return set()          # `import x` / `from x import *`
        return set(ref.bindings) if ref.statement.lstrip().startswith("from") and " as " not in ref.statement else set()
    if "{" in ref.statement:
        return set(ref.bindings)
    return set()


def _code(text: str) -> str:
    return _JS.strip_comments(text)


@contextlib.contextmanager
def patched_tree(app_root: Path, files: dict[str, str] | None = None) -> Iterator[Path]:
    """A temporary copy of the app (libraries excluded) with `files` written over it."""
    with tempfile.TemporaryDirectory() as tmp:
        tree = Path(tmp) / "app"
        shutil.copytree(app_root, tree, ignore=shutil.ignore_patterns(*DEFAULT_EXCLUDE_DIRS))
        for path, content in (files or {}).items():
            (tree / path).parent.mkdir(parents=True, exist_ok=True)
            (tree / path).write_text(content, encoding="utf-8")
        yield tree


def broken_seams(app_root: Path, original: dict[str, str], fixed: dict[str, str]) -> list[str]:
    """Cross-file breaks introduced by the fixed files of ONE batch, applied together."""
    changed = {p: c for p, c in fixed.items() if c.strip() != original.get(p, "").strip()}
    if not changed:
        return []
    with patched_tree(app_root) as tree:
        before = build_import_index(tree)
    with patched_tree(app_root, changed) as tree:
        after = build_import_index(tree)

    problems: list[str] = []
    for target in changed:
        if target not in after.files:
            continue
        # 1) callers of the changed file still find what they use
        target_code_before = "\n".join(before.files[target].code_lines) if target in before.files else ""
        target_code_after = "\n".join(after.files[target].code_lines)
        for importer, ref in after.importers.get(target, []):
            for member in sorted(_member_uses(after.files[importer], ref.bindings)):
                if (_defines(target_code_before, member, target)
                        and not _defines(target_code_after, member, target)):
                    problems.append(f"{importer} uses .{member} which the fix removed from {target}")
            for name in sorted(_direct_names(ref, target)):
                if (_defines(target_code_before, name, target)
                        and not _defines(target_code_after, name, target)):
                    problems.append(f"{importer} imports {name} which the fix removed from {target}")
        # 2) new calls the changed file makes into its imports exist there
        old_uses = set()
        if target in before.files:
            for ref, _ in before.imports.get(target, []):
                old_uses |= _member_uses(before.files[target], ref.bindings)
        for ref, dep in after.imports.get(target, []):
            if not dep or dep not in after.files:
                continue
            dep_code = "\n".join(after.files[dep].code_lines)
            for member in sorted(_member_uses(after.files[target], ref.bindings) - old_uses):
                if not _defines(dep_code, member, dep):
                    problems.append(f"{target} newly calls .{member}, not defined in {dep}")
    return problems


# ---------------------------------------------------------------------------------------
# Re-scan with an independent scanner (Snyk Code)
# ---------------------------------------------------------------------------------------

ScanFn = Callable[[Path], list[dict]]


def snyk_scan(tree: Path) -> list[dict]:
    """Snyk Code scan of `tree`, normalised. Reuses the rescan test tier's helpers."""
    from tests.rescan._snyk_rescan import load_findings, run_sast_scan
    with tempfile.TemporaryDirectory() as tmp:
        sarif = Path(tmp) / "sast.sarif.json"
        run_sast_scan(tree, sarif)
        return load_findings([sarif])


def _rule_counts(findings: list[dict], paths: set[str]) -> Counter:
    return Counter(
        ((f.get("location") or {}).get("file"), (f.get("identifiers") or {}).get("rule_id"))
        for f in findings
        if f.get("finding_type") == "sast" and (f.get("location") or {}).get("file") in paths
    )


def rescan_counts(before: list[dict], after: list[dict], paths: set[str]) -> dict[str, int]:
    """Compare scanner findings in `paths` before and after, per (file, rule) -- not by line,
    because a fix shifts line numbers. Returns before / fixed / remaining / new counts."""
    b, a = _rule_counts(before, paths), _rule_counts(after, paths)
    keys = set(b) | set(a)
    return {
        "scan_before": sum(b.values()),
        "scan_fixed": sum(max(0, b[k] - a[k]) for k in keys),
        "scan_remaining": sum(min(b[k], a[k]) for k in keys),
        "scan_new": sum(max(0, a[k] - b[k]) for k in keys),
    }


# ---------------------------------------------------------------------------------------
# Run evaluation
# ---------------------------------------------------------------------------------------

def evaluate_run(
    run_dir: Path,
    batches: list[dict],
    app_root: Path,
    scan_fn: ScanFn | None = None,
    baseline: list[dict] | None = None,
) -> dict[str, dict]:
    results: dict[str, dict] = {}
    for batch in batches:
        bid = batch["batch_id"]
        m = defaultdict(int)
        originals, fixes = {}, {}
        for fe in batch.get("files_to_fix", []):
            path = fe["file"]
            orig_path = app_root / path
            if not orig_path.exists():
                continue
            original = orig_path.read_text(encoding="utf-8")
            originals[path] = original
            out = run_dir / bid / path
            m["expected"] += 1
            if not out.exists():
                continue
            fixed = out.read_text(encoding="utf-8")
            fixes[path] = fixed
            m["fixed"] += 1
            if fixed.strip() == original.strip():
                m["noop"] += 1
            ok = _syntax_ok(out)
            if ok is not None:
                m["syntax_checked"] += 1
                m["syntax_ok"] += ok
            kept, total = _flagged_lines_kept(fe.get("findings", []), original, fixed)
            m["flagged_kept"] += kept
            m["flagged_total"] += total
            m["lines_changed"] += _changed_lines(original, fixed)
        seams = broken_seams(app_root, originals, fixes)
        m["broken_seams"] = len(seams)
        if scan_fn is not None and baseline is not None:
            with patched_tree(app_root, fixes) as tree:
                m.update(rescan_counts(baseline, scan_fn(tree), set(originals)))
        results[bid] = {"metrics": dict(m), "seams": seams}
    return results


_SUM_KEYS = ("expected", "fixed", "noop", "syntax_ok", "syntax_checked", "flagged_kept",
             "flagged_total", "broken_seams", "lines_changed", "scan_before", "scan_fixed",
             "scan_remaining", "scan_new")


def compare(
    run_specs: list[tuple[str, Path]],
    batches: list[dict],
    app_root: Path,
    scan_fn: ScanFn | None = None,
) -> tuple[dict[str, list[dict]], list[dict]]:
    """Evaluate every run and average per label and batch. Returns (per-run results, rows)."""
    baseline = None
    if scan_fn is not None:
        print("Re-scan: scanning the original app for the baseline...")
        with patched_tree(app_root) as tree:
            baseline = scan_fn(tree)
    runs: dict[str, list[dict]] = defaultdict(list)
    for label, run_dir in run_specs:
        if scan_fn is not None:
            print(f"Re-scan: {label} ({run_dir})")
        runs[label].append({"dir": str(run_dir), "results": evaluate_run(
            Path(run_dir), batches, app_root, scan_fn=scan_fn, baseline=baseline)})

    rows = []
    for label, label_runs in runs.items():
        for batch in batches:
            bid = batch["batch_id"]
            ms = [r["results"][bid]["metrics"] for r in label_runs]
            s = {k: sum(m.get(k, 0) for m in ms) for k in _SUM_KEYS}
            n = len(ms)
            rows.append({
                "label": label, "batch": bid, "runs": n,
                "fixed": f"{s['fixed'] / n:.1f}/{s['expected'] / n:.0f}",
                "no-op": _pct(s["noop"], s["fixed"]),
                "syntax ok": _pct(s["syntax_ok"], s["syntax_checked"]),
                "flagged kept": _pct(s["flagged_kept"], s["flagged_total"]),
                "broken seams": f"{s['broken_seams'] / n:.1f}",
                "lines chg": f"{(s['lines_changed'] / s['fixed']) if s['fixed'] else 0:.1f}",
                "scan fixed": _pct(s["scan_fixed"], s["scan_before"]) if scan_fn else "-",
                "scan new": f"{s['scan_new'] / n:.1f}" if scan_fn else "-",
            })
    return runs, rows


COLUMNS = ("label", "batch", "runs", "fixed", "no-op", "syntax ok", "flagged kept",
           "broken seams", "lines chg", "scan fixed", "scan new")


def format_table(rows: list[dict]) -> str:
    widths = {c: max(len(c), *(len(str(r[c])) for r in rows)) for c in COLUMNS} if rows else {}
    lines = ["  ".join(c.ljust(widths[c]) for c in COLUMNS)]
    lines.append("-" * len(lines[0]))
    lines += ["  ".join(str(r[c]).ljust(widths[c]) for c in COLUMNS) for r in rows]
    return "\n".join(lines)


def format_markdown(rows: list[dict]) -> str:
    out = ["| " + " | ".join(COLUMNS) + " |", "|" + "---|" * len(COLUMNS)]
    out += ["| " + " | ".join(str(r[c]) for c in COLUMNS) + " |" for r in rows]
    return "\n".join(out)


def _pct(num: float, den: float) -> str:
    return "-" if not den else f"{100 * num / den:.0f}%"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--run", action="append", required=True, metavar="LABEL=DIR")
    parser.add_argument("--batch", action="append", required=True, metavar="FILE")
    parser.add_argument("--repo-dir", default=str(REPO_ROOT))
    parser.add_argument("--path-prefix", default=config.FIX_PATH_PREFIX,
                        help="Default: ASVA_FIX_PATH_PREFIX from the environment / .env")
    parser.add_argument("--rescan", action="store_true",
                        help="Also re-scan every run with Snyk Code (needs the snyk CLI, authenticated)")
    parser.add_argument("--json", help="Also write all per-run results to this file")
    args = parser.parse_args()

    app_root = app_root_for(args.repo_dir, args.path_prefix.strip().strip("/"))
    batches = [json.loads(Path(b).read_text(encoding="utf-8")) for b in args.batch]
    if not _NODE:
        print("[note] node not found on PATH: .js syntax checks are skipped (.py files are "
              "still checked)\n")

    specs = []
    for spec in args.run:
        label, _, run_dir = spec.partition("=")
        if not run_dir or not Path(run_dir).is_dir():
            sys.exit(f"[ERROR] --run {spec!r}: expected LABEL=DIR with an existing DIR")
        specs.append((label, Path(run_dir)))

    runs, rows = compare(specs, batches, app_root, scan_fn=snyk_scan if args.rescan else None)
    print(format_table(rows))
    print()
    for label, label_runs in runs.items():
        for r in label_runs:
            for bid, res in r["results"].items():
                for problem in res["seams"]:
                    print(f"[{label} {Path(r['dir']).name}] {bid}: {problem}")

    if args.json:
        Path(args.json).write_text(json.dumps(runs, indent=2), encoding="utf-8")
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Does the service change what the LLM does to a dependency file outside NodeGoat?

tests/eval_fixes.py measures this on NodeGoat, where the result can be run. Here the same
comparison is made on three dependency files of other stacks (tests/fixtures/other_stacks.json,
hand-built from public vulnerabilities; files in tests/fixtures/other_stack_files/):

  A  ASVA today: the scanner's targets, no context
  B  the same, with the service's context in the prompt and one instruction to respect it
  C  the service's compatible targets applied (no LLM decision; read from the upgrade data)

There is no application behind these files, so nothing is started. What is counted is the
decision: which packages are moved to a new major version (the kind of change that broke
NodeGoat), and how many findings the result resolves. The prompt is ASVA's dependency prompt
with the file name and ecosystem swapped in.

One result can be checked without an application: in requirements.txt, `requests` depends on
`urllib3`, so pip's resolver is asked (a dry run, nothing is installed) whether the two
versions the result pins can be installed together.

    python tests/eval_stack_fixes.py --env-file ../.env       # writes evaluation/other_stacks_fixes.md
    python tests/eval_stack_fixes.py --skip-llm                    # report from the saved answers
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time
from contextlib import closing
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(ROOT / "integration"))

import asva_rag_client  # noqa: E402
from app import config, net, store, versions  # noqa: E402
from app.context import ContextBuilder  # noqa: E402
from app.embed import Embedder  # noqa: E402
from app.retrieve import Retriever  # noqa: E402
from eval_fixes import RESPECT_SCA, RUNS_DIR, asva_upgrade_map, call_llm, load_env  # noqa: E402
from eval_sources import FIXTURES, OUT_DIR, to_request  # noqa: E402

FILES = {  # case in other_stacks.json -> (file in other_stack_files, what the prompt calls the ecosystem)
    "requirements.txt": ("requirements.txt", "Python (pip)"),
    "package.json (another Node app)": ("package.json", "npm"),
    "app.csproj": ("app.csproj", ".NET (NuGet)"),
}
WAYS = {"A": "ASVA today (scanner targets, no context)", "B": "Context in the prompt", "C": "Compatible targets applied"}


def prompt(file: str, ecosystem: str, content: str, upgrade_map: dict[str, str], extra: str = "", instruction: str = "") -> str:
    summary = json.dumps([{"package": p, "upgrade_to_version": v} for p, v in upgrade_map.items()], indent=2)
    return f"""You are a senior security engineer fixing vulnerable {ecosystem} dependencies.

File: {file}

Direct dependencies to upgrade (update these exact package names to the specified versions):
{summary}
{extra}
Current file content:
{content}

Instructions:
- Update ONLY the packages listed above.
- Set each package to EXACTLY the version specified in upgrade_to_version.
- If the current version is already equal to or higher than the specified version, leave it unchanged.
- Do NOT add, remove, or rename any other packages.
- Preserve all formatting and structure exactly.
{instruction}- Return ONLY the complete fixed file content. No explanation, no markdown, no code blocks.
"""


def version_in(text: str, name: str) -> str | None:
    """The version a dependency file gives a package (requirements.txt, package.json or a .csproj)."""
    n = re.escape(name)
    for pattern in (rf"(?im)^\s*{n}\s*==\s*([^\s#;]+)", rf'(?i)"{n}"\s*:\s*"[\^~]?([^"]+)"', rf'(?i)Include="{n}"\s+Version="([^"]+)"'):
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    return None


def outcome(result: str, upgrades: list[dict], findings: list[dict]) -> dict:
    moves, majors = [], []
    for u in upgrades:
        now = version_in(result, u["name"])
        if now is None:
            moves.append(f"{u['name']} MISSING")
        elif versions.parse(now) == versions.parse(u["current"]):
            moves.append(f"{u['name']} unchanged")
        elif versions.same_major(now, u["current"]):
            moves.append(f"{u['name']} {now}")
        else:
            moves.append(f"{u['name']} {now} (MAJOR)")
            majors.append(u["name"])
    resolved = 0
    for f in findings:
        name, needed = versions.split_package(f["remediation"].get("upgrade_to"))
        now = version_in(result, name)
        resolved += bool(now and versions.parse(now) and versions.parse(now) >= versions.parse(needed))
    return {"moves": moves, "majors": majors, "resolved": resolved, "findings": len(findings)}


PIP_PAIR = ("requests", "urllib3")  # requests declares which urllib3 versions it works with
_pip_cache: dict[tuple, bool] = {}


def pip_accepts(result: str) -> bool | None:
    """Can pip install the versions of PIP_PAIR that the file pins? (dry run; None if not pinned)"""
    pins = tuple(f"{name}=={version_in(result, name)}" for name in PIP_PAIR)
    if any(pin.endswith("None") for pin in pins):
        return None
    if pins not in _pip_cache:
        done = subprocess.run([sys.executable, "-m", "pip", "install", "--dry-run", "--quiet", "--disable-pip-version-check", *pins],
                              capture_output=True, text=True)
        _pip_cache[pins] = done.returncode == 0
    return _pip_cache[pins]


def apply(content: str, targets: dict[str, str]) -> str:
    """Way C: set each package to its compatible target (what the agent does with the upgrade data)."""
    for name, target in targets.items():
        n = re.escape(name)
        content = re.sub(rf"(?im)^(\s*{n}\s*==\s*)[^\s#;]+", rf"\g<1>{target}", content)
        content = re.sub(rf'(?i)("{n}"\s*:\s*")[^"]+(")', rf"\g<1>{target}\g<2>", content)
        content = re.sub(rf'(?i)(Include="{n}"\s+Version=")[^"]+(")', rf"\g<1>{target}\g<2>", content)
    return content


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--env-file", type=Path, help="File with OLLAMA_HOST, OLLAMA_API_KEY and OLLAMA_MODEL.")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--skip-llm", action="store_true", help="Report from the answers already saved.")
    args = parser.parse_args()

    entries = {e["file"]: e for e in json.loads((FIXTURES / "other_stacks.json").read_text(encoding="utf-8"))["files"]}
    cases = {}
    with closing(store.connect(config.DB_PATH)) as conn, net.make_client() as client:
        builder = ContextBuilder(Retriever.from_db(conn, Embedder()), client)
        for case, (file, ecosystem) in FILES.items():
            entry = entries[case]
            content = (FIXTURES / "other_stack_files" / file).read_text(encoding="utf-8").replace("\r\n", "\n")
            items, references, warnings, upgrades = builder.build(
                conn, [to_request(f) for f in entry["findings"]], entry["fix_type"], config.DEFAULT_MAX_CHARS)
            response = {"items": items, "references": references, "warnings": warnings, "upgrades": upgrades}
            block = asva_rag_client.prompt_block(response)
            scanner = asva_upgrade_map(entry["findings"])
            cases[case] = {"file": file, "content": content, "entry": entry, "upgrades": upgrades, "context": block,
                           "compatible": asva_rag_client.compatible_upgrades(response), "held_back": asva_rag_client.held_back(response),
                           "prompts": {"A": prompt(file, ecosystem, content, scanner),
                                       "B": prompt(file, ecosystem, content, scanner, f"\n{block}\n", RESPECT_SCA)}}

    if not args.skip_llm:
        load_env(args.env_file)
        with httpx.Client(base_url=os.environ["OLLAMA_HOST"].rstrip("/"), timeout=600,
                          headers={"Authorization": f"Bearer {os.environ['OLLAMA_API_KEY']}"}) as llm:
            for case, data in cases.items():
                for way, text in data["prompts"].items():
                    folder = RUNS_DIR / "other_stacks" / way / data["file"].replace(".", "_")
                    folder.mkdir(parents=True, exist_ok=True)
                    (folder / "prompt.txt").write_text(text, encoding="utf-8")
                    for n in range(1, args.runs + 1):
                        out = folder / f"run{n}.txt"
                        if not out.exists():
                            started = time.time()
                            out.write_text(call_llm(llm, text) + "\n", encoding="utf-8", newline="\n")
                            print(f"  {way} {data['file']} run {n}: answered in {time.time() - started:.0f}s")

    out = ["# Other stacks: what the LLM does to a dependency file with and without the service", "",
           f"Written by `tests/eval_stack_fixes.py`. Model: `{os.environ.get('OLLAMA_MODEL') or 'see the saved runs'}`, "
           f"{args.runs} runs per way. The files and findings are hand-built from public vulnerabilities "
           "(`tests/fixtures/other_stacks.json`); there is no application behind them, so nothing is started. "
           "Counted: packages moved to a new major version, and findings the result resolves.", ""]
    report = {}
    for case, data in cases.items():
        entry, upgrades = data["entry"], data["upgrades"]
        pip = data["file"] == "requirements.txt"
        out += [f"## {data['file']} ({entry['stack']}, {len(entry['findings'])} findings)", "",
                "| Way | Run | Result | Packages moved to a new major version | Findings resolved |"
                + (" pip can install the pinned requests + urllib3 |" if pip else ""), "|---|---|---|---|---|" + ("---|" if pip else "")]
        report[case] = {}
        for way in WAYS:
            if way == "C":
                results = [apply(data["content"], data["compatible"])]
            else:
                folder = RUNS_DIR / "other_stacks" / way / data["file"].replace(".", "_")
                results = [p.read_text(encoding="utf-8") for p in sorted(folder.glob("run*.txt"))] if folder.exists() else []
            rows = [{**outcome(r, upgrades, entry["findings"]), "pip": pip_accepts(r) if pip else None} for r in results]
            report[case][way] = rows
            for n, row in enumerate(rows, 1):
                run = "(no LLM decision)" if way == "C" else str(n)
                out.append(f"| {way}: {WAYS[way]} | {run} | {'; '.join(row['moves'])} | {', '.join(row['majors']) or 'none'} | "
                           f"{row['resolved']} of {row['findings']} |"
                           + ((" yes |" if row["pip"] else " **no: pip refuses (conflicting dependencies)** |") if pip else ""))
        out += ["", "Held back for a person (from the service's upgrade data):"] + [f"- {line}" for line in data["held_back"]] + [""]
    OUT_DIR.mkdir(exist_ok=True)
    (OUT_DIR / "other_stacks_fixes.md").write_text("\n".join(out) + "\n", encoding="utf-8")
    (OUT_DIR / "other_stacks_fixes.json").write_text(json.dumps(report, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print("\n".join(out[3:]))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Way B of tests/eval_fixes.py (the service's context in the prompt) with sources left out:
what does the service say then, and what does the LLM do with it? NodeGoat files only.

    python tests/eval_fixes_without.py --env-file ../.env --case package.json --without osv
    python tests/eval_fixes_without.py --env-file ../.env --case docker-compose.yml --without osv+dockerhub

Answers go to evaluation/fix_runs/B_without_<sources>/<case>/ (with the exact prompt) and are
reused on later runs. Whether a result starts is read from evaluation/app_start_checks.json; a
result not seen before is reported as not checked (run tests/eval_fixes.py with --nodegoat, or
tools/app_start_check.py, to check it).
"""

import argparse
import json
import os
import sys
import time
from contextlib import closing
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT), str(Path(__file__).parent)]

import eval_fixes as e  # noqa: E402
from app import config, net, store  # noqa: E402
from app.context import ContextBuilder  # noqa: E402
from app.embed import Embedder  # noqa: E402
from app.retrieve import Retriever  # noqa: E402


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--case", choices=sorted(e.CASES), required=True)
    parser.add_argument("--without", required=True, help="Source id(s) to leave out, joined by '+', e.g. osv+dockerhub.")
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args()

    fixture = json.loads((e.FIXTURES / "nodegoat_findings.json").read_text(encoding="utf-8"))
    entry = next(x for x in fixture["files"] if x["file"] == args.case)
    content = (e.FIXTURES / "nodegoat_files" / args.case).read_text(encoding="utf-8").replace("\r\n", "\n")
    request = [e.to_request(f) for f in entry["findings"]]
    with closing(store.connect(config.DB_PATH)) as conn, net.make_client() as client:
        builder = ContextBuilder(Retriever.from_db(conn, Embedder()), client)
        items, references, warnings, upgrades = builder.build(conn, request, entry["fix_type"], config.DEFAULT_MAX_CHARS,
                                                              exclude=args.without.split("+"))
        full = builder.build(conn, request, entry["fix_type"], config.DEFAULT_MAX_CHARS)[3]  # facts for judging any result
    response = {"items": items, "references": references, "warnings": warnings, "upgrades": upgrades}
    print(f"===== service answer without {args.without}: {sum(len(i['text']) for i in items)} prompt characters")
    for i in items:
        print(i["text"])

    prompt = e.prompts_for(args.case, content, entry["findings"], response)["B"]
    folder = e.RUNS_DIR / f"B_without_{args.without}" / args.case.replace(".", "_")
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "prompt.txt").write_text(prompt, encoding="utf-8")
    e.load_env(args.env_file)
    checks = json.loads(e.CHECKS_FILE.read_text(encoding="utf-8")) if e.CHECKS_FILE.exists() else {}
    print(f"===== LLM runs (way B prompt, without {args.without}):")
    with httpx.Client(base_url=os.environ["OLLAMA_HOST"].rstrip("/"), timeout=600,
                      headers={"Authorization": f"Bearer {os.environ['OLLAMA_API_KEY']}"}) as llm:
        for n in range(1, args.runs + 1):
            out = folder / f"run{n}{Path(args.case).suffix}"
            if not out.exists():
                started = time.time()
                out.write_text(e.call_llm(llm, prompt) + "\n", encoding="utf-8", newline="\n")
                print(f"run {n}: answered in {time.time() - started:.0f}s")
            answer = out.read_text(encoding="utf-8")
            outcome = (e.sca_outcome(content, answer, entry["findings"], full) if args.case == "package.json"
                       else e.container_outcome(content, answer, full))
            check = checks.get(e.content_key(args.case, answer))
            app = "not checked (new result)" if check is None else "starts" if check["ready"] else "DOES NOT START"
            print(f"run {n}: {outcome['summary']} | major changes: {outcome['major'] or 'none'} | app: {app}")


if __name__ == "__main__":
    main()

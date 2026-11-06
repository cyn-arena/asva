# Testing the GitOps module and secrets gate

How to verify the ASVA remediation backend works end to end.

- **GitOps module** — `gitops/` : per triage batch, create ONE fix branch
  (`fix/<batch_id>`), ONE commit per fixed file, push, and open ONE pull request. A scan
  cycle of N batches opens N PRs. ASVA **never merges** — a human does.
- **Secrets gate** — `secrets_scan/gitleaks_gate.py` : runs gitleaks on each candidate
  file *before* it is committed. If a secret is found (or gitleaks can't run), the file is
  withheld — **fail closed**.

There are four tiers of testing, fastest first. Tiers 1–2 need no GitHub access.

---

## 0. One-time setup

### a. Install gitleaks (required for the secrets gate)
Use the pinned, checksum-verified install script:

```powershell
# Windows
./scripts/install-gitleaks.ps1
```
```bash
# Linux / macOS / CI
INSTALL_DIR="$HOME/.local/bin" bash scripts/install-gitleaks.sh
```

It prints where it installed `gitleaks` (Windows default:
`%LOCALAPPDATA%\gitleaks\gitleaks.exe`). Either add that folder to PATH, or put the full
path in `.env` (next step).

### b. Configure `.env`
Copy `.env.example` to `.env` and set at least these:

```ini
GITHUB_BASE_BRANCH=<test-base-branch>          # must be a branch that EXISTS on the remote
ASVA_FIX_PATH_PREFIX=target-apps/NodeGoat      # maps app/x.js -> target-apps/NodeGoat/app/x.js
GITLEAKS_BINARY=C:\Users\<you>\AppData\Local\gitleaks\gitleaks.exe   # or just "gitleaks" if on PATH
```

`.env` is gitignored — never commit it. `gitops/config.py` auto-loads it via `load_dotenv()`.

### c. Install gh + auth (only for Tier 3, the real PR)
```powershell
winget install GitHub.cli
gh auth login          # pick GitHub.com -> HTTPS -> login
gh auth setup-git      # lets `git push` use the gh credential
```
Not needed for Tiers 1, 2, or 4 (CI provides its own token).

### Quick sanity check
```bash
python --version                       # 3.12.x
gitleaks version                       # v8.30.1   (or: run with GITLEAKS_BINARY set)
python -c "import gitops.git_gh_ops, secrets_scan.gitleaks_gate; print('imports OK')"
```

---

## 1. Tier 1 — unit self-test (no GitHub, no gh)

Proves the gate, fail-closed behaviour, traversal defense, the builders, dedupe, and the
full orchestrator (with git/gh mocked). Copy-paste and run:

```bash
# set GITLEAKS_BINARY first if gitleaks is not on PATH, e.g.:
# export GITLEAKS_BINARY="C:/Users/<you>/AppData/Local/gitleaks/gitleaks.exe"
python - <<'PY'
import sys
from secrets_scan import gitleaks_gate as G
from gitops import git_gh_ops as O

ok = True
def check(n, c):
    global ok; print(("  PASS " if c else "  FAIL ") + n); ok = ok and c

print("== secrets gate (real gitleaks) ==")
check("clean file passes", G.scan_files([{"path":"app/i.js","content":"const x=1;\n"}]).clean)
check("github PAT blocked",
      not G.scan_files([{"path":"app/c.js","content":'token="ghp_16C7e42F292c6912E7710c838347Ae178B4a"\n'}]).clean)
check("keyworded api key blocked",
      not G.scan_files([{"path":"app/c.js","content":'api_secret = "kJ8s2bQ9xVm3PqRtZw7Ly0nF4dHcUe1AbXgKsT"\n'}]).clean)

print("== fail-closed ==")
saved = G.GITLEAKS_BINARY; G.GITLEAKS_BINARY = "nope-not-a-binary"
c, r = O.gate_file("app/x.js", "hi"); check("missing binary -> withheld", c is False and "scan error" in r)
G.GITLEAKS_BINARY = saved

print("== traversal defense ==")
for fn, exc, lbl in [(O._safe_rel, O.GitOpError, "git_gh_ops"), (G._safe_rel, G.GitleaksError, "gitleaks")]:
    try: fn("../../etc/passwd"); check(lbl + " rejects ..", False)
    except exc: check(lbl + " rejects ..", True)

print("== per-batch builders ==")
b1 = {"repo_name":"asva","commit_sha":"239f8ach11","batch_id":"asva_sast_239f8ach_1","batch_type":"sast"}
b2 = {"repo_name":"asva","commit_sha":"239f8ach11","batch_id":"asva_sca_239f8ach","batch_type":"sca"}
check("branch = fix/<batch_id>", O.batch_branch_name(b1) == "fix/asva_sast_239f8ach_1")
check("two batches -> two distinct branches", O.batch_branch_name(b1) != O.batch_branch_name(b2))
try: O.batch_branch_name({"repo_name":"asva"}); check("missing batch_id rejected", False)
except O.GitOpError: check("missing batch_id rejected", True)

print("== dedupe (same path within a batch) ==")
b = {"batch_id":"b1","batch_type":"sast",
     "files_to_fix":[{"file":"app/a.js","findings":[{"identifiers":{"cwe":"CWE-79"}}]}]}
items = list(O.iter_file_fixes([{"batch": b,
    "files":[{"path":"app/a.js","content":"v1"},{"path":"app/a.js","content":"v2-IGNORED"}]}]))
check("1 item, first content kept", len(items) == 1 and items[0]["content"] == "v1")

print("== orchestrator: 2 batches -> 2 PRs (git/gh mocked) ==")
calls = []
def fake_run(cmd, repo_dir=".", input_text=None):
    calls.append(cmd)
    n = len([c for c in calls if c[:3] == ["gh","pr","create"]])
    return f"https://github.com/cyn-arena/asva/pull/{n}" if cmd[:3] == ["gh","pr","create"] else ""
O._run = fake_run
O.write_file = lambda *a, **k: None
O.revert_uncommitted = lambda *a, **k: None
cycle = [
  {"batch": {**b1, "files_to_fix":[{"file":"app/a.js","findings":[]}]},
   "files":[{"path":"app/a.js","content":"const a=1;\n"}]},
  {"batch": {**b2, "files_to_fix":[{"file":"package.json","findings":[]}]},
   "files":[{"path":"package.json","content":'{"name":"x"}\n'}]},
]
res = O.submit_scan_cycle(cycle, base_branch="<test-base-branch>")
prs = [c for c in calls if c[:3] == ["gh","pr","create"]]
branches = [c for c in calls if c[:2] == ["git","switch"]]
check("status prs_opened", res["status"] == "prs_opened")
check("2 distinct branches (one per batch)",
      {c[3] for c in branches} == {"fix/asva_sast_239f8ach_1","fix/asva_sca_239f8ach"})
check("2 PRs opened", len(prs) == 2 and len(res["pr_urls"]) == 2)
check("each PR body via stdin (--body-file -)",
      all("--body-file" in c and "--body" not in c for c in prs))
check("NO auto-merge", not any(c[:3] == ["gh","pr","merge"] for c in calls))

print("== refix retry still works within a batch ==")
calls.clear()
attempts = {"app/b.js": 0}
def test_fn(p):
    if p == "app/b.js": attempts[p] += 1; return attempts[p] >= 2   # fails once, then passes
    return True
res2 = O.submit_fix_batch({**b1, "files_to_fix":[{"file":"app/b.js","findings":[]}]},
                          [{"path":"app/b.js","content":"const b=1;\n"}],
                          base_branch="<test-base-branch>", test_fn=test_fn,
                          refix_fn=lambda p, f, n: "const b=2;\n")
check("batch PR opened after retry", res2["status"] == "pr_opened")
check("test ran twice (retried)", attempts["app/b.js"] == 2)
check("1 commit for the retried file", len([c for c in calls if "commit" in c]) == 1)

print(); print("ALL PASS" if ok else "SOME FAILED"); sys.exit(0 if ok else 1)
PY
```

**Expected:** every line `PASS`, ending `ALL PASS` (exit 0).

---

## 2. Tier 2 — dry-run CLI on the real batches (no GitHub writes)

Runs the actual entry point over the sample batches in `samples/fix_batches/*.json`, gates each file, and prints the
per-batch PR plan. Makes **no** branch, commit, push, or PR.

```bash
python -m gitops.run_batch --batch-dir samples/fix_batches
```

**Expected** (with the sample batches, all `asva @ 239f8ach` — 3 batches → 3 PRs):

```
ASVA scan cycle @ 239f8ach  ->  base <test-base-branch>  ->  1 PR per batch
  batches (3): ['asva_container_239f8ach', 'asva_sast_239f8ach_1', 'asva_sca_239f8ach']
...
[dry run] batch asva_container_239f8ach  ->  1 fix branch: fix/asva_container_239f8ach ...
  [GATE] mongo_4.0: clean  ->  commit: ...
  [dry run] would make 1 commit(s) and open ONE PR:
    title: [ASVA] container fixes for asva @ 239f8ach - 1 file(s), 17 finding(s)

[dry run] batch asva_sast_239f8ach_1  ->  1 fix branch: fix/asva_sast_239f8ach_1 ...
  [GATE] app/routes/contributions.js: clean  ->  commit: ...
  ... (3 SAST files)
  [dry run] would make 3 commit(s) and open ONE PR:
    title: [ASVA] sast fixes for asva @ 239f8ach - 3 file(s), 5 finding(s)

[dry run] batch asva_sca_239f8ach  ->  1 fix branch: fix/asva_sca_239f8ach ...
  ...
```

Key things to confirm: **one branch + one PR per batch** (`fix/<batch_id>`), **one commit
per file**, and each PR body contains "Requires human review. ASVA does NOT auto-merge."

### Optional: prove the gate actually blocks a secret
Drop a fake secret into a candidate file and confirm it is **withheld**, not committed:

```bash
python -c "from secrets_scan.gitleaks_gate import scan_files; \
r=scan_files([{'path':'x.js','content':'token=\"ghp_16C7e42F292c6912E7710c838347Ae178B4a\"'}]); \
print('clean=',r.clean,'leaks=',[l['rule'] for l in r.leaks])"
# Expected: clean= False  leaks= ['github-pat']
```

---

## 3. Tier 3 — real PR (needs gh + auth)

This creates real branches and PRs. Run it from a clean checkout on a test base branch.

```bash
python -m gitops.run_batch --batch-dir samples/fix_batches --fixed-dir <llm-output-dir> --execute
```

`--fixed-dir` is a folder containing the proposed fixed file contents at the same relative
paths as in the batches. (The agent loop, `agent/agent_loop.py`, passes contents directly instead.)

**Expected (one per batch):**
1. A new branch `fix/<batch_id>` (e.g. `fix/asva_sast_239f8ach_1`) is pushed to origin per
   batch.
2. One commit per fixed file on each branch.
3. **One PR per batch** opened into the base branch; the command prints each PR URL.
4. Every PR is **open, not merged**.

**How to review and merge (the human step):**
1. Open each printed PR URL on GitHub.
2. Read the body table (files, types, findings) and the per-file commits.
3. Confirm nothing in the "Withheld by the secrets gate" section needed to ship.
4. If good, click **Merge** yourself. ASVA will never do this for you.

Cleanup after a test run: delete each `fix/<batch_id>` branch
(`git push origin --delete fix/<batch_id>`) and close the PRs.

---

## 3b. Surfacing the smoke result on the PR

A passing local `pytest -m smoke` run doesn't help the human reviewer if they never see it.
`gitops/post_smoke_comment.py` turns a smoke run into a comment on the fix PR:

```bash
# 1. Run the smoke suite against green, producing a junit-xml report
BASE_URL=http://localhost:4001 pytest -m smoke --junit-xml=smoke.xml

# 2. Dry run — prints the comment body, posts nothing (the default)
python -m gitops.post_smoke_comment --junit-xml smoke.xml --pr <pr-number-or-url> --base-url http://localhost:4001

# 3. Actually post it (needs gh + auth, same as Tier 3)
python -m gitops.post_smoke_comment --junit-xml smoke.xml --pr <pr-number-or-url> --base-url http://localhost:4001 --execute
```

The comment reports pass/fail counts and, on failure, which checks failed and why — the
same "requires human review" framing as the fix PR body itself. Exits non-zero when any
smoke check failed, even though the comment still posts, so a CI step can fail loudly on a
failed smoke result instead of only a human noticing a green PR-comment icon.

**Not yet wired into CI**: `asva-fix.yml` opens the fix PR but doesn't stand up a live
green NodeGoat instance to smoke-test against, so there's no automatic trigger for step 1
yet. Until that exists, this is a manual (or locally-scripted) step after a fix PR opens.

---

## 4. Tier 4 — CI (GitHub Actions)

1. Push your branch.
2. GitHub → **Actions** → **ASVA Remediation (GitOps + secrets gate)** →
   **Run workflow**, choosing a `base_branch` that exists and a runner
   (`ubuntu-latest` for the dry run).
3. **Expected:** the job installs gitleaks via the script, runs the GitOps dry run on the
   committed `samples/fix_batches/`, and finishes green. No PR is auto-merged.

Full LLM-driven runs, including real fix PRs, go through the app pipelines
(`nodegoat-orchestrator.yml`, `pygoat-orchestrator.yml`).

---

## Troubleshooting / known gotchas

- **A planted `AKIAIOSFODNN7EXAMPLE` is NOT flagged.** Correct — that is AWS's published
  documentation key and gitleaks allowlists it. Test with a `ghp_...` GitHub token instead;
  it is pattern-based and always detected.
- **A bare `k="...secret..."` is NOT flagged.** gitleaks' `generic-api-key` rule needs an
  identifier keyword nearby (`key`, `secret`, `token`, `password`). Use e.g.
  `api_secret = "..."`.
- **Gate says "scan error: ... binary not found".** gitleaks isn't on PATH and
  `GITLEAKS_BINARY` isn't set/loaded. This is fail-closed working as designed — the file is
  withheld. Fix by setting `GITLEAKS_BINARY` in `.env`.
- **`git switch` / base branch error.** `GITHUB_BASE_BRANCH` must name a branch that exists
  on the remote; a typo'd or deleted branch fails the `git fetch`.
- **gitleaks env var read at import time.** If you import `secrets_scan.gitleaks_gate`
  directly (not through `gitops`), `.env` may not be loaded yet, so `GITLEAKS_BINARY` falls
  back to a bare `gitleaks` PATH lookup. Running through `python -m gitops.run_batch` avoids
  this because `gitops.config` loads `.env` first.

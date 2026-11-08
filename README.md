# ASVA

A developer-first DevSecOps workflow that integrates **code build, security scanning, automated triage, and AI-assisted remediation** into a controlled Git-based workflow.

This project demonstrates an end-to-end **shift-left security pipeline** using:
- Git branching strategy
- CI-based build and security scanning
- Automated vulnerability aggregation
- Agent-driven triage and fix generation
- Human-in-the-loop approval gates

---

## Overview

This pipeline enforces security and quality checks early in the SDLC by combining:

- Static Application Security Testing (SAST)
- Secrets detection
- Dependency vulnerability scanning (SCA)
- Container image scanning
- AI/agent-based vulnerability triage and remediation

All outputs are normalized into structured JSON artifacts for downstream automation and analytics.

The NodeGoat and PyGoat orchestrators run from scanning through generated PR candidate
checks to final Azure dashboard publishing. See [PyGoat](docs/pygoat.md) for the workflow
stages and the [dashboard data contract](docs/dashboard-data-contract-v0.1.md) for the evidence
each run uploads. All documentation is listed in [docs/](docs/README.md).

---

## Repository Layout

| Folder | Contents |
|---|---|
| `normaliser/` | Turns scanner SARIF into one ranked list of findings |
| `triage/` | Classifies findings and groups them into fix batches |
| `agent/` | Generates fixes for each batch and runs the test-first checks |
| `llm/` | LLM client |
| `memory/` | Fix history and reviewer decisions fed back into later runs |
| `secrets_scan/` | gitleaks gate run before every commit |
| `gitops/` | Branches, commits, pull requests and PR comments |
| `security_context/` | Separate retrieval (RAG) service with security guidance; has its own README |
| `schemas/` | JSON Schemas for the dashboard data contract |
| `scripts/` | CI helpers, packaging and tool installers |
| `tests/` | Unit, end-to-end and rescan test suites |
| `samples/` | Sample scan results, findings and fix batches |
| `docs/` | Documentation |
| `target-apps/` | Deliberately vulnerable third-party apps used as test targets |
| `.github/` | GitHub Actions workflows and code owners |

---

## Branching Strategy

```
main        → stable code
rel/YY.MM   → release branch; features are merged here first
feat/*      → feature development
fix/*       → one branch per fix batch, created by the ASVA agent
```

### Flow

1. Development happens on `feat/*` branches
2. CI builds and scans the branch
3. Findings are normalised and triaged into fix batches
4. The agent opens one `fix/*` PR per batch against the scanned branch
5. A human reviews each fix PR; nothing is merged automatically
6. Features are merged into the current `rel/*` branch, which is promoted to `main`

See [CONTRIBUTING.md](CONTRIBUTING.md) for pull request rules.

---

## Security Tooling

This project uses **Snyk** for unified security scanning:

- SAST (code analysis)
- SCA (dependency scanning)
- Secrets detection
- Container image scanning

All results are exported as structured JSON.

---

## CI/CD Pipeline Stages

### CI Workflow

1. Build application
2. Run Snyk SAST scan
3. Run dependency scan (SCA)
4. Run container image scan
5. Run secrets scan
6. Aggregate results into unified report
7. Push results to security data store

---

## Agent Workflow

An AI/automation agent is responsible for:

- Triage of vulnerabilities
- Severity classification and prioritization
- Generating fix proposals
- Creating `fix/*` branches
- Opening pull requests back into `feature`

### Constraints

- No auto-merge allowed
- Human approval required for all merges
- Fix scope is limited to security remediation only

---

## Human-in-the-Loop Controls

Humans remain responsible for:

- Feature branch creation
- Code review and approval
- Final merge into `main`
- Security exception handling

---

## Security Data Pipeline

All scan outputs are:

1. Normalized into JSON
2. Stored in a centralized security data lake
3. Used for:
   - vulnerability tracking
   - trend analysis
   - compliance reporting

---

## Continuous Loop

The pipeline operates as a feedback loop:
Build → Scan → Triage → Fix → Review → Merge → Repeat

---

## Local Dev Setup

### Prerequisites

Install the following before running the pipeline locally:

- **Python 3.10+** - `python --version`
- **Git** - https://git-scm.com/download/win
- **GitHub CLI (`gh`)** - https://cli.github.com
- **gitleaks v8.30.1** - secrets gate (see install instructions below)

After installing Git and gh, authenticate gh once:

```bash
gh auth login
gh auth setup-git
```

Install Python dependencies:

```bash
pip install -r requirements.txt
```

Create a `.env` file in the repo root and fill in your values:

```
OLLAMA_HOST=https://your-ollama-gateway.example.com
OLLAMA_API_KEY=your_key_here
OLLAMA_MODEL=deepseek-v4.1-flash
GITHUB_BASE_BRANCH=feat/your-development-branch
ASVA_FIX_PATH_PREFIX=target-apps/NodeGoat
```

Use an existing remote development branch as the fix PR target. The NodeGoat
orchestrator passes its scanned branch and commit to remediation automatically.
Fix branches start from that exact commit even if the target branch advances.
For older scan artifacts, remediation resolves the branch and commit from the
selected GitHub Actions run. Generated evidence stays outside the source checkout.
Local callers can set `ASVA_SCANNED_SHA` to a full scanned commit SHA; when unset,
the GitOps helpers retain their existing behaviour of using the latest target branch.

---

### Step 1 - Normaliser

Parses SARIF output from Snyk scanners and normalises all findings into a single ranked JSON file.
The example below uses the sample NodeGoat scans in `samples/scans/`.

```bash
python normaliser/normaliser.py --inputs samples/scans/nodegoat-image.sarif.json samples/scans/nodegoat-sast.sarif.json samples/scans/nodegoat-sca.sarif.json --output-dir findings
```

Output: `findings/ranked_unified_findings.json`. The root `findings/` and `fix_batches/` folders
are local output and are not committed; `samples/` has committed examples of both.

---

### Step 2 - Triage

Filters to critical/high severity fixable findings, groups them by file, and splits into batch files - one batch per finding type (SAST, SCA, container). Each batch becomes one PR.

```bash
python triage/triage.py --input findings/ranked_unified_findings.json --output findings/ranked_findings.json --batch-dir fix_batches --repo-name asva --commit-sha $(git rev-parse --short=8 HEAD)
```

On Windows PowerShell:

```powershell
python triage/triage.py --input findings/ranked_unified_findings.json --output findings/ranked_findings.json --batch-dir fix_batches --repo-name asva --commit-sha (git rev-parse --short=8 HEAD)
```

Container findings are filed against `docker-compose.yml` by default. For an app whose image is defined in another file, add `--container-file <app-relative path>` (e.g. `--container-file Dockerfile`).

Output:
- `findings/ranked_findings.json` - full classified list
- `fix_batches/{repo}_{type}_{sha}.json` - one batch file per finding type

SAST batches are capped at 10 files per batch and auto-split into `_sast_1`, `_sast_2` etc. if needed.

---

### Step 3 - Agent Loop

Reads each batch, generates fix candidates, runs the secrets and validity gates, and
submits one PR per batch via `git` and `gh`. Source-code and container fixes use the
LLM. NodeGoat's workflow defaults to scanner-directed npm dependency updates, with
the manifest and lockfile submitted together. Set the repository variable
`ASVA_SCA_FIX_MODE=llm` to restore whole-file AI dependency fixes.
Local runs default to the LLM path unless that environment variable is set to `npm`.
See [NodeGoat npm remediation](docs/nodegoat-npm-remediation.md) for configuration,
validation boundaries and rollback.

**Dry run (no git operations - writes fixes to a folder for inspection):**

```powershell
python agent/agent_loop.py --batch-dir fix_batches --repo-dir . --dry-run --output-dir dry_run_output
```

**Full run (creates branches, commits, and opens PRs):**

```powershell
python agent/agent_loop.py --batch-dir fix_batches --repo-dir .
```

**Run a single batch only:**

```powershell
python agent/agent_loop.py --batch-dir fix_batches --repo-dir . --batch fix_batches/asva_sast_239f8ach_1.json
```

Output: one `fix/*` branch and one PR per batch. The agent never merges - human review and approval required.

---

### Step 4 - Install gitleaks

The secrets gate runs before every commit. Install gitleaks v8.30.1 before running the agent.

**Option A - scripted (recommended):**

```bash
./scripts/install-gitleaks.sh      # Linux / macOS / CI / Git Bash
```
```powershell
./scripts/install-gitleaks.ps1     # Windows
```

**Option B - manual:** Download from https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1, extract `gitleaks.exe` and add to PATH. Confirm: `gitleaks version` → `8.30.1`.

If gitleaks is not on PATH, set `GITLEAKS_BINARY` in `.env` to its absolute path.

---

## GitOps (branch, commit, push, PR)

Uses native `git` and `gh`, already installed on the runners. The NodeGoat and
PyGoat fix workflows push the fix branches with `GITHUB_TOKEN` and open the PRs with
`GHPAT_ASVA_GITOPS`, a bot user's token that needs Pull requests write access. PRs opened
with `GITHUB_TOKEN` would not start other workflows, such as the PyGoat PR checks.
Everything else, including artifacts and issues, uses `GITHUB_TOKEN`.
The agent opens PRs for human review and **never merges**.

One PR per triage batch:
```
1 batch → 1 fix branch (fix/<batch_id>) → 1 commit per fixed file → 1 PR
```

To exercise the GitOps layer independently (without the LLM):

```bash
python -m gitops.run_batch --batch-dir fix_batches
```

Add `--fixed-dir <dir> --execute` to actually open PRs.

## CI configuration

The workflows read infrastructure names (LLM gateway, Azure storage, runners, deploy URL)
from repository variables. See [docs/ci-configuration.md](docs/ci-configuration.md) for the
full list of variables and secrets.

## License

To report a security problem, see [SECURITY.md](SECURITY.md).

ASVA is released under the [MIT License](LICENSE). The vulnerable test applications in
`target-apps/` are third-party projects under their own licenses; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

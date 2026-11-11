# PyGoat target application

PyGoat (Python/Django) is one of ASVA's test targets. It lives in `target-apps/PyGoat`;
its upstream source and licence are recorded in
[`target-apps/PyGoat/ASVA_IMPORT.md`](../target-apps/PyGoat/ASVA_IMPORT.md).

## ASVA files added to PyGoat

Upstream's settings and dependency pins are kept. Upstream's Dockerfile no longer builds, so ASVA
customises it in place, as with NodeGoat: one `Dockerfile` is used by the scan, PR checks, candidate
rescans and the Kubernetes deploy. ASVA adds or changes:

| File | Purpose |
|---|---|
| `target-apps/PyGoat/Dockerfile` | Customised in place: Python 3.11 on Debian Bookworm with the OS build packages the pinned dependencies need; collects static assets; app files and `/data` owned by user 1000, which the app runs as |
| `target-apps/PyGoat/compose.asva.yml` | Local and CI run: port `8001`, runs as user 1000 like the Kubernetes pod, readiness check, SQLite data volume only (code runs from the image) |
| `target-apps/PyGoat/pygoat/asva_settings.py` | SQLite path under `/data` and non-hashed static storage (upstream CSS refers to optional fonts that are missing) |
| `target-apps/PyGoat/asva/start.py` | Runs migrations and seeds challenge data at container start, then starts Gunicorn |
| `target-apps/PyGoat/.dockerignore` | Keeps local databases, environments and results out of the image |
| `scripts/pygoat-smoke.py` | Functional smoke checks, standard library only, writes JSON evidence |

The smoke checks load the login page, register a new account, log out, log back in, open a
lab page and fetch local static assets. They are functional checks, not exploit tests, and
passing them does not show that a vulnerability is fixed. Each run creates a throwaway
account, so only run them against a test instance.

## Run locally

With Docker running Linux containers, from the repository root:

```bash
docker compose -f target-apps/PyGoat/compose.asva.yml up -d --build --wait --wait-timeout 120
python scripts/pygoat-smoke.py --output asva-results/pygoat-smoke.json
docker compose -f target-apps/PyGoat/compose.asva.yml logs --tail 80
docker compose -f target-apps/PyGoat/compose.asva.yml down        # keeps the database volume
docker compose -f target-apps/PyGoat/compose.asva.yml down -v     # also deletes the database
```

The app is at `http://127.0.0.1:8001`. To use another port, set `PYGOAT_PORT` before starting
and pass the matching `--base-url` to the smoke script. Local evidence records the source as
`local-uncommitted` unless `SOURCE_SHA` is set.

## CI pipeline

`pygoat-orchestrator.yml` (**PyGoat - Pipeline**) runs the full flow. Start it from the
Actions tab; its `push` trigger also runs it for the development branch listed in the file.

```text
Validate original application (pygoat-baseline.yml)
  -> Scan (pygoat-scan.yml)  +  ASVA unit tests (pygoat-test.yml)        in parallel
  -> Normalise, triage and generate fixes; open one PR per batch (pygoat-fix.yml)
  -> For each PR, in parallel:
       validate the candidate in temporary containers (pygoat-pr-check.yml)
       rescan the candidate at its exact commit (candidate-rescan.yml)
  -> Compare the options on each PR (pr-summary.yml)
  -> Publish all available evidence to Azure, including failures (publish-dashboard-results.yml)
```

- **Baseline.** Builds the checked-out source, starts it, runs the smoke checks and removes
  the containers. A failure stops the scan and fix stages; evidence is still published.
  `pygoat-baseline.yml` also runs on its own for relevant pushes and pull requests.
- **Scan.** Snyk Code for source, Snyk Open Source for the Python dependencies inside the
  built image, and Snyk Container for that image. Snyk exit codes 0 and 1 both mean a
  completed scan (1 = findings). Other exit codes, missing reports or malformed SARIF fail
  the scan check. Needs `SNYK_TOKEN`, plus `SNYK_ORG` if set.
- **Fix.** Downloads the scan results, checks out the exact scanned commit and runs the
  normaliser, triage and agent. Container batches target `Dockerfile`, and batch names
  start with `asva-pygoat`. Each batch becomes one PR against the scanned branch. This stage
  makes paid LLM calls and creates PRs and issues.
- **Candidate checks.** Builds each PR's exact commit, starts temporary containers and runs
  the smoke checks. The result is posted as a PR comment, and failing PRs are marked as
  drafts. PyGoat has no exploit-test suite yet, so misuse tests are recorded as
  `not_available`.
- **Manual after-fix scan.** Run the orchestrator with `scan_kind=after_fix` and
  `after_fix_of=<original run ID>` once reviewed fixes are merged. It scans again without
  generating fixes and links the result to the original run.

Nothing is merged automatically: every PR waits for human review.

### Evidence

| Artifact | Contents |
|---|---|
| `pygoat-baseline-<run-id>-<attempt>` | Baseline smoke results and container logs |
| `pygoat-scan-results` | SAST, SCA and container SARIF, scan status and source metadata |
| `pygoat-fix-output` | Findings, triaged findings, fix batches, PR outcomes and diffs |
| `pygoat-validation-<batch-id>` | Candidate validation JSON and container logs |
| `pygoat-dashboard-package-<attempt>` | The exact package uploaded to Azure |

Artifacts are kept for 14 days. See the [dashboard data contract](dashboard-data-contract-v0.1.md)
for the layout of the uploaded package.

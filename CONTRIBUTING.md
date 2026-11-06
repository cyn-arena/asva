# Contributing to ASVA

## Set up

```bash
pip install -r requirements.txt -r requirements-dev.txt
```

See [Local Dev Setup](README.md#local-dev-setup) in the README for the `.env` settings and the
tools the pipeline needs (Git, GitHub CLI, gitleaks).

## Run the tests

```bash
pytest -m unit -q
```

Unit tests run offline: no network, tokens or gitleaks binary. The other markers
(`api`, `browser`, `smoke`, `rescan`) need a running target app or a Snyk token; see
`pytest.ini`.

## Branches

| Branch | Purpose |
|---|---|
| `main` | Stable code |
| `rel/YY.MM` | Release branch (e.g. `rel/26.11`); features are merged here first |
| `feat/<topic>` | Feature development, merged into the current release branch by pull request |
| `fix/<batch_id>` | Created by ASVA's agent, one per fix batch |

## Pull requests

- Open a pull request into the current release branch and describe what changed and how
  you tested it.
- Changes under `.github/` (workflows and actions) need a review from a code owner.
- ASVA never merges its own fix PRs. Every `fix/*` PR waits for a human review.

## Do not commit

- Secrets or credentials. Use `.env` locally (it is gitignored) and Actions secrets in CI.
- Infrastructure names such as hostnames, storage accounts or runner labels. Workflows read
  these from repository variables; see [docs/ci-configuration.md](docs/ci-configuration.md).
- Pipeline output. Local runs write to `findings/`, `fix_batches/`, `asva-results/`,
  `eval_results/` and `dry_run_output/`, which are gitignored. Committed examples belong in
  `samples/`.

## Reporting security issues

See [SECURITY.md](SECURITY.md).

# ASVA documentation

| Document | What it covers |
|---|---|
| [CI configuration](ci-configuration.md) | Repository variables and secrets the workflows need |
| [Unified findings format](unified-findings-format.md) | The JSON the normaliser and triage produce from scanner SARIF |
| [PyGoat](pygoat.md) | The PyGoat target: ASVA's container setup, running it locally, and its CI pipeline |
| [NodeGoat npm remediation](nodegoat-npm-remediation.md) | How NodeGoat dependency fixes are generated with npm instead of the LLM |
| [Dashboard data contract (v0.1)](dashboard-data-contract-v0.1.md) | What each run uploads to Azure for the dashboard, file by file, including candidate rescans |
| [Testing the GitOps module and secrets gate](testing-gitops-and-secrets-gate.md) | Step-by-step checks, from unit tests to real PRs |

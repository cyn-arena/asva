# CI configuration

The GitHub Actions workflows read deployment-specific values from repository (or organisation)
**variables** and credentials from **secrets**. No infrastructure names are stored in the code.
Set these under *Settings → Secrets and variables → Actions* before running the pipeline.

## Variables

| Variable | Used by | What it is |
|---|---|---|
| `ASVA_OLLAMA_HOST` | `nodegoat-fix.yml`, `pygoat-fix.yml` | Base URL of the OpenAI-compatible LLM gateway |
| `ASVA_OLLAMA_MODEL` | `pygoat-fix.yml` | Optional model override (default `deepseek-v4.1-flash`) |
| `ASVA_NODEGOAT_OLLAMA_MODEL` | `nodegoat-fix.yml` | Optional model override for NodeGoat |
| `ASVA_SCA_FIX_MODE` | `nodegoat-fix.yml` | Optional; `llm` restores whole-file AI dependency fixes (default `npm`) |
| `ASVA_AZURE_STORAGE_ACCOUNT` | fix workflows, `publish-dashboard-results.yml` | Azure Storage account for the RAG database, memory database, reviewer decisions and dashboard evidence |
| `ASVA_AZURE_STORAGE_CONTAINER` | same as above | Blob container in that account |
| `NODEGOAT_BASE_URL` | `nodegoat-orchestrator.yml`, `nodegoat-test.yml` | URL of the deployed NodeGoat used by the e2e tests |
| `NODEPORT_BLUE`, `NODEPORT_GREEN` | `nodegoat-deploy.yml`, `nodegoat-demolish.yml` | Kubernetes NodePorts for the blue and green deployments |
| `ASVA_K8S_RUNNER` | `nodegoat-deploy.yml`, `nodegoat-demolish.yml` | Label of the self-hosted runner inside the Kubernetes cluster |
| `ASVA_LLM_RUNNER` | `asva-fix.yml` (suggested for its `runner` input) | Label of the self-hosted runner that can reach a local Ollama |

## Secrets

| Secret | What it is |
|---|---|
| `AZURE_CREDENTIALS` | Service principal JSON for `azure/login` |
| `GHPAT_ASVA_GITOPS` | Bot user's GitHub token that opens, comments on and drafts the fix PRs (Pull requests write). Fix branches are pushed with `GITHUB_TOKEN` |
| `OLLAMA_API_KEY` (optional `OLLAMA_API_KEY_TEST`) | LLM gateway keys |
| `SNYK_TOKEN`, `SNYK_ORG` | Snyk account used by the scans |
| `NVD_API_KEY`, `CONTEXT7_API_KEY` | Security-context data sources |
| `OCI_REG_ID`, `OCI_REG_TOKEN` | Container registry login for image builds |

Forked pull requests never receive these secrets. The workflows that deploy, push fix branches
or write to Azure run only on push, manual dispatch or calls from other workflows, which all
require write access to the repository.

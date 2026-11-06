# Integrating the Security Context Service into ASVA

This guide covers how the ASVA fix agent gets RAG context into its LLM prompts, and RAG references
and upgrade data into its PRs. All of it is wired in: the prompt (`agent/rag_client.py`, the `rag`
field of `agent/fix_context.py`), the versions a fix may use (`agent/safe_upgrades.py`, which also
holds the same-major rule used without the RAG) and the PR text (`rag_pr_text` in
`gitops/git_gh_ops.py`). The fix workflows start the service as a container inside the fix job
(`scripts/rag-container.sh`), which keeps its database between runs in Azure Blob
(`<container>/asva-rag/rag.db`, using the job's `AZURE_CREDENTIALS` login). The database is only a cache
of public data: without it the service starts from the copy in its image. With `ASVA_TEST_FIRST=1`
(set in the fix workflows), `agent/test_first.py` builds and tests fixes before there is a PR:
dependency fixes go through the trial plan, keeping what works, and code fixes that fail go back to
the LLM with the failure, then open as a draft if they still fail. A new app gives its check through
settings (`agent/app_check.py`) and brings its own tests; no code changes are needed. Each fix job also
keeps one GitHub issue per app up to date with all its container findings and where fixes are published
(`gitops/post_container_report.py`). The sections below describe the design.

```
triage batch ──► agent_loop (per file) ──► rag_client.fetch_context ──► Security Context Service
                      │                                                      (Kubernetes)
                      ├─► prompt  += rag_client.prompt_block(response)
                      ├─► PR body += rag_client.pr_references(responses) + rag_client.pr_upgrades(responses)
                      └─► response["upgrades"]: the suggested targets as data
```

## 1. The client

`integration/asva_rag_client.py` is the client; the agent reaches it through `agent/rag_client.py`,
which turns any failure into "no context". It uses only the Python standard library, so no new
dependencies.

It is configured by one environment variable, `ASVA_RAG_URL`. If that is empty, RAG is off.

**What the client sends per finding.** Everything comes from fields ASVA's normaliser and triage
already produce:

| Service field | From the ASVA finding | Notes |
|---|---|---|
| `cve`, `cwe`, `rule_id` | `identifiers` | `cwe` is empty for dependency and container findings until the patch below is applied |
| `package`, `upgrade_to`, `fixable`, `dependency_path`, `ecosystem` | `location`, `remediation`, `dependency` | |
| `image_name`, `image_tag` | `location` | container findings; in ASVA since the container-file change of 13 Oct 2026 |
| `title`, `summary`, `description` | same names | |

**CWE for dependency and container findings.** Snyk puts the CWE of those rules in the SARIF rule
`tags`, and the normaliser only reads `properties.cwe`, so those findings arrive without one.
`integration/asva_normaliser_cwe.patch` makes `extract_cwe` fall back to the tags (with a unit test
and the format doc). Apply it in the asva repo with `git apply`, then regenerate the stored findings
and batches. On the stored NodeGoat scan it gives a CWE to 85 of 85 dependency findings and 78 of 139
container findings. Without it the service still resolves CWEs through NVD and OSV.dev, where they
know the CVE.

## 2. Prompt context in `agent/agent_loop.py`

**a) One shared way to add context.** Agree this with Mizuki (memory) and Jun Jie (repo-aware context):

```python
def build_fix_prompt(file_path, current_content, findings, fix_type, context_blocks: list[str] | None = None) -> str:
    extra = ("\n\n" + "\n\n".join(context_blocks) + "\n") if context_blocks else ""
    ...
    # in every fix_type branch, put {extra} just before "Current file content:"
```

Do the same for `build_logic_change_prompt`. Then pass `context_blocks` through `get_llm_fix`,
`build_refix_prompt`, `get_llm_refix` and `get_llm_logic_fix`. With no blocks, the prompts are
unchanged, so the existing tests still pass.

**b) Fetch per file in `process_batch`. Fail open:**

```python
from rag import rag_client

context_blocks, rag_response = [], None
if use_rag:
    try:
        rag_response = rag_client.fetch_context(findings, fix_type)
        if block := rag_client.prompt_block(rag_response):
            context_blocks.append(block)
    except rag_client.RAGUnavailableError as error:
        print(f"    [WARN] Security context unavailable ({error}); continuing without it")
batch.setdefault("security_context", {})[file_path] = rag_response
fixed_content = get_llm_fix(file_path, current_content, findings, fix_type, context_blocks)
```

For logic batches, call it once with `fix_type="logic_change"` and all the batch's findings.
`make_refix_fn` can call `fetch_context` again: the client caches responses, so retries cost nothing.

**c) Apply compatible fixes, hold the rest back.** Every entry of the response's `upgrades` has a
`compatible_target`: the version (or image line) that fixes the finding without a major version
change, or nothing when there is none. The recommended agent behaviour, measured in
`evaluation/fix_results.md`:

```python
upgrade_map = rag_client.compatible_upgrades(rag_response)   # {"marked": "0.3.18", ...}: give this to the LLM
held = rag_client.held_back(rag_response)                    # ["mongodb 2.2.36: No compatible fix: ...", ...]
```

- **Dependency files:** build the prompt's upgrade list from `upgrade_map` instead of every scanner
  target. In the 11 Oct 2026 run the agent applied all targets, including `mongodb` 2.x → 3.x, and
  the PR check found the app no longer started.
- **NodeGoat with `ASVA_SCA_FIX_MODE=npm`** (the default on `feat/expand-app-support`,
  `agent/npm_remediation.py`): no LLM prompt is involved, so the context block has no effect
  there. The upgrade plan is the place to use the service: in `generate()`, before
  `upgrade_plan(batch, manifest, lock)`, ask the service for the SCA file and pass a copy of the
  batch in which each finding's `remediation.upgrade_to` is `name@compatible_upgrades(...)[name]`,
  or `None` when the package is not in that map (`upgrade_plan` then records it as unresolved).
  Add `held_back(...)` to the dependency PR body next to the npm upgrade plan. Checked on
  23 Oct 2026 with that branch's own normaliser, triage and `upgrade_plan`: today the plan
  includes `mongodb` 2.x → 3.1.13 (SCA PR #258 failed startup with `db.dropCollection is not
  a function`); with the compatible targets it is `marked` 0.3.18, `body-parser` 1.20.4 and
  `underscore` 1.13.8, and `mongodb` is held back with the service's reason.
- **Container files:** if the image entry has a `compatible_target`, tell the LLM to use exactly
  that tag; if not, make no change. The container prompt currently asks for "the latest stable
  version"; on 11 Oct that produced `mongo:8.0` and the app no longer started.
- **What is held back** goes into the PR body or an issue (`held`), with the service's reason and,
  for images, the migration target. Nothing is silently dropped.
- **A partly fixable package** (`compatible_scope: "partial"`) is in both lists: its compatible
  target resolves the vulnerabilities that have a fix within the installed major version, so it is
  applied, and `held` says which ones stay open until the migration.
- **An image whose OS already publishes the fixes** (`status: "rebuild_may_suffice"`, no target)
  needs no file change: the note says to re-pull or rebuild the same tag.
- **Upgrades held back** are listed, in the order to try them, in the response's `trials`, with
  the companion upgrades each needs. Add `rag_client.trial_plan(rag_response)` to the PR body
  ("Upgrades to try next, one at a time"). For the plan, send the dependency file:
  `fetch_context(findings, fix_type, manifest=(name, text))`; for npm, once the npm path has written
  the candidate's lockfile, also `dev_only=npm_dev_only(lock)` and
  `copies=npm_copies(lock, names of the findings' packages)`. Nothing else in ASVA changes. A later
  pipeline step could build and test each trial and keep the ones that pass (option A).

**d) In `main()`:**
- Add a `--no-rag` flag.
- Set `use_rag = rag_client.enabled() and not args.no_rag`.
- After the LLM pre-flight, call `rag_client.check_health()` and print `RAG: ON` or `RAG: OFF (reason)`.
- Don't abort if RAG is down.
- In `--dry-run`, also write each batch's `security_context` to `<output_dir>/<batch_id>/_security_context.json`.

## 3. References and upgrade summary in the PR, in `gitops/git_gh_ops.py`

In `batch_pr_body`, after the changed-files table:

```python
from rag import rag_client
responses = (batch.get("security_context") or {}).values()
if upgrades := rag_client.pr_upgrades(*responses):
    lines += ["", upgrades]
if references := rag_client.pr_references(*responses):
    lines += ["", references]
```

`pr_upgrades` adds (dependency and container batches):
- a table per package: installed version, scanner target, compatible fix (or **none**), smallest fixed version (OSV.dev), latest version, and the reason when there is no compatible fix
- per image: the compatible fix or, if there is none, the migration target, and a table of all newer lines (version, base OS, checked CVEs resolved, support)

`pr_references` adds:
- a CVE table (CVSS, CWE, CISA KEV flag)
- the breaking changes to expect in a held-back major upgrade (the library's documentation, via Context7)
- CWE links with their OWASP Top 10 categories, MITRE's definition and two mitigations each
- OS package fixes with the distribution's wording on where they are published (e.g. "Available with Ubuntu Pro")
- advisories that stay open after the upgrade (from OSV.dev)
- links to the guidance used
- the required attribution, including the NVD notice

Jun Jie owns this file, so coordinate with him.

## 4. CI (`.github/workflows/nodegoat-fix.yml`)

The service runs inside the cluster, so the fix job must run on the in-cluster runner:

```yaml
jobs:
  fix:
    runs-on: ${{ vars.ASVA_K8S_RUNNER }}
    env:
      ASVA_RAG_URL: http://svc-security-context.dvapps.svc.cluster.local:8000   # namespace: confirm
```

ASVA needs **no API keys**; the NVD and Context7 keys live in the service's Kubernetes Secret.

## 5. Deploy the service

```bash
# once: the secret (values never go into git)
kubectl -n dvapps create secret generic security-context-secrets \
  --from-literal=NVD_API_KEY=... --from-literal=CONTEXT7_API_KEY=... \
  --from-literal=ADMIN_TOKEN=$(python -c "import secrets; print(secrets.token_urlsafe(32))")

kubectl apply -k deploy/k8s            # namespace and image are set in deploy/k8s/kustomization.yaml

# first full NVD download (otherwise it starts with the 6-hourly CronJob)
kubectl -n dvapps create job --from=cronjob/security-context-sync-frequent nvd-initial-sync
kubectl -n dvapps port-forward svc/svc-security-context 8800:8000   # then: tests/query_rag.py
```

The image is built, checked (`tools/image_check.py`) and published to GitHub's container registry
by the repo's `.github/workflows/security-context.yml`: on every push that changes
`security_context/`, weekly (from the default branch), and by hand.

The pod needs outbound HTTPS to `services.nvd.nist.gov`, `api.osv.dev`, `context7.com`,
`registry.npmjs.org`, `pypi.org`, `auth.docker.io`, `registry-1.docker.io` and `endoflife.date`, plus
`cwe.mitre.org`, `api.github.com`, `raw.githubusercontent.com` and `www.cisa.gov` for syncs. A
source the cluster may not reach, or that is not approved, is switched off with
`DISABLED_SOURCES` in `deploy/k8s/configmap.yaml` (e.g. `dockerhub,endoflife`); the service then
answers without it.

## 6. What the agent receives, per fix type

| fix_type | Prompt items (≤ 2,500 chars) | References | Upgrade data |
|---|---|---|---|
| `code_change`, `logic_change`, `config_change` | Up to 3 OWASP cheat-sheet sections (≤ 800 chars each); a compact CWE entry if none match | CWE with definition, mitigations and OWASP Top 10; OWASP links | - |
| `version_upgrade` (dependencies) | Upgrade notes: installed → target, major-version risk and whether a fix exists within the installed major version, "already at target" cases, OSV.dev cross-check | CVEs (CVSS, CWE, KEV), CWEs, OSV advisories (incl. ones still open after the upgrade), Context7's breaking-change notes for a held-back major upgrade | Per package: target, compatible fix, smallest fixed version, latest, major change, status |
| `version_upgrade` (container) | The image and its OS, whether its release line is past end of life, where the OS-package fixes are published, and the compatible line or that there is none (the list of newer lines and the migration target only with `IMAGE_LINES_IN_PROMPT=true`) | CVEs (CVSS, CWE, KEV), CWEs, each OS fix with its availability, image sources | The image: compatible fix, migration target, major change, all candidate lines |
| any, with a CVE in CISA KEV | A "known exploited, fix first" item, placed first | KEV flag on the CVE | |

The prompt block tells the LLM that the material is data, not instructions, and that the scanner
findings remain authoritative.

## 7. Comparing results with and without a source

Any request can name sources to leave out (`"exclude_sources": ["osv"]`), and `DISABLED_SOURCES`
does the same for every request. `tests/eval_sources.py` uses this to measure what each source
contributes; the results are in `evaluation/results.md`.

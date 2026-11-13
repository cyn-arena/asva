# ASVA Security Context Service

The RAG service for ASVA (ITP2 subtask 3.3). For one file's security findings, it returns:
- **prompt context:** trusted, size-limited reference material for the LLM fix prompt
- **references:** structured citations for the PR body and the UI
- **upgrade data:** for dependency and container files, what to change as data (current version,
  target, the **compatible fix** if there is one, smallest fixed version, newest version, whether
  it is a major change)

Retrieved text is **guidance, not evidence**: the scanner finding stays authoritative.

```
                  sync (CronJob / CLI)                         request (ASVA fix agent, per file)
MITRE CWE ──┐                                     ┌─► OWASP similarity search + keyword fallback (code fixes)
OWASP ──────┼─► SQLite (records, links, chunks) ◄─┼─► CWE hub: CWE ← finding / scanner rule tags / CVE (NVD, OSV)
CISA KEV ───┤        ▲ cached on demand           ├─► upgrade notes: OSV.dev cross-check, major-version risk,
NVD ────────┘        │                            │   compatible fix or none (dependencies)
   NVD · OSV.dev · Context7 ──────────────────────┤─► container image: where the OS fixes are published (OSV.dev),
   Docker Hub · endoflife.date                    │   whether a compatible line exists, end of life
                                                  └─► CISA KEV "fix first"
```

| Source | What it provides | How it's used |
|---|---|---|
| MITRE CWE | Definitions, mitigations, hierarchy, OWASP Top 10 (2021/2025) categories | Exact lookup by ID; synced |
| OWASP Cheat Sheet Series | How to fix each class of issue | MiniLM embeddings, similarity search (keyword fallback); synced |
| CISA KEV | Known-exploited CVEs | Exact lookup; synced |
| NVD | CVE description, CVSS, CWE links | Lazy (on demand, cached 7 days) or full mirror plus incremental updates |
| OSV.dev (includes the GitHub Advisory Database and the Linux distributions' security data) | Affected and fixed versions per package; per OS release, where a fix is published | On demand, cached 24 h |
| Context7 | Library docs: breaking changes for major upgrades | On demand, cached 30 days; compatibility only, not a security authority. Its notes go to the references (for the person doing a held-back upgrade), not into the prompt. For an npm package it finds the library through the repository address in the package's registry entry (a lookup key only) |
| Package registries (PyPI, npm) | Which versions of a package exist and what each one requires | On demand, cached 24 h; only for the trial plan (not the prompt); version context only |
| Docker Hub | An image's newer release lines, the version each ships and its base OS (Ubuntu, Debian, Alpine) | On demand, cached 24 h; version context only |
| endoflife.date | Whether the image's line is past end of life; release and end-of-life dates per release line (community-maintained) | On demand, cached 7 days; version context only |

The last two were added for the upgrade recommendations and are **not security authorities**. They
are separate, switchable sources: `DISABLED_SOURCES=dockerhub,endoflife` turns them off, and the
container answer then falls back to what OSV.dev and the scanner say.

**Removed: the npm registry (14 Oct 2026).** It supplied a package's newest published version for
the PR's upgrade table. That is not a security fact, it covered npm packages only, and none of it
reached the prompt; the aim is the compatible fix, not the newest version, so upgrade entries no
longer carry a `latest` field. What it gave is recorded in
[evaluation/with_without_npm.txt](evaluation/with_without_npm.txt). One lookup of the registry
remains, inside the Context7 source: an npm package's repository address, which is how the right
library is found. Without it Context7's name search picked another project for 3 of 8 packages
(`mongodb` gave the MongoDB server manual and no notes; `underscore` and `forever` gave unrelated
projects), see
[evaluation/context7_library_lookup_without_npm.txt](evaluation/context7_library_lookup_without_npm.txt).
Nothing from that lookup appears in an answer. Since 23 Oct the registries are used again for a
different, tested purpose: what each version requires, for the trial plan (source id `registries`).

## Layout

```
app/
  main.py          HTTP API (below)
  context.py       per fix type: prompt items + references + upgrade data + size budget
  retrieve.py      OWASP similarity search (tuned), keyword fallback and CWE helpers
  keyword.py       BM25 keyword search over the same cheat-sheet sections
  images.py        container images: fix status per OS release, newer lines, which one to suggest
  models.py        request/response contract (schema_version "1")
  store.py         SQLite (WAL); format-versioned so data volumes upgrade cleanly
  sources/         cwe, owasp, kev, nvd, osv, context7, registry (Docker Hub), lifecycle (endoflife.date)
  net.py           shared HTTP client: retries with backoff, rate limits
  sync.py          python -m app.sync           (download / refresh sources)
  trigger.py       python -m app.trigger kev nvd (ask a running service to sync; used by CronJobs)
  admin.py         background syncs for POST /admin/sync
tests/             offline unit tests (mocked APIs, real saved responses), the query_rag.py demo,
                   eval_sources.py (results with and without each source) and eval_fixes.py (do the
                   LLM's fixes get better: real LLM runs plus an app-start check)
tools/             build_fixture.py (demo findings), capture_fixtures.py (test data),
                   app_start_check.py / pygoat_start_check.py (does NodeGoat / PyGoat still build,
                   start and work with a candidate fix; need Docker)
evaluation/        results.md (sources) and fix_results.md (fixes), written by the two eval scripts
deploy/k8s/        Kubernetes manifests (kustomize)
integration/       drop-in ASVA client + INTEGRATION.md
```

The service lives in the asva repo as `security_context/`; run every command below from this
folder. The raw evaluation runs (`evaluation/fix_runs/`, `evaluation/logs/`: model answers,
generated files, Docker logs) are not in the repo; the result pages in `evaluation/` are.

## Run locally (Python 3.12)

```powershell
cd security_context
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements-dev.txt
copy .env.example .env                              # then add NVD_API_KEY and CONTEXT7_API_KEY
.venv\Scripts\python -m app.sync                    # ~3 min the first time; later only changes
.venv\Scripts\python -m uvicorn app.main:app --port 8800
```

In a second terminal:

```powershell
.venv\Scripts\python tests\query_rag.py                  # step-by-step demo of 5 real NodeGoat files
.venv\Scripts\python tests\query_rag.py --all             # all 7 files of the scan
.venv\Scripts\python tests\query_rag.py --only package    # a single case
.venv\Scripts\python tests\query_rag.py --app pygoat      # PyGoat's requirements.txt, with its trial plan
.venv\Scripts\python tests\query_rag.py --only research --full
.venv\Scripts\python tests\query_rag.py --only docker --compare osv   # one case with and without a source
.venv\Scripts\python tests\eval_sources.py                # every case with and without every source
.venv\Scripts\python -m pytest                            # offline unit tests
```

`query_rag.py` uses real NodeGoat findings from the ASVA pipeline, hardcoded in
`tests/fixtures/nodegoat_findings.json`, so it never reads the rest of the repo. For each file it shows:
1. the finding(s)
2. the identifiers (CWE, CVE, packages, image)
3. what the service did (search query and best similarity, keyword fallback, NVD / KEV / OSV /
   Context7 / Docker Hub lookups)
4. the prompt context
5. the upgrade data (dependency and container files)
6. the references
7. a check

The first run looks CVEs, packages and the image up online; later runs use the cache. The findings
are rebuilt from the repo with `python tools\build_fixture.py --asva ..` whenever ASVA's
stored scan results change. PyGoat's (`tests/fixtures/pygoat_findings.json`) come from a pipeline
run downloaded with `gh run download` into `data/pipeline_runs/`:
`python tools\build_fixture.py --asva .. --app pygoat --run-dir data\pipeline_runs\pygoat_<run id>`.

## Run with Docker

```powershell
docker compose up --build -d             # first build ~5 min (downloads + embeds sources)
.venv\Scripts\python tests\query_rag.py  # same demo, against the container on port 8800
docker compose exec security-context python -m app.sync --source kev   # refresh a source
docker compose down                      # stop (the data volume is kept)
.venv\Scripts\python tools\image_check.py --url http://localhost:8800   # the check CI runs on a new image
```

In CI, `.github/workflows/security-context.yml` runs the unit tests, builds the image, starts it,
runs `tools/image_check.py` and publishes it to `ghcr.io/cyn-arena/asva-security-context`.

The image contains the model and a snapshot of CWE, OWASP and KEV. On first start the snapshot
is copied into the `/data` volume. After an upgrade to an image with a newer data format, the
built-in sources are re-seeded, and cached online lookups are kept. API keys come from `.env` at
runtime, never from the image.

## Deploy to Kubernetes

The manifests are in `deploy/k8s`: a Deployment (1 replica, hardened like NodeGoat), a ClusterIP
Service, a 2 Gi PVC, a ConfigMap (`NVD_SYNC_MODE=full`), and CronJobs (KEV + NVD every 6 hours,
CWE + OWASP weekly). Steps are in [integration/INTEGRATION.md](integration/INTEGRATION.md#5-deploy-the-service).
Preview them with `kubectl kustomize deploy/k8s`.

**What is downloaded where.** MITRE CWE, the OWASP cheat sheets and CISA KEV are small and are
always held in full. NVD is the large one (every CVE ever published): locally and in CI it is
looked up per CVE when a finding needs it and cached (`NVD_SYNC_MODE=lazy`); on Kubernetes it is
mirrored in full once and then kept up to date with only the changes (`NVD_SYNC_MODE=full`).
OSV.dev, Context7, Docker Hub and endoflife.date have no bulk download: they are
asked per package or image and the answers are cached. Outbound access is needed to
`services.nvd.nist.gov`, `api.osv.dev`, `context7.com`, `registry.npmjs.org`, `pypi.org`, `auth.docker.io`,
`registry-1.docker.io` and `endoflife.date` (plus `cwe.mitre.org`, `api.github.com`,
`raw.githubusercontent.com` and `www.cisa.gov` for syncs).

## API

| Endpoint | Purpose |
|---|---|
| `POST /v1/context` | Prompt context, references and upgrade data for one file's findings |
| `GET /healthz` | Status, snapshot versions, counts, which online sources are configured or switched off |
| `GET /v1/cwe/{id}` | One CWE: entry, parents, OWASP Top 10 categories |
| `POST /admin/sync`, `GET /admin/sync` | Start or check a background sync (`Authorization: Bearer $ADMIN_TOKEN`; disabled without it) |

```json
POST /v1/context
{"fix_type": "version_upgrade", "debug": false,
 "findings": [{"finding_type": "sca", "cve": "CVE-2016-10531", "package": "marked@0.3.5",
               "ecosystem": "npm", "upgrade_to": "marked@0.3.6", "cwes": ["CWE-79"],
               "dependency_path": ["owasp-nodejs-goat@1.3.0", "marked@0.3.5"]}]}
```

Optional request fields: `cwes` (the CWE ids on the scanner's rule, for dependency and container
findings), `image_name` / `image_tag` (container findings), and `exclude_sources` (answer without
some sources, see [Source evaluation](#source-evaluation)).

The response is `{schema_version, snapshot, items, references, upgrades, warnings, debug}`.
- **`items`** go into the prompt, limited to 2,500 chars by default. Each has a `kind`: `guidance`,
  `cwe`, `upgrade_notes`, `container_summary` or `kev` (`library_notes` only with
  `LIBRARY_NOTES_IN_PROMPT=true`). Guidance items say how they were found (`matched_by`:
  `similarity` with a `score`, or `keyword`).
- **`references`** go into the PR and UI, with no size limit. Each has a `type`: `cve` (with CVSS,
  CWE and KEV flag), `cwe` (with MITRE's definition, top mitigations and OWASP Top 10), `advisory`
  (with `fixed_in`, and either `beyond_target` or, for OS packages, the distribution's
  `availability` wording), `guidance`, `library_docs` (Context7's breaking-change notes for a
  major upgrade, with their text) or `image`.
- **`upgrades`** is the upgrade advice as data, one entry per package or image:

| Field | Packages | Images |
|---|---|---|
| `current` / `target` | installed version / the scanner's target | current tag / the compatible line, else the migration target (may be empty) |
| `compatible_target` | the version that fixes it without a major version change; empty if there is none | a line of the same major version that resolves the CVEs; empty if there is none |
| `min_fixed` | smallest version OSV.dev lists as fixing the matched advisories | - |
| `major_change` | the target crosses a major version | the target is a new major version |
| `status` | `ok`, `major_change`, `already_at_target`, `osv_disagrees`, `no_target` | `newer_line_needed`, `rebuild_may_suffice`, `unknown` |
| `candidates` | - | every newer line: version, base OS, CVEs resolved there, support dates |

| fix_type | Prompt items |
|---|---|
| `code_change`, `logic_change`, `config_change` | Up to 3 OWASP sections (≤ 800 chars each), or a compact CWE entry if none match |
| `version_upgrade` (dependencies) | Upgrade notes (installed → target, major-version risk, whether a fix exists within the installed major version, "already at target", OSV.dev cross-check) |
| `version_upgrade` (container) | Where the OS-package fixes are published, the image's newer release lines, whether a compatible (same major version) line exists, the migration target, and a major-version warning |
| any, with a CVE in CISA KEV | "Known exploited, fix first", placed first |

Online sources fail softly: a 503 from NVD is retried with backoff, and anything still failing
becomes a `warning` while cached data is used. `ONLINE_LOOKUPS=false` answers from the local
database only.

### Compatible fixes first

The aim is a fix that does not break the application, so every upgrade entry says whether a
**compatible** fix exists: one that needs no major version change (semver).
- **Packages.** A scanner target in the same major version is the compatible fix. When the
  scanner's target is a major version change, the service asks OSV.dev whether every advisory
  against the installed version is also fixed within the installed major version; if so that
  version is offered instead (`compatible_scope: all`). If only some are, that version is still
  offered and the entry says which advisories stay open (`compatible_scope: partial`, e.g.
  `urllib3` 1.26.9: 1.26.19 resolves part, the rest needs 2.x). If none is, the entry says
  there is no compatible fix (for NodeGoat: `mongodb` 2.2.36, first fixed in 3.1.13) and the
  finding needs a migration, not a version bump. Versions that start with a year (`certifi`
  2023.7.22) are not read as major versions.
- **Images.** A newer line of the same major version whose base OS resolves the CVEs is the
  compatible fix. If the only lines that resolve them are new major versions, the entry says so
  and names a migration target.

ASVA is meant to apply `compatible_target` automatically and hold the rest back for a person
(`integration/asva_rag_client.py`: `compatible_upgrades`, `held_back`).
[evaluation/fix_results.md](evaluation/fix_results.md) compares that with what the agent does
today, using the real LLM and the PR check's "does the app still start" test.

**Compared with a plain rule.** The policy above is, at its core, the rule "never apply a major
version upgrade automatically", plus data. The fix evaluations test that rule on its own, without
the service (way D). On NodeGoat it makes the same choices as the service (6 of 26 findings really
fixed, counted in the lockfile; the app starts); on PyGoat the service adds certifi (a year-based version) and partial upgrades of
urllib3 and Werkzeug (25 against 23 findings). Most of the measured benefit therefore comes from
the rule; the service adds those cases, the reasons for holding an upgrade back, and the PR facts.
The rule also holds back major upgrades that would have worked: on PyGoat, 4 of the 7 held back
(Pillow, sqlparse, oauthlib, Werkzeug) build and pass the smoke test on their own and would fix 23
more findings, including a known-exploited CVE; the other 3 fail on dependency conflicts
([evaluation/pygoat_fix_results.md](evaluation/pygoat_fix_results.md)). Neither the rule nor the
service can tell which major upgrade works; only a build and test can, so held-back upgrades are
best tried one at a time as separate candidates.

### Trial plan: held-back upgrades to try next

The response's `trials` list (`app/trials.py`) is the answer to "the rule holds back upgrades that
would have worked": every upgrade held back from the safe candidate, in the order to try it on its
own, with what it fixes and what else it needs. It is data for the PR and a reviewer (or a later
pipeline step that builds and tests each one); none of it goes into the LLM prompt.

| `kind` | What it is |
|---|---|
| `lockfile_refresh` | npm: `npm update` of vulnerable packages whose fixed version is inside the range the package above them allows (no major change) |
| `parent_upgrade` | npm: a newer version of the direct dependency a vulnerable copy comes in through (newest in the same major version; `major_upgrade` for the newest of all) |
| `major_upgrade` | the scanner's target for a package held back as a major version change |
| `image_major` | the image's migration target |

Order: changes without a major version change first, then known-exploited fixes, then most findings
fixed, then fewest companion upgrades; development-tool-only trials last. `also_needs` lists the
**companion upgrades** read from the package registries: a requirement of the target that the
app's pinned version does not meet (cryptography 49.0.0 requires cffi>=2.0.0), and a pinned package
whose own requirement excludes the target (requests 2.28.2 requires urllib3<1.27), each with the
smallest version that resolves it.

The request carries the dependency file in `manifest` (`file`, `content`); for npm also
`dev_only` and `copies`, read from the lockfile by `asva_rag_client.npm_dev_only` and `npm_copies`.
`copies` lists every installed copy of the vulnerable packages with the chain that brings it in:
npm installs several copies (express 4.16.4 keeps its own qs 6.5.2), and the scanner reports only
one path per finding, so a plan built from that one path predicted fixes that did not happen.
Results of following the plan: [evaluation/trial_results.md](evaluation/trial_results.md).

### Container images

For a container file the service combines three things, each from a source:
1. **Where the fixes are.** The scanner's rule id names the image's OS release
   (`SNYK-UBUNTU2004-…` → Ubuntu 20.04, `SNYK-DEBIAN12-…`, `SNYK-ALPINE318-…`). OSV.dev republishes
   the security data of Ubuntu, Debian and Alpine per CVE, with a fix per release; Ubuntu's also
   has an availability text. When the only fix for the image's release is listed under Ubuntu Pro,
   the answer quotes that text ("Available with Ubuntu Pro (Infra-only): …"). The service never
   says a fix is paid on its own judgement: without OSV.dev it only repeats what the scanner offers.
   When the release already publishes every fix and the image line is still maintained, the answer
   says no tag change is needed (re-pull or rebuild) and puts no other tag forward.
2. **What else exists.** Docker Hub gives the image's newer release lines, the version each tag
   ships and its base OS, read from the image metadata without pulling anything. Lines are tags
   written like the current one (`16` → `18`, `20`; `4.4` → `5.0`; `3.11-slim` → `3.12-slim`). A
   release that OSV.dev lists with a standard fix, or lists for other CVEs but not as affected by
   this one, counts as resolving the CVE.
3. **Which line to move to.** A line of the same major version that resolves the CVEs is the
   compatible fix. Otherwise endoflife.date's release and end-of-life dates decide the migration
   target (`app/images.py`): among lines that are at least 90 days old, supported for at least 180
   more days and whose base OS resolves every checked CVE, the nearest one, i.e. the smallest
   version jump. The line supported longest is named as well. Without support dates no migration
   target is named. endoflife.date also says when the image's own line is past end of life.

**What goes into the prompt.** The image, its OS, whether its line is past end of life, where the
fixes stand, and the compatible fix or that there is none. The list of newer lines, their support
dates and the migration target are for the person who plans a held-back migration: they are in the
upgrade data (`upgrades[].candidates`, `target`, `note`) and the PR summary, and in the prompt only
with `IMAGE_LINES_IN_PROMPT=true`. The LLM cannot act on them: with no compatible fix the file is
left as it is.

When only new major versions resolve the findings, the answer says there is no compatible fix and
that moving is a migration, not a drop-in change. It cannot say which lines the application's
client library supports: the request does not carry that. (Measured for NodeGoat: it starts on
mongo 4.4 and 5.0 and on nothing newer, see evaluation/fix_results.md.)
Limits: release lines only for images on Docker Hub with a version in the tag; fix data only for
Ubuntu, Debian and Alpine; an image built from a Dockerfile is only covered if the request names
its base image; the same line on a newer base OS (`22-bookworm` → `22-trixie`) is not considered.

## Configuration

See `.env.example`. You need `NVD_API_KEY` and `CONTEXT7_API_KEY`; `ADMIN_TOKEN` enables the sync
endpoint. On Kubernetes, settings come from `deploy/k8s/configmap.yaml` and the
`security-context-secrets` Secret. `DISABLED_SOURCES` switches sources off for every request.

## Retrieval tuning

The OWASP ranking was tuned on NodeGoat's 11 distinct own-code SAST issues. "Effective" was
measured as the share of key fix advice present in the returned text, such as allowlists for SSRF.

| Setting | Key advice covered | Avg size |
|---|---|---|
| Untuned (6,000-char budget) | 77% | ~3,700 chars |
| Tuned similarity search | 86% | ~1,900 chars |
| Tuned, with the keyword fallback (current) | 95% | ~1,900 chars |

What made the difference:
- a "how to prevent and fix" query
- down-weighting intro/overview headings
- returning whole sections
- boosting a cheat sheet whose title clearly matches the finding (this fixed SSRF being confused with CSRF)
- down-weighting cheat sheets for other languages

Larger budgets added no coverage. A relative score cut-off, sentence-level compression and a
two-stage search were tried and rejected.

**Keyword fallback.** When a finding's best similarity score is below 0.62, the two lowest-ranked
sections are replaced by the two best keyword (BM25) matches, so the answer does not grow
(`KEYWORD_FALLBACK_BELOW`, `KEYWORD_FALLBACK_RESULTS`; 0 results switches it off). Keyword search
alone is clearly worse than similarity search (62% against 86%), and one keyword result was not
enough. The gain comes from one issue type, "Use of Hardcoded Passwords", and the threshold rests
on 12 issue types, so treat it as provisional. Light stemming was tried and did not help.

**Outside NodeGoat.** The figures above are for NodeGoat's own 12 issue types, which the ranking was
partly tuned on. On 46 issue types in six languages that it was never tuned on
(`tests/eval_search.py`, [evaluation/search_results.md](evaluation/search_results.md)), judged by
whether the returned sections come from the right cheat sheet: at least one section is right for
83% of the issue types, the first section for 65%, and 60% of all returned sections are on topic.
Three sections remain the right amount (1: 65%, 2: 74%, 3: 83%, 4: 83%). The keyword fallback
helps a little there (80% → 83%; three issue types better, two worse), and the CWE name in the
query, which helps on NodeGoat's set, does not help there (first section right 65% with it, 72%
without). Hardcoded secrets and passwords are the weak spot: the search does not reach the Secrets
Management cheat sheet for them.

Context7 notes are filtered to the versions being crossed. For example, `CHANGES_7.0.0.md` is
dropped for a 2.x → 3.x upgrade.

**Context7's notes are not in the prompt.** They describe the breaking changes of a major
upgrade, and a major upgrade is held back for a person, so they go to the references
(`library_docs`, with their text) for whoever carries out the migration. The reasons and the
measurements are in [evaluation/context7_note.md](evaluation/context7_note.md).
`LIBRARY_NOTES_IN_PROMPT=true` puts them back into the prompt.

**Known gaps:**
- "Hardcoded Non-Cryptographic Secret" (CWE-547) reaches the Secrets Management cheat sheet by
  neither search; the keyword fallback fixes only the hardcoded-password case (CWE-798). A
  finding → CWE → OWASP cheat-sheet link as a soft boost is the planned fix.
- Fix data for OS packages covers Ubuntu, Debian and Alpine images.

## Fix evaluation

`tests/eval_fixes.py` asks the real LLM for the dependency fix and the container fix in three ways
(ASVA's prompts today; the same with this service's context in the prompt; the agent applying
the service's compatible targets), several times each, and puts every distinct result through
the PR check's test: build, start, `/login` must answer within 90 seconds
(`tools/app_start_check.py`). Results: [evaluation/fix_results.md](evaluation/fix_results.md).

```powershell
.venv\Scripts\python tests\eval_fixes.py --env-file ..\.env --nodegoat ..\target-apps\NodeGoat
```

It needs an LLM endpoint (`OLLAMA_HOST`, `OLLAMA_API_KEY`, `OLLAMA_MODEL`), Docker and the NodeGoat
app folder; the app is copied to a temporary folder and never changed.

`tests/eval_fixes_without.py` repeats way B for one NodeGoat file with sources left out
(`--without osv`), to see what the LLM does without them.

`tests/eval_pygoat_fixes.py` makes the same comparison for PyGoat's `requirements.txt`, with
ASVA's Python prompt and the pipeline's PyGoat model, and checks every distinct result the way the
pipeline's candidate validation does: build the image from PyGoat's `Dockerfile`, start it, and run
ASVA's smoke test `scripts/pygoat-smoke.py` (`tools/pygoat_start_check.py`). The file the
pipeline's own agent produced in the run the findings come from is checked too. Results:
[evaluation/pygoat_fix_results.md](evaluation/pygoat_fix_results.md).

```powershell
.venv\Scripts\python tests\eval_pygoat_fixes.py --env-file ..\.env --pygoat ..\target-apps\PyGoat --smoke ..\scripts\pygoat-smoke.py
```

## Evaluations beyond NodeGoat

NodeGoat and PyGoat are the applications the pipeline runs today, and a source that adds nothing
there may matter for another one. Three scripts test the service on other stacks, without an application:

| Script | What it tests | Result |
|---|---|---|
| `tests/eval_stacks.py` | The with-and-without-each-source comparison on 10 hand-built cases: Java, Python, .NET, Go and Ruby dependencies, Debian- and Alpine-based images, an image from another registry | [evaluation/other_stacks.md](evaluation/other_stacks.md) |
| `tests/eval_search.py` | The OWASP guidance search on 46 issue types in six languages that it was never tuned on, each with the cheat sheets that are the right place to look | [evaluation/search_results.md](evaluation/search_results.md) |
| `tests/eval_stack_fixes.py` | What the real LLM does to a `requirements.txt`, a `package.json` and a `.csproj` with and without the service (packages moved to a new major version, findings resolved) | [evaluation/other_stacks_fixes.md](evaluation/other_stacks_fixes.md) |

The cases are built from well-known public vulnerabilities, not from a scan, and say so in their
files. They show what the sources return and what the LLM decides; only the NodeGoat evaluation
shows whether a fix runs.

## Source evaluation

`tests/eval_sources.py` runs every demo file with all sources and again without each one
(`exclude_sources`), and writes [evaluation/results.md](evaluation/results.md): per source the
facts the answer loses without it and the prompt characters it costs, per file where the prompt
characters go, the three search methods compared, and coverage against the amount of OWASP text.
It is how to decide which sources earn their place and which could be dropped to keep the prompt
short. To see one case with and without one source, step by step:

```powershell
.venv\Scripts\python tests\query_rag.py --only docker --compare osv
```

## Attribution

- MITRE CWE: [CWE Terms of Use](https://cwe.mitre.org/about/termsofuse.html).
- OWASP Cheat Sheet Series: [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/).
- NVD: this product uses the NVD API but is not endorsed or certified by the NVD.
- OSV.dev: licence per upstream source; GitHub advisories are CC BY 4.0.
- CISA KEV: public U.S. Government data.
- Context7: library documentation; see each source link.
- Docker Hub: image metadata.
- endoflife.date: MIT, community-maintained.

Every item and reference carries its source and URL.

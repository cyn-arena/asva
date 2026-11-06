# Evaluation results: index

Everything measured for the Security Context Service, in one place. Each result file says how it
was produced; the scripts are in `tests/` and can be rerun (see the main README). Last updated
23 Oct 2026.

## Headline numbers

Dependency fixes, the service's focus. "App works" means it was built and started with Docker and
passed the pipeline's own check (NodeGoat: `/login` answers; PyGoat: ASVA's smoke test).

| App, data | ASVA today | Plain rule, no service | Service: compatible upgrades | Service: following the trial plan (option B) |
|---|---|---|---|---|
| PyGoat, pipeline run 39018400376 (62 findings) | 62 targeted, **app does not build** | 23, does not build (PyYAML 5.4) | 25, does not build (PyYAML 5.4); 22 with PyYAML held at 5.1, app works | **57, app works** |
| NodeGoat, pipeline run 39018400601 (26 findings in the app) | 9, **app does not start** | 6, app works | 6, app works | **12 as Snyk counts, 19 no longer in the Linux image; app works** |

- Counting for npm: a finding is fixed only when every installed copy is fixed. This count matched
  Snyk's own rescan of the pipeline's dependency PR exactly (9 = 9). Counting what is written in
  package.json overstates it (an earlier "9 of 26" was corrected to 6).
- NodeGoat has 32 more findings in development tools that the production image never installs.
- What is left on NodeGoat: 3 need a MongoDB driver migration (code changes, which also blocks the
  7 container findings); 4 need npm overrides (untested).
- What is left on PyGoat: django-allauth 65 does not build with the app's other pins (2 findings);
  PyYAML 5.4 cannot be built on Python 3.11 (3 findings; 6.0.2 works).

Container (NodeGoat `mongo:4.4`): ASVA today breaks the app 3 of 3 runs; the service keeps the tag
(no compatible fix exists; the newer lines need the driver migration), 0 of 7 fixed.

Code fixes (SAST): the OWASP guidance is not shown to improve fixes; not tested with the LLM yet.

## Files

| File | What it shows | Data |
|---|---|---|
| [trial_results.md](trial_results.md) | Option B: every held-back upgrade tried on its own, then the passing ones together | PyGoat run 39018400376; NodeGoat run 39018400601 |
| [trial_results_scanner_paths.md](trial_results_scanner_paths.md) | The first version of the NodeGoat plan, built from the scanner's one path per finding: 8 of 26 (why the plan now reads every copy in the lockfile) | NodeGoat run 39018400601 |
| [pygoat_fix_results.md](pygoat_fix_results.md) | PyGoat, four ways with the real LLM (ASVA today, plain rule, context in the prompt, compatible targets), PyYAML variants, each held-back major upgrade on its own | PyGoat run 39018400376 |
| [nodegoat_lockfile.md](nodegoat_lockfile.md) | NodeGoat findings really fixed (every copy in the lockfile), checked against Snyk's rescan; app vs development tools | NodeGoat run 39018400601 |
| [fix_results.md](fix_results.md) | NodeGoat package.json and docker-compose.yml, four ways with the real LLM, app-start check | NodeGoat scan of 11 Oct (rel/26.11) |
| [with_without_osv_package_llm.txt](with_without_osv_package_llm.txt) | NodeGoat package.json, context without OSV.dev: the LLM applied the breaking mongodb upgrade in 1 of 3 runs | NodeGoat scan of 11 Oct |
| [results.md](results.md) | Every source with and without, NodeGoat: facts lost and prompt characters per source; OWASP search quality on NodeGoat's issue types | NodeGoat scan of 11 Oct |
| [search_results.md](search_results.md) | OWASP search on 46 issue types in six languages it was not tuned on: right cheat sheet 83%, first section 65%, on topic 60% | hand-written issue list |
| [other_stacks.md](other_stacks.md) | Every source with and without on 10 hand-built cases (Java, Python, .NET, Go, Ruby, Debian/Alpine images) | hand-built from public CVEs |
| [other_stacks_fixes.md](other_stacks_fixes.md) | The LLM on a requirements.txt, package.json and .csproj with and without the service | hand-built from public CVEs |
| [context7_note.md](context7_note.md) | Why Context7's notes are references, not prompt text | NodeGoat |
| [context7_library_lookup_without_npm.txt](context7_library_lookup_without_npm.txt) | Context7's name search finds the wrong library for 3 of 8 npm packages | NodeGoat packages |
| `with_without_*.txt` | One source left out, step by step (13–14 Oct) | NodeGoat scan of 11 Oct |
| `app_start_checks.json` | Every build and start check, by file content (reused instead of rebuilding) | all |
| `*.json` next to a `.md` | The same results as data | |

## Folders

| Folder | Contents |
|---|---|
| `fix_runs/trials/pygoat/`, `fix_runs/trials/nodegoat/` | The exact dependency files of every trial in trial_results.md |
| `fix_runs/trials/nodegoat_scanner_paths/` | Trial files of the first NodeGoat plan (its refresh and combined files were replaced by the second plan's) |
| `fix_runs/pygoat/` | PyGoat: each way's prompt and LLM answers (A, B, C, D), the pipeline's own answer (A_ci, PR #276), `diagnostic/` variants, `major_trials/` |
| `fix_runs/A`, `B`, `C`, `D` | NodeGoat (11 Oct data): each way's prompt and LLM answers |
| `fix_runs/nodegoat_lockfile/` | NodeGoat lockfiles: unchanged, the pipeline's PR #274, the service's compatible upgrades, with refresh |
| `fix_runs/other_stacks/` | LLM answers for the hand-built dependency files |
| `fix_runs/B_without_*`, `B_with_context7_notes`, `B_2026-10-13`, `_superseded_*` | Earlier and single-source runs, kept for the record |
| `logs/` | Console output of the longer runs |
| `../data/pipeline_runs/` | The downloaded pipeline runs the PyGoat and NodeGoat data come from (not in git) |

No pull requests were created by any of these tests: the PyGoat and NodeGoat data come from runs
the pipeline had already made (PRs #272 to #276 are from those runs), and every trial was built
locally in a temporary copy of the app.

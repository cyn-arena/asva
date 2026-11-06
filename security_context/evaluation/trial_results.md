# Option B: following the trial plan

Written by `tests/eval_trials.py`. Each trial is applied on its own to the safe candidate, with the companion upgrades the plan names; then all trials that passed are applied together. Files in `evaluation/fix_runs/trials/`.

## PyGoat (requirements.txt)

### Upgrades to try next, one at a time

These are not in this PR. Each could fix more, but needs a build and the app's tests first.

| # | Try | Fixes | Also needs | Notes |
|---|---|---|---|---|
| 1 | `pillow` 9.4.0 → 12.3.0 | 13 (known exploited: CVE-2023-4863) | - | Major version change (9.x → 12.x): try it on its own and run the app's tests; the code may need changes. |
| 2 | `sqlparse` 0.3.1 → 0.6.0 | 8 | - | Major version change (0.3.x → 0.6.x): try it on its own and run the app's tests; the code may need changes. |
| 3 | `cryptography` 39.0.1 → 49.0.0 | 6 | `cffi` 1.15.1 → 2.0.0 (cryptography 49.0.0 requires cffi>=2.0.0) | Major version change (39.x → 49.x): try it on its own and run the app's tests; the code may need changes. |
| 4 | `urllib3` 1.26.9 → 2.8.0 | 6 | `requests` 2.28.2 → 2.30.0 (requests 2.28.2 requires urllib3<1.27,>=1.21.1) | Major version change (1.x → 2.x): try it on its own and run the app's tests; the code may need changes. |
| 5 | `werkzeug` 2.1.2 → 3.0.3 | 2 | - | Major version change (2.x → 3.x): try it on its own and run the app's tests; the code may need changes. |
| 6 | `django-allauth` 0.52.0 → 65.13.0 | 2 | `asgiref` 3.6.0 → 3.8.1 (django-allauth 65.13.0 requires asgiref>=3.8.1) | Major version change (0.52.x → 65.x): try it on its own and run the app's tests; the code may need changes. |
| 7 | `oauthlib` 3.2.2 → 4.0.0 | 1 | - | Major version change (3.x → 4.x): try it on its own and run the app's tests; the code may need changes. |

| Candidate | Findings fixed | App |
|---|---|---|
| safe candidate (the service's compatible upgrades) | 22 of 62 | builds, starts, smoke test passes |
| 1. pillow 9.4.0 → 12.3.0 | 35 of 62 | builds, starts, smoke test passes |
| 2. sqlparse 0.3.1 → 0.6.0 | 30 of 62 | builds, starts, smoke test passes |
| 3. cryptography 39.0.1 → 49.0.0 (with cffi → 2.0.0) | 28 of 62 | builds, starts, smoke test passes |
| 4. urllib3 1.26.9 → 2.8.0 (with requests → 2.30.0) | 28 of 62 | builds, starts, smoke test passes |
| 5. werkzeug 2.1.2 → 3.0.3 | 23 of 62 | builds, starts, smoke test passes |
| 6. django-allauth 0.52.0 → 65.13.0 (with asgiref → 3.8.1) | 24 of 62 | **does not build**: the image did not build: pip failed at MarkupSafe>=2.1.1: ------ |
| 7. oauthlib 3.2.2 → 4.0.0 | 23 of 62 | builds, starts, smoke test passes |
| **all passing trials together** | 57 of 62 | builds, starts, smoke test passes |

## NodeGoat (package.json and package-lock.json)

### Upgrades to try next, one at a time

These are not in this PR. Each could fix more, but needs a build and the app's tests first.

| # | Try | Fixes | Also needs | Notes |
|---|---|---|---|---|
| 1 | `npm update brace-expansion ini minimatch mixin-deep proxy-addr` | 11 | - | `npm update brace-expansion ini minimatch mixin-deep proxy-addr`: newer versions within the ranges the packages above them allow, which include the fixed versions. Not a major version change. |
| 2 | `express` 4.16.4 → 4.22.3 | 3 | - | Same major version; brings fixed copies of body-parser, qs. |
| 3 | `express` 4.16.4 → 5.3.0 | 4 | - | Major version change; brings fixed copies of body-parser, proxy-addr, qs. |
| 4 | `mongodb` 2.2.36 → 3.1.13 | 3 | - | Major version change (2.x → 3.x): try it on its own and run the app's tests; the code may need changes. |
| 5 | `forever` 2.0.0 → 4.0.3 | 0 | - | Major version change; brings fixed copies of ini (other copies of them remain, so no finding is fully fixed by this alone). |
| 6 | `npm update y18n` | 1 | - | development tools only, not in the running app. `npm update y18n`: newer versions within the ranges the packages above them allow, which include the fixed versions. Not a major version change. |
| 7 | `async` 2.6.1 → 2.6.4 | 0 | - | development tools only, not in the running app. Same major version; brings fixed copies of lodash (other copies of them remain, so no finding is fully fixed by this alone). |
| 8 | `grunt` 1.0.3 → 1.6.3 | 0 | - | development tools only, not in the running app. Same major version; brings fixed copies of js-yaml (other copies of them remain, so no finding is fully fixed by this alone). |
| 9 | `async` 2.6.1 → 3.2.6 | 0 | - | development tools only, not in the running app. Major version change; brings fixed copies of lodash (other copies of them remain, so no finding is fully fixed by this alone). |
| 10 | `cypress` 3.3.1 → 16.2.0 | 0 | - | development tools only, not in the running app. Major version change; brings fixed copies of cross-spawn, json-schema (other copies of them remain, so no finding is fully fixed by this alone). |
| 11 | `grunt-retire` 0.3.12 → 1.0.9 | 0 | - | development tools only, not in the running app. Major version change; brings fixed copies of hawk (other copies of them remain, so no finding is fully fixed by this alone). |
| 12 | `nodemon` 1.19.1 → 3.1.14 | 0 | - | development tools only, not in the running app. Major version change; brings fixed copies of cross-spawn (other copies of them remain, so no finding is fully fixed by this alone). |
| 13 | `zaproxy` 0.2.0 → 1.0.1 | 0 | - | development tools only, not in the running app. Major version change; brings fixed copies of hawk, lodash (other copies of them remain, so no finding is fully fixed by this alone). |

| Candidate | Fixed, of 26 in the app (as Snyk counts) | Not in the Linux image any more | Fixed, in dev tools only | App |
|---|---|---|---|---|
| safe candidate (the service's compatible upgrades) | 6 | 6 | 0 | starts |
| 1. lockfile refresh | 8 | 15 | 0 | starts |
| 2. express 4.16.4 → 4.22.3 | 10 | 10 | 0 | starts |
| 3. express 4.16.4 → 5.3.0 | 10 | 10 | 0 | **does not start**: npm ERR!     /home/node/.npm/_logs/2026-10-22T19_15_46_897Z-debug.log |
| 4. mongodb 2.2.36 → 3.1.13 | 9 | 9 | 0 | **does not start**: (node:9) UnhandledPromiseRejectionWarning: TypeError: db.dropCollection is not a function |
| 5. forever 2.0.0 → 4.0.3 | 7 | 7 | 0 | starts |
| 6. lockfile refresh [dev tools] | 7 | 7 | 0 | starts |
| 7. async 2.6.1 → 2.6.4 [dev tools] | 6 | 6 | 0 | starts |
| 8. grunt 1.0.3 → 1.6.3 [dev tools] | 6 | 6 | 0 | starts |
| 9. async 2.6.1 → 3.2.6 [dev tools] | 6 | 6 | 0 | starts |
| 10. cypress 3.3.1 → 16.2.0 [dev tools] | 6 | 6 | 0 | starts |
| 11. grunt-retire 0.3.12 → 1.0.9 [dev tools] | 6 | 6 | 0 | starts |
| 12. nodemon 1.19.1 → 3.1.14 [dev tools] | 6 | 6 | 0 | starts |
| 13. zaproxy 0.2.0 → 1.0.1 [dev tools] | 6 | 6 | 0 | starts |
| **all passing trials together** | 12 | 19 | 0 | starts |

"Not in the Linux image any more" also counts findings whose only vulnerable copies are bundled inside an optional package that is not installed on Linux (fsevents, a macOS file watcher). npm cannot update those copies, and Snyk still reports them from the lockfile. Checked in the built image of the last row: node_modules/fsevents does not exist.


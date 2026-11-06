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
| 1 | `npm update brace-expansion ini minimatch mixin-deep proxy-addr set-value` | 13 | - | `npm update brace-expansion ini minimatch mixin-deep proxy-addr set-value`: newer versions within the ranges the packages above them allow, which include the fixed versions. Not a major version change. |
| 2 | `body-parser` 1.18.3 → 1.20.9 | 2 | - | Same major version; brings fixed copies of qs. |
| 3 | `mongodb` 2.2.36 → 3.1.13 | 3 | - | Major version change (2.x → 3.x): try it on its own and run the app's tests; the code may need changes. |
| 4 | `grunt-contrib-nodeunit` 1.0.0 → 2.0.0 | 22 | - | development tools only, not in the running app. Major version change (1.x → 2.x): try it on its own and run the app's tests; the code may need changes. |
| 5 | `coveralls` 2.13.3 → 3.0.0 | 9 | - | development tools only, not in the running app. Major version change (2.x → 3.x): try it on its own and run the app's tests; the code may need changes. |
| 6 | `cross-spawn` 4.0.2 → 6.0.6 | 1 | - | development tools only, not in the running app. Major version change (4.x → 6.x): try it on its own and run the app's tests; the code may need changes. |

| Candidate | Fixed, of 26 in the app | Fixed, in dev tools only | App |
|---|---|---|---|
| safe candidate (the service's compatible upgrades) | 6 | 0 | starts |
| 1. lockfile refresh | 8 | 0 | starts |
| 2. body-parser 1.18.3 → 1.20.9 | 6 | 0 | starts |
| 3. mongodb 2.2.36 → 3.1.13 | 9 | 0 | **does not start**: (node:9) UnhandledPromiseRejectionWarning: TypeError: db.dropCollection is not a function |
| 4. grunt-contrib-nodeunit 1.0.0 → 2.0.0 [dev tools] | 6 | 0 | starts |
| 5. coveralls 2.13.3 → 3.0.0 [dev tools] | 6 | 0 | starts |
| 6. cross-spawn 4.0.2 → 6.0.6 [dev tools] | 6 | 0 | starts |
| **all passing trials together** | 8 | 0 | starts |


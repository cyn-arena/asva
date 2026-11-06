# NodeGoat: which dependency findings are really fixed

Written by `tests/eval_nodegoat_lockfile.py` from `tests/fixtures/nodegoat_branch_findings.json` (58 findings). Fixed = every installed copy of the vulnerable package in the lockfile is at or above the version OSV.dev lists as fixing it. App = the PR check's test (build, start, /login answers within 90 s).

26 of the 58 findings are in packages the production image installs (NodeGoat's Dockerfile runs `npm install --production`); the other 32 are in development tools only.

| Candidate | Fixed, of 26 in the app | Fixed, of 32 in dev tools | Still vulnerable | Fixed version unknown | App |
|---|---:|---:|---:|---:|---|
| unchanged | 0 | 0 | 47 | 11 | starts |
| pipeline (PR, every scanner target) | 9 | 0 | 38 | 11 | **does not start**: (node:9) UnhandledPromiseRejectionWarning: TypeError: db.dropCollection is not a function |
| rag (compatible upgrades) | 6 | 0 | 41 | 11 | starts |
| rag + refreshed indirect packages | 9 | 0 | 38 | 11 | starts |

**Check against Snyk.** The pipeline rescanned its own dependency PR with Snyk. Findings gone according to Snyk: 9; according to the count above: 9; in both: 9.
Only Snyk: none. Only this count: none.

## In the app, still vulnerable after 'rag + refreshed indirect packages'

- brace-expansion CVE-2026-14257: needs 1.1.17, has 1.1.11, 1.1.21
- brace-expansion CVE-2026-69152: needs 1.1.18, has 1.1.11, 1.1.21
- qs CVE-2025-15284: needs 6.14.1, has 6.14.2, 6.5.2
- brace-expansion CVE-2026-13149: needs 1.1.16, has 1.1.11, 1.1.21
- minimatch CVE-2026-27903: needs 3.1.3, has 3.0.4, 3.0.8
- brace-expansion CVE-2026-33750: needs 1.1.13, has 1.1.11, 1.1.21
- minimatch CVE-2026-26996: needs 3.1.3, has 3.0.4, 3.0.8
- brace-expansion CVE-2026-102278: needs 1.1.20, has 1.1.11, 1.1.21
- brace-expansion CVE-2026-102276: needs 1.1.19, has 1.1.11, 1.1.21
- body-parser CVE-2024-45590: needs 1.20.3, has 1.18.3, 1.20.4
- bson CVE-2020-7610: needs 1.1.4, has 1.0.9
- bson CVE-2019-2391: needs 1.1.4, has 1.0.9
- mongodb SNYK-JS-MONGODB-473855: needs 3.1.13, has 2.2.36
- qs CVE-2022-24999: needs 6.5.3, has 6.14.2, 6.5.2
- ini CVE-2020-7788: needs 1.3.6, has 1.3.5, 1.3.8
- set-value CVE-2021-23440: needs 2.0.1, has 0.4.3, 2.0.1
- set-value CVE-2019-10747: needs 2.0.1, has 0.4.3, 2.0.1

In the app, fixed version unknown: none

Indirect packages refreshed: babel-traverse, brace-expansion, bson, cross-spawn, handlebars, hawk, ini, is-my-json-valid, js-yaml, json-schema, jsonpointer, lodash, minimatch, mixin-deep, proxy-addr, qs, semver, set-value, y18n

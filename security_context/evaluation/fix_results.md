# Fix evaluation: do fixes get better with the service's context?

Generated 2026-10-22 18:48 UTC by `tests/eval_fixes.py`. LLM: unknown, 3 runs per way. Findings: NodeGoat scan 20261013062102 @ 765e1949. "Starts" is ASVA's PR-check test: the app is built and started with Docker Compose and must answer on /login within 90 seconds.

## Summary

| File | A: ASVA today (no context) | D: Plain rule, no service (same major version only) | B: Context in the prompt | C: Upgrade data applied |
|---|---|---|---|---|
| package.json | **breaks the app** (3 of 3 runs) | app starts, 9 of 26 findings fixed (3 of 3 runs) | app starts, 9 of 26 findings fixed (3 of 3 runs) | app starts, 9 of 26 findings fixed (3 of 3 runs) |
| docker-compose.yml | **breaks the app** (3 of 3 runs) | app starts, 0 of 7 findings fixed (3 of 3 runs) | no change made, app unaffected (3 of 3 runs) | no change made, app unaffected (3 of 3 runs) |

## package.json (dependencies, 26 findings)

| Way | What the fix did (runs) | Major version changes applied | App after the fix | Findings resolved by a fix that works |
|---|---|---|---|---|
| A: ASVA today (no context) | body-parser 1.20.4, express 4.16.4, marked 0.3.18, mongodb 3.1.13, underscore 1.13.8 (3 of 3) | mongodb | **does not start** | 0 of 26 |
| D: Plain rule, no service (same major version only) | body-parser 1.20.4, marked 0.3.18, underscore 1.13.8 (3 of 3) | none | starts (4.0 s) | 9 of 26 |
| B: Context in the prompt | body-parser 1.20.4, marked 0.3.18, underscore 1.13.8 (2 of 3) | none | starts (4.0 s) | 9 of 26 |
| B: Context in the prompt | body-parser 1.20.4, express 4.16.4, marked 0.3.18, underscore 1.13.8 (1 of 3) | none | starts (4.0 s) | 9 of 26 |
| C: Upgrade data applied | body-parser 1.20.4, marked 0.3.18, underscore 1.13.8 (3 of 3) | none | starts (4.0 s) | 9 of 26 |

Why way A (body-parser 1.20.4, express 4.16.4, marked 0.3.18, mongodb 3.1.13, underscore 1.13.8) does not start: `(node:11) UnhandledPromiseRejectionWarning: TypeError: db.dropCollection is not a function`

Versions installed in the built app, read from the running container:
- A (3 of 3 runs): mongodb@3.1.13, body-parser@1.20.4, express@4.16.4, marked@0.3.18, underscore@1.13.8
- D (3 of 3 runs): mongodb@2.2.36, body-parser@1.20.4, express@4.16.4, marked@0.3.18, underscore@1.13.8
- B (3 of 3 runs): mongodb@2.2.36, body-parser@1.20.4, express@4.16.4, marked@0.3.18, underscore@1.13.8
- C (3 of 3 runs): mongodb@2.2.36, body-parser@1.20.4, express@4.16.4, marked@0.3.18, underscore@1.13.8

Note: "findings resolved" here means the scanner's target is set in package.json. npm also keeps nested copies (express 4.16.4 brings its own body-parser 1.18.3 and qs 6.5.2), so fewer are really gone: measured against the lockfile, and matching Snyk's own rescan, way C fixes 6 of these 26, and 9 with a lockfile refresh. See [nodegoat_lockfile.md](nodegoat_lockfile.md).

14 of the 26 findings cannot be fixed by any version bump in package.json: their package is already at the scanner's target, and the vulnerable packages come in through it (lockfile refresh or npm overrides needed).

Held back for a person in way C, with the service's reason:
- express 4.16.4: express is already at 4.16.4; the vulnerable packages (proxy-addr) come in through it and need a lockfile refresh or npm overrides.
- forever 2.0.0: forever is already at 2.0.0; the vulnerable packages (brace-expansion, ini, minimatch, mixin-deep, set-value, y18n) come in through it and need a lockfile refresh or npm overrides.
- mongodb 2.2.36: No compatible fix: OSV.dev lists no fix within 2.x (first fixed in 3.1.13). This needs a migration to 3.x, not a version bump.

## docker-compose.yml (container image, 7 findings)

| Way | What the fix did (runs) | Major version changes applied | App after the fix | Findings resolved by a fix that works |
|---|---|---|---|---|
| A: ASVA today (no context) | mongo:latest (unpinned tag; 9.0.4 today) (2 of 3) | mongo | **does not start** | 0 of 7 |
| A: ASVA today (no context) | mongo:8.0 (1 of 3) | mongo | **does not start** | 0 of 7 |
| D: Plain rule, no service (same major version only) | mongo:4.4.29 (3 of 3) | none | starts (4.2 s) | 0 of 7 |
| B: Context in the prompt | mongo:4.4 (unchanged) (3 of 3) | none | starts (4.1 s) | 0 of 7 (nothing applied, nothing broken) |
| C: Upgrade data applied | mongo:4.4 (unchanged) (3 of 3) | none | starts (4.1 s) | 0 of 7 (nothing applied, nothing broken) |

Why way A (mongo:latest (unpinned tag; 9.0.4 today)) does not start: `Unsupported OP_QUERY command: insert. The client driver may require an upgrade. For more details see https://dochub.mongodb.org/core/legacy-opcode-removal`

Why way A (mongo:8.0) does not start: `Unsupported OP_QUERY command: insert. The client driver may require an upgrade. For more details see https://dochub.mongodb.org/core/legacy-opcode-removal`

Held back for a person in way C, with the service's reason:
- mongo 4.4: No compatible fix: no 4.x line of mongo resolves these findings. Migration target: mongo:7.0.

## Which MongoDB lines the app starts on (as it is, driver 2.2.36)

| Image | App | Checked CVEs resolved by its base OS | Support |
|---|---|---|---|
| mongo:5.0 | starts (4.0 s) | 0 of 7 | past end of life |
| mongo:6.0 | **does not start** | 7 of 7 | past end of life |
| mongo:7.0 | **does not start** | 7 of 7 | until 2027-08-31 |
| mongo:8.0 | **does not start** | 7 of 7 | until 2029-10-31 |

The lines it does not start on fail with: `Unsupported OP_QUERY command: insert. The client driver may require an upgrade. For more details see https://dochub.mongodb.org/core/legacy-opcode-removal`


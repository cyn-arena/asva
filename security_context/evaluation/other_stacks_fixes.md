# Other stacks: what the LLM does to a dependency file with and without the service

Written by `tests/eval_stack_fixes.py`. Model: `glm-5.3-flash`, 3 runs per way. The files and findings are hand-built from public vulnerabilities (`tests/fixtures/other_stacks.json`); there is no application behind them, so nothing is started. Counted: packages moved to a new major version, and findings the result resolves.

## requirements.txt (Python / pip, 6 findings)

| Way | Run | Result | Packages moved to a new major version | Findings resolved | pip can install the pinned requests + urllib3 |
|---|---|---|---|---|---|
| A: ASVA today (scanner targets, no context) | 1 | certifi 2023.7.22; django 4.2.15; pillow 10.0.1 (MAJOR); pyyaml 5.4; urllib3 2.6.0 (MAJOR) | pillow, urllib3 | 6 of 6 | **no: pip refuses (conflicting dependencies)** |
| A: ASVA today (scanner targets, no context) | 2 | certifi 2023.7.22; django 4.2.15; pillow 10.0.1 (MAJOR); pyyaml 5.4; urllib3 2.6.0 (MAJOR) | pillow, urllib3 | 6 of 6 | **no: pip refuses (conflicting dependencies)** |
| A: ASVA today (scanner targets, no context) | 3 | certifi 2023.7.22; django 4.2.15; pillow 10.0.1 (MAJOR); pyyaml 5.4; urllib3 2.6.0 (MAJOR) | pillow, urllib3 | 6 of 6 | **no: pip refuses (conflicting dependencies)** |
| B: Context in the prompt | 1 | certifi 2023.7.22; django 4.2.15; pillow unchanged; pyyaml 5.4; urllib3 1.26.19 | none | 4 of 6 | yes |
| B: Context in the prompt | 2 | certifi 2023.7.22; django 4.2.15; pillow unchanged; pyyaml 5.4; urllib3 1.26.19 | none | 4 of 6 | yes |
| B: Context in the prompt | 3 | certifi 2023.7.22; django 4.2.15; pillow unchanged; pyyaml 5.4; urllib3 1.26.19 | none | 4 of 6 | yes |
| C: Compatible targets applied | (no LLM decision) | certifi 2023.7.22; django 4.2.15; pillow unchanged; pyyaml 5.4; urllib3 1.26.19 | none | 4 of 6 | yes |

Held back for a person (from the service's upgrade data):
- pillow 9.4.0: No compatible fix: OSV.dev lists no fix within 9.x (fixed in 10.0.0 to 13.0.0). This needs a migration to 10.x, not a version bump. CVE-2023-4863 is known to be exploited (CISA KEV) and is not fixed by a compatible bump: plan this migration urgently.
- urllib3 1.26.9: Partly fixable without a major version change: urllib3 1.26.19 resolves 3 of the 10 vulnerabilities OSV.dev lists for urllib3 1.26.9. No fix within 1.x for CVE-2025-50181, CVE-2025-66418, CVE-2025-66471 +4 more (fixed in 2.5.0 to 2.8.0): those need a migration to 2.x.

## package.json (JavaScript / npm, 3 findings)

| Way | Run | Result | Packages moved to a new major version | Findings resolved |
|---|---|---|---|---|
| A: ASVA today (scanner targets, no context) | 1 | express 4.19.2; jsonwebtoken 9.0.0 (MAJOR); lodash 4.17.21 | jsonwebtoken | 3 of 3 |
| A: ASVA today (scanner targets, no context) | 2 | express 4.19.2; jsonwebtoken 9.0.0 (MAJOR); lodash 4.17.21 | jsonwebtoken | 3 of 3 |
| A: ASVA today (scanner targets, no context) | 3 | express 4.19.2; jsonwebtoken 9.0.0 (MAJOR); lodash 4.17.21 | jsonwebtoken | 3 of 3 |
| B: Context in the prompt | 1 | express 4.19.2; jsonwebtoken unchanged; lodash 4.17.21 | none | 2 of 3 |
| B: Context in the prompt | 2 | express 4.19.2; jsonwebtoken unchanged; lodash 4.17.21 | none | 2 of 3 |
| B: Context in the prompt | 3 | express 4.19.2; jsonwebtoken unchanged; lodash 4.17.21 | none | 2 of 3 |
| C: Compatible targets applied | (no LLM decision) | express 4.19.2; jsonwebtoken unchanged; lodash 4.17.21 | none | 2 of 3 |

Held back for a person (from the service's upgrade data):
- jsonwebtoken 8.5.1: No compatible fix: OSV.dev lists no fix within 8.x (first fixed in 9.0.0). This needs a migration to 9.x, not a version bump.

## app.csproj (.NET / NuGet, 1 findings)

| Way | Run | Result | Packages moved to a new major version | Findings resolved |
|---|---|---|---|---|
| A: ASVA today (scanner targets, no context) | 1 | Newtonsoft.Json 13.0.1 (MAJOR) | Newtonsoft.Json | 1 of 1 |
| A: ASVA today (scanner targets, no context) | 2 | Newtonsoft.Json 13.0.1 (MAJOR) | Newtonsoft.Json | 1 of 1 |
| A: ASVA today (scanner targets, no context) | 3 | Newtonsoft.Json 13.0.1 (MAJOR) | Newtonsoft.Json | 1 of 1 |
| B: Context in the prompt | 1 | Newtonsoft.Json unchanged | none | 0 of 1 |
| B: Context in the prompt | 2 | Newtonsoft.Json unchanged | none | 0 of 1 |
| B: Context in the prompt | 3 | Newtonsoft.Json unchanged | none | 0 of 1 |
| C: Compatible targets applied | (no LLM decision) | Newtonsoft.Json unchanged | none | 0 of 1 |

Held back for a person (from the service's upgrade data):
- Newtonsoft.Json 12.0.3: No compatible fix: OSV.dev lists no fix within 12.x (first fixed in 13.0.1). This needs a migration to 13.x, not a version bump.


# Other stacks: does each source have anything to give outside NodeGoat?

Generated 2026-10-13 19:55 UTC by `tests/eval_stacks.py` from `tests/fixtures/other_stacks.json`: 10 cases, 21 findings.

**What these cases are.** Hand-built from well-known public vulnerabilities (real CVE ids, packages and versions) in the shape ASVA sends. No application was scanned and none exists to run the fixes against, so this shows what the sources return, not whether a fix works. The NodeGoat results, which are measured on a real scan and a running app, are in `results.md` and `fix_results.md`.

## 1. What each source gives across these cases

| Source | Cases where the prompt loses a fact without it | Cases where prompt or PR data loses a fact | Cases where the outcome changes | Prompt characters it adds |
|---|---:|---:|---:|---:|
| OWASP Cheat Sheet Series | 0 of 10 | 0 of 10 | 0 of 10 | 0 |
| MITRE CWE | 0 of 10 | 9 of 10 | 0 of 10 | 0 |
| Keyword fallback | 0 of 10 | 0 of 10 | 0 of 10 | 0 |
| NVD | 0 of 10 | 10 of 10 | 0 of 10 | 0 |
| CISA KEV | 4 of 10 | 4 of 10 | 2 of 10 | 911 |
| OSV.dev | 10 of 10 | 10 of 10 | 10 of 10 | 1,255 |
| Context7 | 0 of 10 | 2 of 10 | 0 of 10 | 0 |
| Docker Hub | 2 of 10 | 3 of 10 | 3 of 10 | 746 |
| endoflife.date | 2 of 10 | 3 of 10 | 3 of 10 | 130 |

"Outcome" is the decision the service reports: per package the compatible fix and whether to apply or hold back; per image the fix status, the lines and the target.

What is lost without each source:

- **OWASP Cheat Sheet Series**: nothing in these cases
- **MITRE CWE**: weakness defined (references); weakness defined, with OWASP Top 10 category (references)
- **Keyword fallback**: nothing in these cases
- **NVD**: CVSS score and severity per CVE (references)
- **CISA KEV**: prompt: warning that a CVE is known to be exploited; known-exploited flag per CVE (references)
- **OSV.dev**: prompt: for a major upgrade: the compatible fix, or that there is none; prompt: independent confirmation of the scanner's target; prompt: that no tag change is needed (the OS publishes the fixes); prompt: where the fixes stand for the image's OS release; advisories that stay open after the upgrade (references); compatible target for a major upgrade (upgrades); fix version per CVE for the OS release (references); reason a major upgrade is held back (upgrades); smallest fixed version per package (upgrades)
- **Context7**: breaking-change notes for a major upgrade (references)
- **Docker Hub**: prompt: compatible fix, or that there is none; prompt: that the image's release line is past end of life; migration target (upgrades); newer release lines with their base OS (upgrades); support dates per release line (upgrades)
- **endoflife.date**: prompt: that the image's release line is past end of life; migration target (upgrades); support dates per release line (upgrades)

## 2. Case by case

### pom.xml (Java / Maven, 4 finding(s), 930 prompt characters)

With all sources:

- org.apache.commons:commons-text 1.9 → scanner 1.10.0 | compatible fix 1.10.0 | apply | smallest fixed 1.10.0
- org.apache.logging.log4j:log4j-core 2.14.1 → scanner 2.16.0 | compatible fix 2.16.0 | apply | smallest fixed 2.16.0
- org.springframework:spring-beans 5.3.17 → scanner 5.3.18 | compatible fix 5.3.18 | apply | smallest fixed 5.3.18
- known exploited (CISA KEV): CVE-2021-44228, CVE-2021-45046, CVE-2022-22965

Without MITRE CWE (+0 characters): loses weakness defined, with OWASP Top 10 category (references).

Without NVD (+0 characters): loses CVSS score and severity per CVE (references).

Without CISA KEV (-410 characters): loses prompt: warning that a CVE is known to be exploited; known-exploited flag per CVE (references). Outcome becomes: 

Without OSV.dev (-115 characters): loses prompt: independent confirmation of the scanner's target; smallest fixed version per package (upgrades); advisories that stay open after the upgrade (references). Outcome becomes: org.apache.commons:commons-text 1.9 → scanner 1.10.0 | compatible fix 1.10.0 | apply / org.apache.logging.log4j:log4j-core 2.14.1 → scanner 2.16.0 | compatible fix 2.16.0 | apply / org.springframework:spring-beans 5.3.17 → scanner 5.3.18 | compatible fix 5.3.18 | apply

### requirements.txt (Python / pip, 6 finding(s), 1,168 prompt characters)

With all sources:

- certifi 2022.12.7 → scanner 2023.7.22 | compatible fix 2023.7.22 | apply | smallest fixed 2023.7.22
- django 4.2 → scanner 4.2.15 | compatible fix 4.2.15 | apply | smallest fixed 4.2.15
- pillow 9.4.0 → scanner 10.0.1 | compatible fix none | major change: held back | smallest fixed 10.0.1
- pyyaml 5.1 → scanner 5.4 | compatible fix 5.4 | apply | smallest fixed 5.4
- urllib3 1.26.9 → scanner 2.6.0 | compatible fix 1.26.19 (partial) | major change: apply the compatible fix | smallest fixed 2.6.0
- known exploited (CISA KEV): CVE-2023-4863

Without MITRE CWE (+0 characters): loses weakness defined, with OWASP Top 10 category (references).

Without NVD (+0 characters): loses CVSS score and severity per CVE (references).

Without CISA KEV (-179 characters): loses prompt: warning that a CVE is known to be exploited; known-exploited flag per CVE (references). Outcome becomes: 

Without OSV.dev (-483 characters): loses prompt: independent confirmation of the scanner's target; prompt: for a major upgrade: the compatible fix, or that there is none; smallest fixed version per package (upgrades); compatible target for a major upgrade (upgrades); reason a major upgrade is held back (upgrades); advisories that stay open after the upgrade (references). Outcome becomes: certifi 2022.12.7 → scanner 2023.7.22 | compatible fix 2023.7.22 | apply / django 4.2 → scanner 4.2.15 | compatible fix 4.2.15 | apply / pillow 9.4.0 → scanner 10.0.1 | compatible fix none | major change: held back / pyyaml 5.1 → scanner 5.4 | compatible fix 5.4 | apply / urllib3 1.26.9 → scanner 2.6.0 | compatible fix none | major change: held back

Without Context7 (+0 characters): loses breaking-change notes for a major upgrade (references).

### package.json (another Node app) (JavaScript / npm, 3 finding(s), 550 prompt characters)

With all sources:

- express 4.17.1 → scanner 4.19.2 | compatible fix 4.19.2 | apply | smallest fixed 4.19.2
- jsonwebtoken 8.5.1 → scanner 9.0.0 | compatible fix none | major change: held back | smallest fixed 9.0.0
- lodash 4.17.15 → scanner 4.17.21 | compatible fix 4.17.21 | apply (OSV.dev disagrees with the target) | smallest fixed 4.18.0

Without MITRE CWE (+0 characters): loses weakness defined, with OWASP Top 10 category (references).

Without NVD (+0 characters): loses CVSS score and severity per CVE (references).

Without OSV.dev (-235 characters): loses prompt: independent confirmation of the scanner's target; prompt: for a major upgrade: the compatible fix, or that there is none; smallest fixed version per package (upgrades); reason a major upgrade is held back (upgrades); advisories that stay open after the upgrade (references). Outcome becomes: express 4.17.1 → scanner 4.19.2 | compatible fix 4.19.2 | apply / jsonwebtoken 8.5.1 → scanner 9.0.0 | compatible fix none | major change: held back / lodash 4.17.15 → scanner 4.17.21 | compatible fix 4.17.21 | apply

Without Context7 (+0 characters): loses breaking-change notes for a major upgrade (references).

### app.csproj (.NET / NuGet, 1 finding(s), 353 prompt characters)

With all sources:

- Newtonsoft.Json 12.0.3 → scanner 13.0.1 | compatible fix none | major change: held back | smallest fixed 13.0.1

Without MITRE CWE (+0 characters): loses weakness defined, with OWASP Top 10 category (references).

Without NVD (+0 characters): loses CVSS score and severity per CVE (references).

Without OSV.dev (-160 characters): loses prompt: independent confirmation of the scanner's target; prompt: for a major upgrade: the compatible fix, or that there is none; smallest fixed version per package (upgrades); reason a major upgrade is held back (upgrades). Outcome becomes: Newtonsoft.Json 12.0.3 → scanner 13.0.1 | compatible fix none | major change: held back

### go.mod (Go modules, 1 finding(s), 197 prompt characters)

With all sources:

- github.com/gin-gonic/gin 1.6.3 → scanner 1.7.7 | compatible fix 1.7.7 | apply | smallest fixed 1.7.7

Without MITRE CWE (+0 characters): loses weakness defined, with OWASP Top 10 category (references).

Without NVD (+0 characters): loses CVSS score and severity per CVE (references).

Without OSV.dev (-57 characters): loses prompt: independent confirmation of the scanner's target; smallest fixed version per package (upgrades); advisories that stay open after the upgrade (references). Outcome becomes: github.com/gin-gonic/gin 1.6.3 → scanner 1.7.7 | compatible fix 1.7.7 | apply

### Gemfile (Ruby / RubyGems, 1 finding(s), 159 prompt characters)

With all sources:

- rack 2.2.3 → scanner 2.2.3.1 | compatible fix 2.2.3.1 | apply | smallest fixed 2.2.3.1

Without NVD (+0 characters): loses CVSS score and severity per CVE (references).

Without OSV.dev (-57 characters): loses prompt: independent confirmation of the scanner's target; smallest fixed version per package (upgrades); advisories that stay open after the upgrade (references). Outcome becomes: rack 2.2.3 → scanner 2.2.3.1 | compatible fix 2.2.3.1 | apply

### docker-compose.yml (node:18, Debian 12) (Node runtime image on Debian, 2 finding(s), 722 prompt characters)

With all sources:

- image node:18 on Debian 12; status newer_line_needed
- fix data for this OS release: 1 in the standard repositories, 0 subscription-only, 1 without a fix, of 2 checked
- line 19: 19.9.0 on unknown OS, CVEs not checked, past end of life
- line 20: 20.20.2 on Debian 12, 1/2 CVEs resolved, past end of life
- line 21: 21.7.3 on unknown OS, CVEs not checked, past end of life
- line 22: 22.23.3 on Debian 12, 1/2 CVEs resolved, supported until 2027-04-30
- line 23: 23.11.1 on Debian 12, 1/2 CVEs resolved, past end of life
- line 24: 24.21.0 on Debian 12, 1/2 CVEs resolved, supported until 2028-04-30
- line 25: 25.9.0 on Debian 12, 1/2 CVEs resolved, past end of life
- line 26: 26.11.1 on Debian 13, 2/2 CVEs resolved, supported until 2029-04-30
- compatible fix: none; migration target: 26

Without MITRE CWE (+0 characters): loses weakness defined (references).

Without NVD (+0 characters): loses CVSS score and severity per CVE (references).

Without CISA KEV (-161 characters): loses prompt: warning that a CVE is known to be exploited; known-exploited flag per CVE (references).

Without OSV.dev (+40 characters): loses prompt: where the fixes stand for the image's OS release; fix version per CVE for the OS release (references). Outcome becomes: fix data for this OS release: none found / line 20: 20.20.2 on Debian 12, CVEs not checked, past end of life / line 22: 22.23.3 on Debian 12, CVEs not checked, supported until 2027-04-30 / line 23: 23.11.1 on Debian 12, CVEs not checked, past end of life / line 24: 24.21.0 on Debian 12, CVEs not checked, supported until 2028-04-30 / line 25: 25.9.0 on Debian 12, CVEs not checked, past end of life / line 26: 26.11.1 on Debian 13, CVEs not checked, supported until 2029-04-30

Without Docker Hub (-339 characters): loses prompt: that the image's release line is past end of life; prompt: compatible fix, or that there is none; support dates per release line (upgrades); newer release lines with their base OS (upgrades); migration target (upgrades). Outcome becomes: compatible fix: none; migration target: None

Without endoflife.date (-63 characters): loses prompt: that the image's release line is past end of life; support dates per release line (upgrades); migration target (upgrades). Outcome becomes: line 19: 19.9.0 on unknown OS, CVEs not checked, support dates unknown / line 20: 20.20.2 on Debian 12, 1/2 CVEs resolved, support dates unknown / line 21: 21.7.3 on unknown OS, CVEs not checked, support dates unknown / line 22: 22.23.3 on Debian 12, 1/2 CVEs resolved, support dates unknown / line 23: 23.11.1 on Debian 12, 1/2 CVEs resolved, support dates unknown / line 24: 24.21.0 on Debian 12, 1/2 CVEs resolved, support dates unknown / line 25: 25.9.0 on Debian 12, 1/2 CVEs resolved, support dates unknown / line 26: 26.11.1 on Debian 13, 2/2 CVEs resolved, support dates unknown / compatible fix: none; migration target: None

### docker-compose.yml (redis:6.2-alpine, Alpine 3.18) (Redis image on Alpine, 1 finding(s), 458 prompt characters)

With all sources:

- image redis:6.2-alpine on Alpine 3.18; status rebuild_may_suffice
- fix data for this OS release: 1 in the standard repositories, 0 subscription-only, 0 without a fix, of 1 checked
- line 7.2-alpine: 7.2.16 on Alpine 3.21, 1/1 CVEs resolved, supported until 2029-12-01
- line 7.4-alpine: 7.4.11 on Alpine 3.21, 1/1 CVEs resolved, supported until 2029-12-01
- line 8.0-alpine: ? on Alpine 3.21, 1/1 CVEs resolved, supported until 2026-12-01
- line 8.2-alpine: 8.2.10 on Alpine 3.22, 1/1 CVEs resolved, supported until 2030-09-01
- line 8.4-alpine: 8.4.7 on Alpine 3.22, 1/1 CVEs resolved, support dates unknown
- line 8.6-alpine: 8.6.7 on Alpine 3.23, 1/1 CVEs resolved, support dates unknown
- line 8.8-alpine: 8.8.3 on Alpine 3.23, 1/1 CVEs resolved, support dates unknown
- line 8.10-alpine: 8.10.2 on Alpine 3.23, 1/1 CVEs resolved, support dates unknown
- compatible fix: none; migration target: None

Without MITRE CWE (+0 characters): loses weakness defined (references).

Without NVD (+0 characters): loses CVSS score and severity per CVE (references).

Without OSV.dev (-13 characters): loses prompt: where the fixes stand for the image's OS release; prompt: that no tag change is needed (the OS publishes the fixes); fix version per CVE for the OS release (references). Outcome becomes: image redis:6.2-alpine on Alpine 3.18; status unknown / fix data for this OS release: none found / line 7.2-alpine: 7.2.16 on Alpine 3.21, CVEs not checked, supported until 2029-12-01 / line 7.4-alpine: 7.4.11 on Alpine 3.21, CVEs not checked, supported until 2029-12-01 / line 8.0-alpine: ? on Alpine 3.21, CVEs not checked, supported until 2026-12-01 / line 8.2-alpine: 8.2.10 on Alpine 3.22, CVEs not checked, supported until 2030-09-01 / line 8.4-alpine: 8.4.7 on Alpine 3.22, CVEs not checked, support dates unknown / line 8.6-alpine: 8.6.7 on Alpine 3.23, CVEs not checked, support dates unknown / line 8.8-alpine: 8.8.3 on Alpine 3.23, CVEs not checked, support dates unknown / line 8.10-alpine: 8.10.2 on Alpine 3.23, CVEs not checked, support dates unknown / compatible fix: none; migration target: 7.2-alpine

Without Docker Hub (-60 characters): loses support dates per release line (upgrades); newer release lines with their base OS (upgrades). Outcome becomes: 

Without endoflife.date (+0 characters): loses support dates per release line (upgrades). Outcome becomes: line 7.2-alpine: 7.2.16 on Alpine 3.21, 1/1 CVEs resolved, support dates unknown / line 7.4-alpine: 7.4.11 on Alpine 3.21, 1/1 CVEs resolved, support dates unknown / line 8.0-alpine: ? on Alpine 3.21, 1/1 CVEs resolved, support dates unknown / line 8.2-alpine: 8.2.10 on Alpine 3.22, 1/1 CVEs resolved, support dates unknown

### docker-compose.yml (postgres:13, Debian 12) (PostgreSQL image on Debian, 1 finding(s), 566 prompt characters)

With all sources:

- image postgres:13 on Debian 12; status newer_line_needed
- fix data for this OS release: 0 in the standard repositories, 0 subscription-only, 1 without a fix, of 1 checked
- line 14: 14.24-1.pgdg13+2 on Debian 13, 1/1 CVEs resolved, supported until 2026-11-12
- line 15: 15.19-1.pgdg13+2 on Debian 13, 1/1 CVEs resolved, supported until 2027-11-11
- line 16: 16.15-1.pgdg13+2 on Debian 13, 1/1 CVEs resolved, supported until 2028-11-09
- line 17: 17.11-1.pgdg13+2 on Debian 13, 1/1 CVEs resolved, supported until 2029-11-08
- line 18: 18.6-1.pgdg13+2 on Debian 13, 1/1 CVEs resolved, supported until 2030-11-14
- compatible fix: none; migration target: 15

Without MITRE CWE (+0 characters): loses weakness defined (references).

Without NVD (+0 characters): loses CVSS score and severity per CVE (references).

Without OSV.dev (+40 characters): loses prompt: where the fixes stand for the image's OS release. Outcome becomes: fix data for this OS release: none found / line 14: 14.24-1.pgdg13+2 on Debian 13, CVEs not checked, supported until 2026-11-12 / line 15: 15.19-1.pgdg13+2 on Debian 13, CVEs not checked, supported until 2027-11-11 / line 16: 16.15-1.pgdg13+2 on Debian 13, CVEs not checked, supported until 2028-11-09 / line 17: 17.11-1.pgdg13+2 on Debian 13, CVEs not checked, supported until 2029-11-08 / line 18: 18.6-1.pgdg13+2 on Debian 13, CVEs not checked, supported until 2030-11-14

Without Docker Hub (-347 characters): loses prompt: that the image's release line is past end of life; prompt: compatible fix, or that there is none; support dates per release line (upgrades); newer release lines with their base OS (upgrades); migration target (upgrades). Outcome becomes: compatible fix: none; migration target: None

Without endoflife.date (-67 characters): loses prompt: that the image's release line is past end of life; support dates per release line (upgrades); migration target (upgrades). Outcome becomes: line 14: 14.24-1.pgdg13+2 on Debian 13, 1/1 CVEs resolved, support dates unknown / line 15: 15.19-1.pgdg13+2 on Debian 13, 1/1 CVEs resolved, support dates unknown / line 16: 16.15-1.pgdg13+2 on Debian 13, 1/1 CVEs resolved, support dates unknown / line 17: 17.11-1.pgdg13+2 on Debian 13, 1/1 CVEs resolved, support dates unknown / line 18: 18.6-1.pgdg13+2 on Debian 13, 1/1 CVEs resolved, support dates unknown / compatible fix: none; migration target: None

### docker-compose.yml (ghcr.io/acme/api:1.4.2, Debian 12) (Image from another registry, 1 finding(s), 565 prompt characters)

With all sources:

- image ghcr.io/acme/api:1.4.2 on Debian 12; status rebuild_may_suffice
- fix data for this OS release: 1 in the standard repositories, 0 subscription-only, 0 without a fix, of 1 checked
- compatible fix: none; migration target: None

Without MITRE CWE (+0 characters): loses weakness defined (references).

Without NVD (+0 characters): loses CVSS score and severity per CVE (references).

Without CISA KEV (-161 characters): loses prompt: warning that a CVE is known to be exploited; known-exploited flag per CVE (references).

Without OSV.dev (-215 characters): loses prompt: where the fixes stand for the image's OS release; prompt: that no tag change is needed (the OS publishes the fixes); fix version per CVE for the OS release (references). Outcome becomes: image ghcr.io/acme/api:1.4.2 on Debian 12; status unknown / fix data for this OS release: none found


# Source evaluation: results with and without each source

Generated 2026-10-22 17:00 UTC by `tests/eval_sources.py` from the NodeGoat scan 20261013062102 @ 765e1949 (7 files, 40 findings). Prompt budget per file: 2,500 characters.

A fact is something a useful answer should contain, checked mechanically. "Lost" means the fact was in the answer with all sources and is missing without that source.

## 1. What each source contributes

| Source | Used for | Prompt characters it adds | Prompt facts lost without it | PR / upgrade-data facts lost without it | Reading |
|---|---|---:|---:|---:|---|
| OWASP Cheat Sheet Series | how-to-fix guidance for code findings (similarity search) | 7,175 | 5 | 5 | Keep: the prompt loses facts without it. |
| MITRE CWE | weakness name in the search query; definition, mitigations and OWASP Top 10 label in references | -750 | 0 | 16 | Keep for the PR / UI data; it adds nothing to the prompt. |
| Keyword fallback | keyword matches when the similarity search is unsure (a method, not a source) | 0 | 0 | 0 | No effect on these files: no finding's best similarity is below the threshold. Its effect on the wider issue set is in part 3. |
| NVD | CVSS score, severity and CWE per CVE | 0 | 0 | 3 | Keep for the PR / UI data; it adds nothing to the prompt. |
| CISA KEV | flags CVEs known to be exploited | 0 | 1 | 1 | No effect on NodeGoat's findings; matters only when a CVE is in the catalogue (see the illustration). |
| OSV.dev | cross-checks upgrade targets; smallest fixed version; where an OS package fix is published | 351 | 3 | 3 | Keep: the prompt loses facts without it. |
| Context7 | breaking-change notes for major library upgrades (in the references, for the migration) | 0 | 0 | 1 | Keep for the PR / UI data; it adds nothing to the prompt. |
| Docker Hub | newer release lines of a container image and their base OS; decides whether a compatible line exists | 341 | 3 | 3 | Keep: the prompt loses facts without it. |
| endoflife.date | whether the image's line is past end of life; support dates, needed to name a migration target | 65 | 1 | 2 | Keep: the prompt loses facts without it. |

Total prompt text over the 7 files with all sources: 11,949 characters (about 2,987 tokens). A negative number means the answer grows without that source (a fallback text replaces it).

### The facts behind the counts

**Without OWASP Cheat Sheet Series:**
- prompt, app/routes/profile.js: key advice: cause: nested repetition
- prompt, app/routes/research.js: key advice: allowlist of targets
- prompt, app/routes/research.js: key advice: validate the URL/input
- prompt, app/routes/index.js: key advice: allowlist of targets
- prompt, app/routes/index.js: key advice: avoid user-controlled redirects
- app/routes/contributions.js: links to the guidance used (references)
- config/env/development.js: links to the guidance used (references)
- app/routes/profile.js: links to the guidance used (references)
- app/routes/research.js: links to the guidance used (references)
- app/routes/index.js: links to the guidance used (references)

**Without MITRE CWE:**
- app/routes/contributions.js: weakness named and defined (MITRE CWE) (references)
- app/routes/contributions.js: mitigations listed (MITRE CWE) (references)
- app/routes/contributions.js: OWASP Top 10 category (references)
- config/env/development.js: weakness named and defined (MITRE CWE) (references)
- config/env/development.js: mitigations listed (MITRE CWE) (references)
- config/env/development.js: OWASP Top 10 category (references)
- app/routes/profile.js: weakness named and defined (MITRE CWE) (references)
- app/routes/profile.js: mitigations listed (MITRE CWE) (references)
- app/routes/research.js: weakness named and defined (MITRE CWE) (references)
- app/routes/research.js: mitigations listed (MITRE CWE) (references)
- app/routes/research.js: OWASP Top 10 category (references)
- app/routes/index.js: weakness named and defined (MITRE CWE) (references)
- app/routes/index.js: mitigations listed (MITRE CWE) (references)
- app/routes/index.js: OWASP Top 10 category (references)
- package.json: weakness per CVE, with OWASP Top 10 category (references)
- docker-compose.yml: weakness per CVE (references)

**Without NVD:**
- package.json: CVSS score and severity per CVE (references)
- docker-compose.yml: CVSS score and severity per CVE (references)
- (illustration) pom.xml with Log4Shell: CVSS score and severity (references)

**Without CISA KEV:**
- prompt, (illustration) pom.xml with Log4Shell: says the CVE is known to be exploited, fix first
- (illustration) pom.xml with Log4Shell: known-exploited flag and date (references)

**Without OSV.dev:**
- prompt, package.json: independent confirmation of the scanner's targets
- prompt, package.json: says no compatible fix exists for mongodb (none within 2.x)
- prompt, docker-compose.yml: says the fixes are subscription-only, in the source's words
- package.json: smallest fixed version per package (upgrades)
- package.json: advisories that stay open after the upgrade (references)
- docker-compose.yml: fix version and availability per CVE (references)

**Without Context7:**
- package.json: mongodb 3.x breaking-change notes for the migration (references)

**Without Docker Hub:**
- prompt, docker-compose.yml: says the image's release line is past end of life
- prompt, docker-compose.yml: says no compatible (same major version) fix exists
- prompt, docker-compose.yml: warns that a new major version is not a drop-in change
- docker-compose.yml: newer release lines with their base OS (upgrades)
- docker-compose.yml: support dates per release line (upgrades)
- docker-compose.yml: migration target (upgrades)

**Without endoflife.date:**
- prompt, docker-compose.yml: says the image's release line is past end of life
- docker-compose.yml: support dates per release line (upgrades)
- docker-compose.yml: migration target (upgrades)

## 2. Per file

| File | Type | Findings | Prompt characters | Where they go | Facts present | Facts missing even with all sources |
|---|---|---:|---:|---|---:|---|
| app/routes/contributions.js | sast | 3 | 2,127 | OWASP Cheat Sheet Series 2,127 | 7 of 7 | - |
| config/env/development.js | sast | 1 | 1,666 | OWASP Cheat Sheet Series 1,666 | 4 of 5 | key advice: keep secrets out of code |
| app/routes/profile.js | sast | 1 | 2,335 | OWASP Cheat Sheet Series 2,335 | 4 of 6 | key advice: tooling to check regexes; OWASP Top 10 category |
| app/routes/research.js | sast | 1 | 2,379 | OWASP Cheat Sheet Series 2,379 | 6 of 6 | - |
| app/routes/index.js | sast | 1 | 1,851 | OWASP Cheat Sheet Series 1,851 | 7 of 7 | - |
| package.json | sca | 26 | 920 | OSV.dev 920 | 12 of 12 | - |
| docker-compose.yml | container | 7 | 671 | OSV.dev 671 | 11 of 11 | - |
| (illustration) pom.xml with Log4Shell | sca | 1 | 381 | OSV.dev 214, CISA KEV 167 | 3 of 3 | - |

Prompt characters per file without each source (bold = facts were lost):

| File | all | -owasp | -cwe | -keyword | -nvd | -kev | -osv | -context7 | -dockerhub | -endoflife |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| app/routes/contributions.js | 2,127 | **841** (1 lost) | **2,127** (3 lost) | 2,127 | 2,127 | 2,127 | 2,127 | 2,127 | 2,127 | 2,127 |
| config/env/development.js | 1,666 | **371** (1 lost) | **1,942** (3 lost) | 1,666 | 1,666 | 1,666 | 1,666 | 1,666 | 1,666 | 1,666 |
| app/routes/profile.js | 2,335 | **517** (2 lost) | **2,335** (2 lost) | 2,335 | 2,335 | 2,335 | 2,335 | 2,335 | 2,335 | 2,335 |
| app/routes/research.js | 2,379 | **734** (3 lost) | **2,379** (3 lost) | 2,379 | 2,379 | 2,379 | 2,379 | 2,379 | 2,379 | 2,379 |
| app/routes/index.js | 1,851 | **720** (3 lost) | **2,325** (3 lost) | 1,851 | 1,851 | 1,851 | 1,851 | 1,851 | 1,851 | 1,851 |
| package.json | 920 | 920 | **920** (1 lost) | 920 | **920** (1 lost) | 920 | **703** (4 lost) | **920** (1 lost) | 920 | 920 |
| docker-compose.yml | 671 | 671 | **671** (1 lost) | 671 | **671** (1 lost) | 671 | **537** (2 lost) | 671 | **330** (6 lost) | **606** (3 lost) |
| (illustration) pom.xml with Log4Shell | 381 | 381 | 381 | 381 | **381** (1 lost) | **214** (2 lost) | 324 | 381 | 381 | 381 |

## 3. OWASP search: similarity, keyword, and the fallback

Share of key fix advice found in the returned sections, averaged per issue type, over NodeGoat's own-code SAST issue types. The ranking was tuned on 11 of them; the rest were added later and are the fairer test.

| Search method | Issue types it was tuned on | All issue types | Average prompt characters |
|---|---:|---:|---:|
| similarity only | 86% (11) | 79% (12) | 1,912 |
| keyword only | 62% (11) | 57% (12) | 2,015 |
| similarity + keyword fallback (below 0.62, 2 results) | 95% (11) | 88% (12) | 1,925 |
| same, without the CWE name in the search query | 86% (11) | 79% (12) | 2,089 |

Per issue type, lowest similarity first (covered key-advice points):

| Issue type | CWE | Best similarity | similarity only | keyword only | similarity + keyword fallback | same, without the CWE name in the search query |
|---|---|---:|---:|---:|---:|---:|
| Use of Hardcoded Passwords | CWE-798 | 0.589 | 0 of 1 | 1 of 1 | 1 of 1 | 0 of 1 |
| Cleartext Transmission - HTTP Instead of HTTPS | CWE-319 | 0.610 | 2 of 2 | 2 of 2 | 2 of 2 | 2 of 2 |
| Hardcoded Non-Cryptographic Secret (added later) | CWE-547 | 0.624 | 0 of 1 | 0 of 1 | 0 of 1 | 0 of 1 |
| Open Redirect | CWE-601 | 0.663 | 3 of 3 | 1 of 3 | 3 of 3 | 3 of 3 |
| Server-Side Request Forgery (SSRF) | CWE-918 | 0.706 | 2 of 2 | 1 of 2 | 2 of 2 | 2 of 2 |
| Code Injection | CWE-94 | 0.713 | 3 of 3 | 3 of 3 | 3 of 3 | 3 of 3 |
| Cross-site Scripting (XSS) - Potentially Insecure Settings | CWE-79 | 0.715 | 1 of 1 | 0 of 1 | 1 of 1 | 1 of 1 |
| Sensitive Cookie in HTTPS Session Without 'Secure' Attribute | CWE-614 | 0.729 | 1 of 1 | 0 of 1 | 1 of 1 | 1 of 1 |
| Allocation of Resources Without Limits or Throttling | CWE-770 | 0.739 | 1 of 1 | 1 of 1 | 1 of 1 | 1 of 1 |
| Information Exposure - X-Powered-By Header | CWE-200 | 0.763 | 2 of 2 | 2 of 2 | 2 of 2 | 2 of 2 |
| Cross-Site Request Forgery (CSRF) | CWE-352 | 0.866 | 2 of 2 | 2 of 2 | 2 of 2 | 2 of 2 |
| Regular Expression Denial of Service (ReDoS) | CWE-400 | 0.874 | 1 of 2 | 0 of 2 | 1 of 2 | 1 of 2 |

Issue types where the fallback changed the result:

**Use of Hardcoded Passwords** (best similarity 0.589): 0 of 1 → 1 of 1
- similarity only: NodeJS Security Cheat Sheet › Take precautions against brute-forcing; Credential Stuffing Prevention Cheat Sheet › Degradation; NodeJS Security Cheat Sheet › Perform input validation
- with fallback: NodeJS Security Cheat Sheet › Take precautions against brute-forcing; [keyword] Mobile Application Security Cheat Sheet › 2. Credential Handling; [keyword] NoSQL Security Cheat Sheet › Secrets Management

**Cleartext Transmission - HTTP Instead of HTTPS** (best similarity 0.610): 2 of 2 → 2 of 2
- similarity only: NodeJS Security Cheat Sheet › Use appropriate security headers; DOM based XSS Prevention Cheat Sheet › GUIDELINE \#4 - Avoid sending untrusted data into HTML rendering methods; Browser Extension Security Vulnerabilities Cheat Sheet › Mitigation: Insecure Communication
- with fallback: NodeJS Security Cheat Sheet › Use appropriate security headers; [keyword] Drone Security Cheat Sheet › 1. Communication Security; [keyword] Logging Cheat Sheet › Protection

Issue types where leaving the CWE name out of the search query changed the coverage: Use of Hardcoded Passwords (1 of 1 with the name, 0 without).

## 4. How much OWASP text is needed

Coverage over all 12 issue types against the number of sections returned per finding and the characters kept per section (keyword fallback as configured).

| Sections per finding | Characters per section | Key advice covered | Average prompt characters |
|---:|---:|---:|---:|
| 1 | 400 | 44% | 358 |
| 1 | 800 | 56% | 671 |
| 1 | 1,200 | 60% | 974 |
| 2 | 400 | 56% | 705 |
| 2 | 800 | 67% | 1,283 |
| 2 | 1,200 | 71% | 1,784 |
| 3 | 400 | 76% | 1,073 |
| 3 | 800 | 88% | 1,925  ← service default |
| 3 | 1,200 | 88% | 2,612 |
| 4 | 400 | 76% | 1,429 |
| 4 | 800 | 88% | 2,580 |
| 4 | 1,200 | 88% | 3,478 |

# OWASP guidance search outside NodeGoat

Generated 2026-10-22 17:00 UTC by `tests/eval_search.py` from `tests/fixtures/search_cases.json`: 46 issue types in 7 languages that the ranking was never tuned on, each with the OWASP cheat sheets that are the right place to look (written down before the search was run). 6 more issue types have no cheat sheet of their own and are listed at the end, not scored.

## 1. Search methods

| Method | First section is from an expected sheet | Any returned section is | Share of returned sections on topic | Average prompt characters |
|---|---:|---:|---:|---:|
| similarity only | 65% | 80% | 65% | 1,811 |
| keyword only | 39% | 67% | 38% | 1,667 |
| similarity + keyword fallback (service default) | 65% | 83% | 60% | 1,710 |
| default, without the CWE name in the query | 72% | 85% | 67% | 1,684 |

## 2. How many sections to return (service default search)

| Sections per finding | Any returned section is from an expected sheet | Share of returned sections on topic | Average prompt characters |
|---:|---:|---:|---:|
| 1 | 65% | 65% | 571 |
| 2 | 74% | 62% | 1,163 |
| 3  ← default | 83% | 60% | 1,710 |
| 4 | 83% | 62% | 2,362 |

## 3. Per language (service default search)

| Language | Issue types | First section right | Any section right | On topic |
|---|---:|---:|---:|---:|
| csharp | 2 | 100% | 100% | 100% |
| go | 2 | 50% | 100% | 67% |
| java | 12 | 58% | 83% | 53% |
| javascript | 14 | 64% | 79% | 52% |
| php | 2 | 100% | 100% | 83% |
| python | 13 | 62% | 77% | 64% |
| ruby | 1 | 100% | 100% | 67% |

## 4. Issue types the default search missed (8 of 46)

- **Information Exposure** (javascript/DisablePoweredBy, CWE-200; best similarity 0.558). Expected: HTTP Security Response Headers, NodeJS Security. Returned: Web Frontend Security › Never transmit secrets to the client; [keyword] Cloud Architecture Security › Logging; [keyword] Cryptographic Storage › Defense in Depth
- **Improper Certificate Validation** (javascript/InsecureTLSConfig, CWE-295; best similarity 0.609). Expected: Transport Layer Security, Pinning. Returned: NodeJS Security › Perform input validation; [keyword] WebSocket Security › Framework-Specific Best Practices; [keyword] Secure Code Review › Input Validation Vulnerabilities
- **Sensitive Cookie Without 'HttpOnly' Flag** (python/WebCookieMissesCallToSetHttpOnly, CWE-1004; best similarity 0.602). Expected: Session Management, Cookie Theft Mitigation. Returned: Django Security › Cookies; [keyword] NodeJS Security › Set cookie flags appropriately; [keyword] Cross-Site Request Forgery Prevention › Pseudo-Code For Implementing HMAC CSRF Tokens
- **Use of Hardcoded Passwords** (python/NoHardcodedPasswords, CWE-259; best similarity 0.562). Expected: Secrets Management. Returned: Credential Stuffing Prevention › Identifying Leaked Passwords; [keyword] Multifactor Authentication › Passwords and PINs; [keyword] Password Storage › Common requirements for peppering strategies
- **Use of a Broken or Risky Cryptographic Algorithm** (java/InsecureCipher, CWE-327; best similarity 0.607). Expected: Cryptographic Storage. Returned: Java Security › General cryptography guidance; [keyword] Java Security › Encryption for transmission; [keyword] Transport Layer Security › Use Strong Cryptographic Hashing Algorithms
- **Cleartext Transmission of Sensitive Information** (python/CleartextTransmission, CWE-319; best similarity 0.525). Expected: Transport Layer Security, HTTP Strict Transport Security. Returned: LLM Prompt Injection Prevention › Input Validation and Sanitization; [keyword] Top 10 Automotive Security Vulnerabilities › 8. Data Leakage and Privacy Violations; [keyword] Mobile Application Security › 1. UI Data Masking
- **Generation of Error Message Containing Sensitive Information** (java/ErrorMessageExposure, CWE-209; best similarity 0.590). Expected: Error Handling. Returned: Deserialization › Prevent Data Leakage and Trusted Field Clobbering; [keyword] Web Service Security › Message Confidentiality; [keyword] Bean Validation › Error Messages
- **Hardcoded Non-Cryptographic Secret** (javascript/HardcodedNonCryptoSecret, CWE-547; best similarity 0.637). Expected: Secrets Management. Returned: NodeJS Security › Run security linters; Web Frontend Security › Never transmit secrets to the client; DOM based XSS Prevention › N-Levels of Encoding

## 5. Where the keyword fallback changed the result (5 of 46)

- **Hardcoded Secret** (javascript/HardcodedSecret; best similarity 0.598): better. Similarity only: Web Frontend Security › Never transmit secrets to the client; GitHub Actions Security › Secure handling of static credentials (if elimination is unavoidable); NodeJS Security › Use appropriate security headers. With the fallback: Web Frontend Security › Never transmit secrets to the client; [keyword] Secrets Management › 5.1 Injection of Secrets (file, in-memory); [keyword] Django REST Framework (DRF) › Secret Management
- **Information Exposure** (javascript/DisablePoweredBy; best similarity 0.558): worse. Similarity only: Web Frontend Security › Never transmit secrets to the client; Third Party JavaScript Management › Risk 3: Disclosure of sensitive information to 3rd parties; NodeJS Security › Use appropriate security headers. With the fallback: Web Frontend Security › Never transmit secrets to the client; [keyword] Cloud Architecture Security › Logging; [keyword] Cryptographic Storage › Defense in Depth
- **Sensitive Cookie Without 'HttpOnly' Flag** (python/WebCookieMissesCallToSetHttpOnly; best similarity 0.602): worse. Similarity only: Django Security › Cookies; Transport Layer Security › Use the "Secure" Cookie Flag; Session Management › HttpOnly Attribute. With the fallback: Django Security › Cookies; [keyword] NodeJS Security › Set cookie flags appropriately; [keyword] Cross-Site Request Forgery Prevention › Pseudo-Code For Implementing HMAC CSRF Tokens
- **Use of Hardcoded Credentials** (python/NoHardcodedCredentials; best similarity 0.548): better. Similarity only: Authentication › Protect Against Automated Attacks; GitHub Actions Security › Secure handling of static credentials (if elimination is unavoidable); Credential Stuffing Prevention › Multi-Step Login Processes. With the fallback: Authentication › Protect Against Automated Attacks; [keyword] Secrets Management › 1 Introduction; [keyword] Injection Prevention › Application Types
- **Log Forging** (java/LogInjection; best similarity 0.589): better. Similarity only: Java Security › How to prevent; Java Security › Example using Log4j Core 2; Java Security › Example using Logback. With the fallback: Java Security › How to prevent; [keyword] Java Security › General advice to prevent Injection; [keyword] Logging › Accountability

## 6. Issue types without a cheat sheet of their own (not scored)

- **Path Traversal** (python/PT, CWE-23; best similarity 0.307): nothing returned
- **Path Traversal** (java/PT, CWE-23; best similarity 0.387): Insecure Direct Object Reference Prevention › Java and Spring Boot example; [keyword] Symfony › Directory Traversal; [keyword] NodeJS Security › Examples
- **Arbitrary File Write via Archive Extraction (Tar Slip)** (python/TarSlip, CWE-22; best similarity 0.441): File Upload › Filename Safety; [keyword] Symfony › Directory Traversal; [keyword] Laravel › Path Traversal
- **Server-Side Template Injection** (python/Ssti, CWE-1336; best similarity 0.445): Django Security › Cross Site Scripting (XSS); [keyword] Injection Prevention › Application Types; [keyword] Django REST Framework (DRF) › What is a view in Django?
- **File Inclusion** (php/FileInclusion, CWE-98; best similarity 0.509): Symfony › Command Injection; [keyword] Laravel › Do Not Rely On User Input To Dictate Filenames or Path; [keyword] Laravel › Path Traversal
- **Buffer Overflow** (cpp/BufferOverflow, CWE-120; best similarity 0.423): C-Based Toolchain Hardening › GCC/Binutils; [keyword] Denial of Service › Input validation; [keyword] Denial of Service › Software Design Concepts

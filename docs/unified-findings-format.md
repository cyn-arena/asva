# Unified Findings Format — Specification

## Overview

The ASVA normaliser consumes SARIF output from three different Snyk scanners and converts
every finding into a single shared JSON structure. This document defines that structure,
explains every field, and shows a concrete example for each scanner type.

The normaliser writes two files to its output directory (default `findings/`):

| File | Contents | Consumer |
|---|---|---|
| `ranked_unified_findings.json` | Every finding as one flat JSON list, sorted by `priority` (most urgent first) | Triage (`triage/triage.py`) |
| `normalisation-audit.json` | Run summary: `scan_run_id`, input reports, and counts extracted, normalised, de-duplicated and merged | Evidence and debugging |

Triage then writes `ranked_findings.json`: the same findings with routing fields added (see
[Fields added by triage](#fields-added-by-triage)).

---

## Supported Scanners

| Scanner | `finding_type` value | What it finds |
|---|---|---|
| Snyk Open Source | `sca` | Vulnerable packages listed in `package.json` |
| Snyk Container | `container` | Vulnerable OS packages inside a Docker image |
| Snyk Code | `sast` | Security bugs in your own source code |

---

## Finding Schema

### Top-level fields

| Field | Type | Description |
|---|---|---|
| `finding_id` | string (UUID) | Unique identifier for this finding instance. Regenerated on every normaliser run. |
| `finding_type` | `"sca"` \| `"container"` \| `"sast"` | Which scanner produced this finding. Use this as the discriminator to know which nested fields are populated. |
| `scan_run_id` | string | Identifier of the normaliser run, shared by every finding from that run. |
| `provenance` | object | Where the finding came from: `scan_source`, `tool`, `report` (SARIF file name), `automation_id` and `artifact_uri` from the SARIF run. |
| `package` | object | `{"name", "version"}` of the affected package for SCA/Container; both `null` for SAST. |
| `severity` | `"critical"` \| `"high"` \| `"medium"` \| `"low"` | Normalised severity label. See [Severity Mapping](#severity-mapping). |
| `score` | float \| null | Danger score used for sorting. CVSS v3 for SCA/Container; derived pseudo-score for SAST. See [Scoring](#scoring). |
| `has_real_score` | boolean | `true` = official CVSS score. `false` = pseudo-score derived from the scanner's level label. |
| `identifiers` | object | CVE, CWE, and rule ID. See [Identifiers](#identifiers). |
| `title` | string \| null | Short vulnerability name from the scanner rule. |
| `summary` | string | One-sentence description for the triage LLM. For SAST this is `result.message.text`; for SCA/Container it matches `title`. |
| `location` | object | Where the vulnerability lives. See [Location](#location). |
| `code_flow` | array | SAST only: the scanner's data-flow steps from SARIF `codeFlows`/`threadFlows`, in reported order, de-duplicated, each `{"file": string, "line": int}`. Used by the fix agent's repo-aware context. Empty (`[]`) for SCA/Container or when the scanner reports no flow. |
| `dependency` | object \| null | Dependency chain. Populated for `sca` only; `null` for `container` and `sast`. See [Dependency](#dependency). |
| `remediation` | object | How to fix it. See [Remediation](#remediation). |
| `priority` | integer | 1-based rank across all findings in this run. `1` = most urgent. Assigned after deduplication and sorting. |

**Detail fields for the fix stage:**

| Field | Type | Description |
|---|---|---|
| `description` | string | Raw text from the scanner rule. For SCA/Container this is the full vulnerability description including the CVE reference. For SAST this repeats `summary`. |
| `ecosystem` | string | Package manager: `"npm"`, `"deb"`, `"pip"`, or `"unknown"`. Tells the fix agent which install command to use. |
| `is_node_modules` | boolean | `true` when the finding's file is inside `node_modules/`. Triage skips these. |

The normaliser also uses an internal `dedup_key` while de-duplicating (see
[Deduplication](#deduplication)); it is removed before the file is written.

### Fields added by triage

`triage/triage.py` adds these fields in `ranked_findings.json`:

| Field | Type | Description |
|---|---|---|
| `editable_target` | string \| null | Source file the agent edits for this finding (for container findings, the app's Dockerfile or compose file). `null` when no editable file could be mapped. |
| `routing_status` | `"editable"` \| `"deferred"` | `deferred` when there is no `editable_target`; deferred findings get no fix batch. |
| `covered_by` | string \| null | `finding_id` of the root finding whose fix also covers this one, or `null` for root findings. |
| `is_test_file` | boolean | `true` when the finding is in a test file. |
| `fix_type` | `"version_upgrade"` \| `"code_change"` \| `"config_change"` | Taken from `remediation.type`; anything else becomes `config_change`. |
| `triage_reason` | string | One-line explanation of the routing decision. |

Triage also sets `location.file` to the editable target and keeps the scanner's original
path in `location.observed_file`.

---

### Identifiers

```json
"identifiers": {
  "cve": "CVE-2016-10531",
  "cwe": null,
  "rule_id": "npm:marked:20150520"
}
```

| Field | Populated by | Description |
|---|---|---|
| `cve` | SCA, Container | CVE identifier, e.g. `"CVE-2022-23219"`. Parsed from the rule's `fullDescription.text`. `null` when no CVE is referenced. |
| `cwe` | SAST | CWE identifier, e.g. `"CWE-94"`. From `rule.properties.cwe[0]`. `null` for SCA and Container. |
| `rule_id` | All | Scanner's internal rule ID. Always present. Used as fallback dedup key when no CVE/CWE exists. |

---

### Location

The `location` object captures where to look for the vulnerability. Its content differs
by `finding_type` — use `kind` as the discriminator.

```json
"location": {
  "kind": "dependency | os_package | container_package | source_file",
  "file": "...",
  "line": null,
  "package": "...",
  "display": "...",
  "image_name": null,
  "image_tag": null
}
```

| Field | Type | Description |
|---|---|---|
| `kind` | `"dependency"` \| `"os_package"` \| `"container_package"` \| `"source_file"` | Application dependency, known OS package, unknown image ecosystem, or source location. |
| `file` | string | The file or artifact containing the vulnerability. See table below. |
| `line` | integer \| null | Source line number. Only populated for `sast` when the line is meaningful (not a scanner placeholder). `null` otherwise. |
| `package` | string \| null | `"name@version"` of the vulnerable package. Populated for `sca` and `container`. `null` for `sast`. |
| `display` | string | Human-readable one-liner. Examples: `"marked@0.3.5 in package.json"`, `"app/routes/contributions.js:32"`. |
| `image_name` | string \| null | The scanned container image, without its tag, e.g. `"mongo"`. Populated for `container` only. |
| `image_tag` | string \| null | The scanned image's tag, e.g. `"4.4"`. `null` when the image was scanned untagged, or when the scanner output does not name the image separately (then `image_name` holds the scanner's whole artifact name). Populated for `container` only. |

**`file` values by scanner type:**

| `finding_type` | `kind` | Example `file` | What it means |
|---|---|---|---|
| `sca` | `dependency` | `"package.json"` | The manifest where the vulnerable package is declared |
| `container` | `os_package` | `"mongo_4.4"` | The scanner's artifact name for the image (the image reference with `:` written as `_`) |
| `container` | `dependency` | `"asva-pygoat_scan"` | An application dependency observed in an image; not an editable source path |
| `container` | `container_package` | `"image_scan"` | An image package whose ecosystem is unknown |
| `sast` | `source_file` | `"app/routes/contributions.js"` | The source file containing the vulnerable code |

> **Container findings after triage:** the scanner names the image, not the file that defines
> it. For OS packages, triage replaces `location.file` with the file the fix agent should edit —
> `docker-compose.yml` by default, or the path given with `triage.py --container-file` (e.g. a
> Dockerfile). The observation stays in `observed_file`, `image_name` / `image_tag`
> and `provenance`. Image application dependencies and unknown ecosystems are
> deferred unless there is evidence mapping them to editable source; their image
> paths are never guessed into source manifests. Grouping uses scan type and resolved
> editable file, producing one edit per file in each batch.

> **Note:** SCA and Container findings do not have meaningful line numbers — `line` is always
> `null` for these types. The vulnerable "location" for a dependency is the package name and
> version, not a line of code.

---

### Dependency

Only populated for `finding_type: "sca"`. Always `null` for `container` and `sast`.

```json
"dependency": {
  "path": ["owasp-nodejs-goat@1.3.0", "body-parser@1.18.3", "qs@6.5.2"],
  "is_direct": false
}
```

| Field | Type | Description |
|---|---|---|
| `path` | array of strings | The dependency chain from the root application to the vulnerable package, e.g. `["app@1.0.0", "express@4.17.1", "qs@6.5.2"]`. Parsed from the `_Introduced through_:` detailed path line in Snyk's rule help markdown. |
| `is_direct` | boolean | `true` when the chain has exactly 2 entries (root app → vulnerable package), meaning the package is declared directly in `package.json`. `false` for transitive dependencies pulled in by another package. |

**How the fix stage uses this:**
- `is_direct: true` → edit `package.json` directly and bump that package's version.
- `is_direct: false` → upgrade the parent package (`path[-2]`), which pulls in a non-vulnerable version transitively. The `remediation.upgrade_to` field always names the correct package to bump.

---

### Remediation

```json
"remediation": {
  "type": "version_upgrade",
  "fixable": true,
  "upgrade_to": "marked@0.3.6"
}
```

| Field | Type | Description |
|---|---|---|
| `type` | `"version_upgrade"` \| `"code_change"` \| `"no_fix"` | The kind of action required. |
| `fixable` | boolean | Whether a fix is available. Always `true` for SAST (a code change is always possible). May be `false` for SCA/Container when Snyk reports no fixed version exists. |
| `upgrade_to` | string \| null | For `version_upgrade`: the exact `"package@version"` to upgrade to. This is the direct parent to bump, which may differ from the vulnerable package itself for transitive dependencies. For `container` it is the OS package version that contains the fix, e.g. `"perl/perl-base@5.30.0-9ubuntu0.5+esm2"` (a `+esm`/`~esm` suffix means the fix ships only through Ubuntu's Expanded Security Maintenance). `null` for `code_change` and `no_fix`. |

**`type` values by scanner:**

| `finding_type` | `type` | What the fix agent does |
|---|---|---|
| `sca` / `container` | `version_upgrade` | Run the package manager upgrade command targeting `upgrade_to` |
| `sca` / `container` | `no_fix` | Log as unfixable; skip the fix loop for this finding |
| `sast` | `code_change` | Apply a code edit to the file at `location.file` line `location.line` |

---

## Severity Mapping

Snyk SARIF uses the standard `level` field (not plain severity words). The normaliser maps
these to severity labels as follows:

| SARIF `level` | Severity | Notes |
|---|---|---|
| `"error"` | `high` | May be promoted to `critical` — see below |
| `"warning"` | `medium` | May be promoted to `critical` — see below |
| `"note"` | `low` | |
| `"none"` | `info` | |
| missing | `unknown` | |

**Critical promotion:** Any finding with a CVSS score ≥ 9.0 is promoted to `critical`,
regardless of what `level` the scanner emitted. Snyk does not have a dedicated SARIF level
for critical severity — it encodes this information only in the CVSS score.

---

## Scoring

### SCA and Container findings

Score comes from the rule's CVSS v3 base score, read from two possible properties keys
(in order of preference):

1. `rule.properties.cvssv3_baseScore`
2. `rule.properties.security-severity`

`has_real_score: true`. Range: 0.0–10.0.

### SAST findings

Snyk Code does not publish CVSS scores. The normaliser derives a pseudo-score from the
SARIF `level` field so all three scanner types share one sortable ranking:

| SARIF `level` | Pseudo-score | Rationale |
|---|---|---|
| `"error"` | **8.5** | Near the top of the `high` CVSS band (7.0–8.9), below any real CVSS 9.0+ |
| `"warning"` | **5.0** | Middle of the `medium` CVSS band (4.0–6.9) |
| `"note"` | **2.0** | Middle of the `low` CVSS band (0.1–3.9) |

`has_real_score: false`. The triage LLM should treat these as approximate rankings, not
authoritative scores.

**Sort order (within the same severity tier):** real-scored findings (`has_real_score: true`)
always rank above pseudo-scored findings (`has_real_score: false`).

---

## Deduplication

The same vulnerability can appear in multiple scan files. The normaliser deduplicates
across files using a key that depends on `finding_type`:

| `finding_type` | Dedup key | Rationale |
|---|---|---|
| `sca` / `container` | Scanner type, CVE and rule, ecosystem, package/version, manifest/image URI, dependency path, image context, remediation | Distinct source/image observations and upgrade recommendations must survive independently |
| `sast` | `{rule_id}\|{file}\|{line}` | Every occurrence of a rule at a different file/line is a separate, independent finding |

When two findings share a key, the one with the higher score is kept.
Remediation is part of the dependency key, so this selection cannot discard a
different upgrade recommendation. Additive `package.name` / `package.version` and
`provenance` fields retain package identity and scanner/run/report context without
changing the existing location or remediation fields.

---

## Concrete Examples

### SCA — Direct dependency

```json
{
  "finding_id": "17255c98-286d-4736-a759-b517c7e365eb",
  "finding_type": "sca",
  "severity": "high",
  "score": 8.8,
  "has_real_score": true,
  "identifiers": {
    "cve": "CVE-2016-10531",
    "cwe": null,
    "rule_id": "npm:marked:20150520"
  },
  "title": "High severity - Cross-site Scripting (XSS) vulnerability in marked",
  "summary": "High severity - Cross-site Scripting (XSS) vulnerability in marked",
  "location": {
    "kind": "dependency",
    "file": "package.json",
    "line": null,
    "package": "marked@0.3.5",
    "display": "marked@0.3.5 in package.json",
    "image_name": null,
    "image_tag": null
  },
  "dependency": {
    "path": ["owasp-nodejs-goat@1.3.0", "marked@0.3.5"],
    "is_direct": true
  },
  "remediation": {
    "type": "version_upgrade",
    "fixable": true,
    "upgrade_to": "marked@0.3.6"
  },
  "priority": 24
}
```

### SCA — Transitive dependency

```json
{
  "finding_id": "0b5e1f6f-20e7-4eee-af0a-a9420c0db664",
  "finding_type": "sca",
  "severity": "high",
  "score": 8.7,
  "has_real_score": true,
  "identifiers": {
    "cve": "CVE-2025-15284",
    "cwe": null,
    "rule_id": "SNYK-JS-QS-14724253"
  },
  "title": "High severity - Allocation of Resources Without Limits or Throttling vulnerability in qs",
  "summary": "High severity - Allocation of Resources Without Limits or Throttling vulnerability in qs",
  "location": {
    "kind": "dependency",
    "file": "package.json",
    "line": null,
    "package": "qs@6.5.2",
    "display": "qs@6.5.2 in package.json",
    "image_name": null,
    "image_tag": null
  },
  "dependency": {
    "path": ["owasp-nodejs-goat@1.3.0", "body-parser@1.18.3", "qs@6.5.2"],
    "is_direct": false
  },
  "remediation": {
    "type": "version_upgrade",
    "fixable": true,
    "upgrade_to": "body-parser@1.20.4"
  },
  "priority": 26
}
```

> `qs` is 3 levels deep so `is_direct: false`. The fix targets `body-parser` (the direct
> parent), not `qs` itself.

### Container — OS package (critical)

```json
{
  "finding_id": "d91e1784-e541-4778-af09-313fb776f388",
  "finding_type": "container",
  "severity": "critical",
  "score": 9.8,
  "has_real_score": true,
  "identifiers": {
    "cve": "CVE-2022-23219",
    "cwe": null,
    "rule_id": "SNYK-UBUNTU1604-GLIBC-2356812"
  },
  "title": "Low severity - Buffer Overflow vulnerability in glibc",
  "summary": "Low severity - Buffer Overflow vulnerability in glibc",
  "location": {
    "kind": "os_package",
    "file": "mongo_4.0",
    "line": null,
    "package": "glibc@2.23-0ubuntu11.3",
    "display": "glibc@2.23-0ubuntu11.3 in mongo_4.0",
    "image_name": "mongo",
    "image_tag": "4.0"
  },
  "dependency": null,
  "remediation": {
    "type": "version_upgrade",
    "fixable": true,
    "upgrade_to": "glibc/libc-bin@2.23-0ubuntu11.3+esm1"
  },
  "priority": 1
}
```

> Snyk labelled this `"Low severity"` in the title but the CVSS score is 9.8 — the normaliser
> promotes it to `critical`. The `title` reflects the scanner's label; `severity` is the
> authoritative value to use.

### SAST — Source code vulnerability

```json
{
  "finding_id": "421d7319-97a2-4ff2-9d04-db914e77ef06",
  "finding_type": "sast",
  "severity": "high",
  "score": 8.5,
  "has_real_score": false,
  "identifiers": {
    "cve": null,
    "cwe": "CWE-94",
    "rule_id": "javascript/CodeInjection"
  },
  "title": "Code Injection",
  "summary": "Unsanitized input from the HTTP request body flows into eval, where it is executed as JavaScript code. This may result in a Code Injection vulnerability.",
  "location": {
    "kind": "source_file",
    "file": "app/routes/contributions.js",
    "line": 32,
    "package": null,
    "display": "app/routes/contributions.js:32",
    "image_name": null,
    "image_tag": null
  },
  "dependency": null,
  "remediation": {
    "type": "code_change",
    "fixable": true,
    "upgrade_to": null
  },
  "priority": 63
}
```

> `has_real_score: false` — the score of 8.5 is the pseudo-score derived from the `"error"`
> level, not a CVSS database value.

---

## Implementation Reference

The format is produced by [`normaliser/normaliser.py`](../normaliser/normaliser.py).

**Run it (from the `normaliser/` directory):**
```bash
python normaliser.py \
  --inputs ../samples/scans/nodegoat-sast.sarif.json \
           ../samples/scans/nodegoat-image.sarif.json \
           ../samples/scans/nodegoat-sca.sarif.json \
  --output-dir ../findings
```

**Outputs:**
- `findings/ranked_unified_findings.json` — the flat, ranked list of findings
- `findings/normalisation-audit.json` — run summary and counts

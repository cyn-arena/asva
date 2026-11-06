# Dashboard data contract (v0.1)

This contract defines what every ASVA pipeline run uploads to Azure Blob Storage for the
dashboard: which files, which folder they go in, and what is inside each one. Any app whose
runs follow it appears on the dashboard without dashboard changes.

Everything the dashboard shows comes from these files. It does not read GitHub workflow
artifacts (which expire after 14 days) or PR comments.

## Where the files go

Everything goes into the existing Azure Blob container (the `ASVA_AZURE_STORAGE_ACCOUNT` / `ASVA_AZURE_STORAGE_CONTAINER` repository variables), using the same login step and the same `AZURE_CREDENTIALS` secret the scan workflow already uses. Each app gets its own top-level folder, named by the workflow's `app-code` input, and each run gets a folder inside it, named by the GitHub Actions run ID:

```
{app}/
  {run_id}/
    manifest.json
    scan/sast.sarif.json
    scan/sca.sarif.json
    scan/container.sarif.json
    findings/ranked_unified_findings.json
    findings/ranked_findings.json
    remediation/fix_batches/{batch_id}.json
    remediation/fixes.json
    validation/{batch_id}.json
  memory/
    decisions.json
```

For NodeGoat that would be `nodegoat/28890127081/manifest.json` and so on. The `memory/` folder is the one exception: `decisions.json` holds reviewer decisions written by the dashboard and read by the pipeline (`memory/decisions_loader.py`).

## The files, one by one

### manifest.json

The manifest is the run's cover page. The dashboard reads it first, to learn which app and commit the run was for, how far the run got, and where the other files are. Example from a NodeGoat run:

```json
{
  "schema_version": "0.1",
  "app": "nodegoat",
  "run_id": "28890127081",
  "commit_sha": "7e8aedab",
  "branch": "feat/automate-scan-and-fix",
  "workflow": "Scan and Fix Vulnerabilities - Node Goat",
  "created_at": "2026-07-07T18:42:18Z",
  "workflow_url": "https://github.com/cyn-arena/asva/actions/runs/28890127081",
  "stages": {
    "scan": "completed",
    "normalise": "completed",
    "triage": "completed",
    "fix": "completed",
    "validate": "completed"
  },
  "artifacts": {
    "scan": {
      "sast": "scan/sast.sarif.json",
      "sca": "scan/sca.sarif.json",
      "container": "scan/container.sarif.json"
    },
    "findings": "findings/ranked_unified_findings.json",
    "triage": "findings/ranked_findings.json",
    "fix_batches": [
      "remediation/fix_batches/asva_container_7e8aedab.json",
      "remediation/fix_batches/asva_sast_7e8aedab_1.json",
      "remediation/fix_batches/asva_sca_7e8aedab.json"
    ],
    "remediation": "remediation/fixes.json"
  }
}
```

`app` is the same value as `app-code`. `run_id` is `github.run_id`, `commit_sha` is the short SHA the scan ran on, and `branch`, `workflow` and `workflow_url` come straight from the GitHub context. `created_at` is when the run started, in UTC.

`stages` records how far the run got. Each stage is `completed`, `failed`, or `not_available` (the stage did not run, for example because an earlier stage failed or the workflow stops before fixing). This lets the dashboard show a run that failed halfway, and say so, instead of showing nothing. The manifest is therefore uploaded at the end of every run, including runs where a stage failed, and always after the files it lists.

`artifacts` lists the paths of the other files, relative to the run folder. Only `findings` is required. The rest are left out when the stage that makes them did not run, and the dashboard copes with that.

### scan/*.sarif.json

These are the raw Snyk files, exactly as the scan step produces them: `sast.sarif.json`, `sca.sarif.json` and `container.sarif.json` (NodeGoat's `image` report is stored under the `container` name; the dashboard finds each file through the manifest). They are kept next to everything else so that a run can always be re-processed later.

### findings/ranked_unified_findings.json and findings/ranked_findings.json

These are the normaliser's and triage's outputs, unchanged (see [unified findings format](unified-findings-format.md)). The first holds every finding from all three scanners after cleaning up and ranking. The second holds only the findings triage kept as actionable, which for NodeGoat is 44 out of 574. The dashboard lists every finding from the first file and uses the second to mark which of them are actionable.

Here is one NodeGoat finding, trimmed to the fields the dashboard uses:

```json
{
  "finding_id": "ad2f536b-5e1e-4e1b-9e07-75ede9ed9e5b",
  "finding_type": "sast",
  "severity": "high",
  "score": 8.5,
  "has_real_score": false,
  "identifiers": { "cve": null, "cwe": "CWE-94", "rule_id": "javascript/CodeInjection" },
  "title": "Code Injection",
  "summary": "Unsanitized input from the HTTP request body flows into eval, where it is executed as JavaScript code.",
  "description": "...",
  "location": {
    "file": "app/routes/contributions.js",
    "line": 32,
    "package": null,
    "display": "app/routes/contributions.js:32"
  },
  "remediation": { "type": "code_change", "fixable": true, "upgrade_to": null },
  "priority": 62
}
```

Extra fields are fine. The dashboard ignores anything it does not recognise, so the normaliser and triage can keep adding fields without breaking it. Renaming or removing one of the fields above would break it, so such a change needs a new `schema_version`.

### remediation/fix_batches/{batch_id}.json

These are the batch files triage writes, one per PR the agent will try to open, uploaded as they are. The dashboard uses them to show which findings each fix covers, through the `finding_id` values listed under `files_to_fix`.

### remediation/fixes.json

One entry per fix batch, built from the agent's results. Besides the PR metadata it carries the diff of every changed file, so the dashboard can show what the AI changed without calling the GitHub API:

```json
[
  {
    "batch_id": "asva_sast_7e8aedab_1",
    "batch_type": "sast",
    "status": "pr_opened",
    "branch": "fix/asva_sast_7e8aedab_1",
    "pr_url": "https://github.com/cyn-arena/asva/pull/232",
    "pr_number": 232,
    "title": "[ASVA] sast fixes for asva @ 7e8aedab - 5 file(s), 7 finding(s)",
    "body": "## ASVA automated security remediation ...",
    "files": [
      {
        "path": "app/routes/contributions.js",
        "additions": 2,
        "deletions": 10,
        "patch": "@@ -27,18 +27,10 @@ ..."
      }
    ]
  }
]
```

`status` uses the agent's values, including for batches that failed before a PR was opened, because "the AI tried and could not fix this" is exactly what a reviewer needs to see. In that case `pr_url`, `pr_number` and `files` can be empty. The `patch` text is what `git diff` prints for that file, and `path` is relative to the app's own folder (so `app/routes/contributions.js` rather than `target-apps/NodeGoat/app/routes/contributions.js`), which lets the dashboard match it to the `location.file` on a finding.

### validation/{batch_id}.json

The candidate-check workflow (`*-pr-check.yml`) runs the smoke tests and the matched misuse-case tests for each fix. It posts the result as a PR comment and also saves it as this file, one per batch, in the run folder of the scan it is checking. The dashboard reads the file, never the comment text:

```json
{
  "batch_id": "asva_sast_7e8aedab_1",
  "pr_url": "https://github.com/cyn-arena/asva/pull/232",
  "commit_sha": "a1b2c3d4",
  "checked_at": "2026-07-07T19:10:00Z",
  "app_started": true,
  "result": "failed",
  "checks": [
    { "name": "login page loads", "kind": "smoke", "status": "passed", "detail": null },
    { "name": "learning resources link goes offsite", "kind": "smoke", "status": "failed", "detail": "Redirected to / instead of the external site" },
    { "name": "code injection via contributions form", "kind": "misuse", "status": "passed", "detail": null }
  ]
}
```

`result` is `passed` when every check passed, and `failed` otherwise, including when the app never started. Each check's `status` is `passed`, `failed` or `skipped`, and `kind` says whether it was a smoke test or a misuse-case test.

## The second scan after the fixes

After reviewed fixes are applied to the branch, ASVA can scan it again. That second scan tells the reviewer which findings are left over. It is a normal run with its own folder, plus two extra fields in its manifest:

```json
{
  "run_id": "28890999999",
  "commit_sha": "c3d4e5f6",
  "scan_kind": "after_fix",
  "after_fix_of": "28890127081"
}
```

`scan_kind` is `initial` for the first scan and `after_fix` for the rescan, and `after_fix_of` points back at the run whose fixes were applied. With that link, the dashboard can compare the two runs and show what the AI fixed and what is left.

### Candidate scans

Every generated fix candidate is also rescanned on its own, at its exact commit. The original run's manifest lists them in `candidate_scans` (each entry has `run_id`, `batch_id`, `pr_url`, the full `candidate_sha`, `status` and the path of its `manifest`). Each candidate gets an ordinary run folder of its own:

```
{app}/{original_run}-candidate-{batch_id}-{full_sha}-a{attempt}/
  manifest.json
  scan/{sast,sca,container}.sarif.json   # available scanner reports
  scan/scan-status.json                  # each scan's status and reason
  findings/ranked_unified_findings.json
  findings/partial_unified_findings.json # if only some scans succeeded
  validation/{batch_id}.json
```

A candidate manifest keeps every v0.1 field and adds `scan_kind: "after_fix"`, `after_fix_of`, `candidate_sha`, `batch_id`, `pr_url`, `evidence_scope: "independent_candidate"` (the change has not been combined with other PRs), `fix_generation: "disabled"` and a per-scanner `scan_status`. Its `commit_sha` is the full SHA, and its `fix` and `triage` stages are `not_available`. The `-a{attempt}` suffix stops a rerun from overwriting earlier evidence.

## Implementation

`.github/workflows/publish-dashboard-results.yml` builds this layout with `scripts/dashboard_evidence.py` at the end of every pipeline run, even when earlier stages failed. It uploads the data files first and `manifest.json` last, so the dashboard never sees a run whose files are incomplete. The JSON Schemas are in [`schemas/`](../schemas/).

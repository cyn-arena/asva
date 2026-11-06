"""
ASVA GitOps backend -- native git + gh.

Creates a fix branch, commits the fixed files, pushes, and opens a pull request for
HUMAN REVIEW using the tools already installed on the runners (git, gh). Authentication
is taken from the environment (CI: the workflow's GITHUB_TOKEN; local: `gh auth login`).

ASVA never merges -- it opens PRs only, ONE PR per triage batch (fix/<batch_id>). Entry
points: git_gh_ops.submit_fix_batch (one batch) and git_gh_ops.submit_scan_cycle (all
batches of a scan, one PR each). The secrets gate (secrets_scan.gitleaks_gate)
runs before any write.
"""

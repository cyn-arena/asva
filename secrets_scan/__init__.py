"""
ASVA secrets-scan gate.

git-leaks pre-commit safety check. Runs over the candidate fixed file contents BEFORE
any GitHub write; if the fix adds a secret, the caller must not commit/push/open a PR.

  - gitleaks_gate.scan_files(files) -> ScanResult(clean, leaks)
  - gitleaks_gate.added_leaks(original, fixed) -> the leaks only the fix has
"""

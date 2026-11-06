# tests/unit/

Pure Python, offline, `@pytest.mark.unit`. No network, no gitleaks binary — the
LLM (`agent.agent_loop.call_llm`) is mocked via the `fake_llm` fixture in `tests/conftest.py`.

Run: `pip install -r requirements.txt -r requirements-dev.txt && pytest -m unit`
(`requirements.txt` is needed too — `agent_loop.py` imports `llm/llm_client.py`, which
imports the real `httpx` package even though no network call is ever made in these tests.)

| File | Covers |
|---|---|
| `test_normaliser.py` | `normaliser/normaliser.py` — extraction/scoring helpers + a full `process_sarif_file` -> `build_ranked_unified` pass against the trimmed SARIF fixtures |
| `test_triage.py` | `triage/triage.py` — filtering, root/`covered_by` classification, batch naming + the SAST 10/11-file split boundary |
| `test_gitleaks_gate.py` | `secrets_scan/gitleaks_gate.py` — fail-closed exit-code semantics, traversal rejection |
| `test_git_gh_ops.py` | `gitops/git_gh_ops.py` — branch naming, path safety, PR title/body shape, the secrets gate, and `revert_uncommitted`'s untracked-file fallback (via a real throwaway git repo) |
| `test_agent_loop.py` | `agent/agent_loop.py` — prompt building, markdown-fence stripping, `process_batch`'s valid/empty/error paths |
| `test_llm_client.py`, `test_run_batch.py` | Thin orchestration modules — light coverage only (request shape / batch selection), per the plan's traceability matrix |
| `test_regression_gate.py` | `agent/regression_gate.py` — the pre-commit `test_fn` validity gate: valid/broken syntax per file type, unknown-type pass-through, and fail-closed vs fail-open on a missing toolchain |
| `test_snyk_rescan.py` | `tests/rescan/_snyk_rescan.py` — scan invocation (mocked `subprocess`: SARIF written, missing binary, no report written) + `diff_findings`'s remediated/persisted/introduced buckets (synthetic finding dicts) |

# tests/fixtures/

Trimmed copies of real ASVA pipeline output, kept small enough to check in but derived from
actual scans/batches rather than hand-invented — so unit tests exercise the real SARIF/batch
shapes.

## sarif/

`sca_sample.sarif.json`, `container_sample.sarif.json`, `sast_sample.sarif.json` — a handful
of results (+ only the rules they reference) pulled from `samples/scans/*.sarif.json`. Selected to
cover: a direct SCA dependency (`marked`) and a transitive one (`qs` via `body-parser`), a
CVSS 9.8 container finding that gets promoted to `critical`, and SAST results spanning
error/warning/note levels including one `node_modules/` hit (for triage's node_modules
filter).

`pip_remediation_sample.sarif.json` contains five results from the PyGoat run
`39011703898`, supplied in `pygoat-dashboard-package-1.zip` (`scan/sca.sarif.json`).
It retains each result's first dependency path and its rule's remediation section.
These real pip results have no `result.fixes`; the fixture covers extracting direct
dependency recommendations from `rule.help.markdown`, including multiple release
branches. It is maintained separately from `make_test_fixtures.py`.

Regenerate after a Snyk SARIF schema change:

```bash
python scripts/make_test_fixtures.py
```

Edit the `SELECTIONS` dict in that script to change which rule IDs / files get pulled.

## batches/

`asva_sast_e6919194_1.json`, `asva_sca_e6919194.json`, `asva_container_e6919194.json` — real
triage output, copied as-is from triage's `fix_batches/` output. Regenerate by re-running the real pipeline
(`normaliser.py` -> `triage.py`) against a fresh scan and copying its `fix_batches/*.json`
output here.

## findings/

`ranked_findings_sample.json` — the real, classified `findings/ranked_findings.json` (also in `samples/findings/`) (42
entries: 20 sca / 17 container / 5 sast), copied as-is. Covers `classify()`'s root vs
`covered_by` grouping and container's `docker-compose.yml` remapping. Does NOT cover the
SAST batch-split boundary (>10 files -> `_1`/`_2`) since this scan only touched 3 SAST
files — that case is synthesized directly in `test_triage.py` instead of needing a bigger
real fixture.

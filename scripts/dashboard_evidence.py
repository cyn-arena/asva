"""Build Peter's v0.1 dashboard evidence without depending on PR comments."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

APPS = {"nodegoat": "target-apps/NodeGoat", "pygoat": "target-apps/PyGoat"}


def identifier(value):
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", value) or ".." in value:
        raise ValueError(f"Invalid evidence identifier: {value!r}")
    return value


def candidate_run_id(parent, batch_id, sha, attempt):
    return identifier(f"{parent}-candidate-{batch_id}-{sha}-a{attempt}")


def read(path, default=None):
    path = Path(path)
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else default


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def command(args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, encoding="utf-8", errors="replace")


def collect_fixes(batch_dir, raw_path, source_dir, scanned_sha, app, agent_result,
                  run=command, metadata=None):
    """Retain every batch, including failed attempts; pin each opened candidate."""
    prefix = APPS[app] + "/"
    fixes, matrix, problems = [], [], []
    try:
        raw = {row["batch_id"]: row for row in read(raw_path, [])}
    except (ValueError, KeyError, TypeError) as exc:
        raw = {}
        problems.append(f"unreadable agent outcomes: {exc}")
    for path in sorted(Path(batch_dir).glob("*.json")):
        batch = read(path)
        bid = identifier(batch["batch_id"])
        row = dict(raw.get(bid, {"batch_id": bid,
            "status": "error" if agent_result != "skipped" else "not_attempted",
            "message": "No agent outcome was produced for this batch"}))
        row.update(batch_type=batch["batch_type"], pr_number=None, title="", body="", files=[])
        row.setdefault("branch", None)
        row.setdefault("pr_url", None)
        generation = row.get("generation") or {}
        if generation.get("method") == "llm" and generation.get("status") != "generated":
            problems.append(bid)
        if row.get("pr_url") and row.get("status") == "pr_opened":
            try:
                sha = run(["git", "rev-parse", "--verify", row["branch"] + "^{commit}"], source_dir).strip()
                row["candidate_sha"] = sha
                # Capture the actual locally generated change, not a later moving PR head.
                stats = run(["git", "diff", "--no-ext-diff", "--no-renames", "--numstat", "-z",
                             scanned_sha, sha, "--", APPS[app]], source_dir)
                for stat in filter(None, stats.split("\0")):
                    added, deleted, filename = stat.split("\t", 2)
                    if not filename.startswith(prefix):
                        raise ValueError("Fix diff escaped the application folder")
                    patch = run(["git", "--literal-pathspecs", "diff", "--no-ext-diff", "--no-renames",
                                 "--no-color", scanned_sha, sha, "--", filename], source_dir)
                    row["files"].append({"path": filename[len(prefix):], "filename": filename,
                        "additions": int(added) if added.isdigit() else 0,
                        "deletions": int(deleted) if deleted.isdigit() else 0, "patch": patch})
                matrix.append({"batch_id": bid, "branch": row["branch"], "sha": sha,
                               "pr_url": row["pr_url"], "status": "pr_opened"})
                details = metadata(row["pr_url"]) if metadata else json.loads(run([
                    "gh", "pr", "view", row["pr_url"], "--json", "number,title,body,state,isDraft"]))
                row.update(pr_number=details["number"], title=details["title"], body=details["body"])
                # Additive compatibility with Peter's current dashboard reader. Keep
                # the original v0.1 field names above rather than renaming them.
                row.update(number=details["number"], html_url=row["pr_url"],
                    state=details.get("state", "OPEN"), draft=details.get("isDraft", False),
                    head_branch=row["branch"], validation_path=f"validation/{bid}.json")
            except (subprocess.SubprocessError, OSError, ValueError, KeyError) as exc:
                row["evidence_error"] = f"Could not collect complete fix evidence: {exc}"
                problems.append(bid)
        fixes.append(row)
    return fixes, matrix, problems


def check(name, passed, detail=None, kind="smoke"):
    return {"name": name, "kind": kind, "status": "passed" if passed else "failed", "detail": detail}


def valid_check(row):
    return isinstance(row, dict) and isinstance(row.get("name"), str) and "detail" in row \
        and (row["detail"] is None or isinstance(row["detail"], str)) \
        and row.get("kind") in ("smoke", "misuse") and row.get("status") in ("passed", "failed", "skipped")


def junit(path, kind):
    if not Path(path).is_file():
        return [check(f"{kind} test evidence available", False, "Test report was not produced", kind)]
    try:
        cases = list(ET.parse(path).getroot().iter("testcase"))
        if not cases:
            return [check(f"{kind} tests executed", False, "Test report contains no test cases", kind)]
        rows = []
        for case in cases:
            failure = case.find("failure")
            if failure is None:
                failure = case.find("error")
            skipped = case.find("skipped")
            rows.append({"name": case.get("name", "unnamed test"), "kind": kind,
                "status": "failed" if failure is not None else "skipped" if skipped is not None else "passed",
                "detail": failure.get("message", "") if failure is not None else
                          skipped.get("message") if skipped is not None else None})
        return rows
    except (ET.ParseError, OSError) as exc:
        return [check(f"{kind} test report readable", False, str(exc), kind)]


def validation(*, app, batch_id, pr_url, sha, started, build_result, smoke_result,
               smoke_xml=None, smoke_json=None, matched_json=None, misuse_xml=None,
               selection_required=False, misuse_result="skipped", comment_result="skipped"):
    rows = [check("candidate image builds and containers start", build_result == "success",
                  None if build_result == "success" else f"Build/start step: {build_result}"),
            check("application becomes HTTP-ready", started,
                  None if started else "HTTP readiness was not demonstrated")]
    misuse_available = False
    out_of_scope = []
    if started:
        if smoke_json:
            try:
                report = read(smoke_json)
                if not isinstance(report, dict) or not report.get("checks") or not all(valid_check(c) for c in report["checks"]):
                    raise ValueError("Functional report missing or contains no checks")
                rows.extend(report["checks"])
            except (ValueError, OSError) as exc:
                rows.append(check("functional test evidence available", False, str(exc)))
        elif smoke_xml:
            rows.extend(junit(smoke_xml, "smoke"))
        if smoke_result != "success":
            rows.append(check("functional test execution completes", False, f"Smoke step: {smoke_result}"))
        if selection_required:
            try:
                selected = read(matched_json)
                if selected is None:
                    raise ValueError("Security-test selection report was not produced")
                if selected.get("matched_tests"):
                    misuse_available = True
                    # A shared file can select a case the batch never targeted. Report it
                    # separately so it cannot fail the candidate. Missing flags stay in scope.
                    unattempted = {m["test_name"] for m in selected["matched_tests"]
                                   if m.get("attempted") is False}
                    misuse_rows = junit(misuse_xml, "misuse")
                    for row in misuse_rows:
                        if row["name"].split("[")[0] in unattempted:
                            out_of_scope.append({**row, "scope": "not_targeted_by_batch"})
                        else:
                            rows.append(row)
                    # Only an unexplained step failure counts; scoped test failures are already rows.
                    if misuse_result != "success" and not any(
                            r["status"] == "failed" for r in misuse_rows):
                        rows.append(check("security test execution completes", False,
                                          f"Misuse step: {misuse_result}", "misuse"))
            except (ValueError, OSError) as exc:
                rows.append(check("security-test selection available", False, str(exc), "misuse"))
    return {"app": app, "batch_id": identifier(batch_id), "pr_url": pr_url,
        "commit_sha": sha, "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "app_started": started, "result": "passed" if all(c["status"] == "passed" for c in rows) else "failed",
        "checks": rows, "misuse_tests": "completed" if misuse_available else "not_available",
        **({"out_of_scope_checks": out_of_scope} if out_of_scope else {}),
        "reporting": {"pr_comment": comment_result}}


def stage(value):
    return {"success": "completed", "failure": "failed", "cancelled": "failed",
            "skipped": "not_available", "": "not_available"}.get(value, "not_available")


def scan_status(app, directory):
    reports, statuses = Path(directory), {}
    reports.mkdir(parents=True, exist_ok=True)
    for kind in ("sast", "sca", "container"):
        path = reports / ("image.sarif.json" if app == "nodegoat" and kind == "container" else f"{kind}.sarif.json")
        code = os.environ.get(kind.upper() + "_EXIT", "")
        statuses[kind] = {"exit_code": code, "status": "failed"}
        try:
            report = read(path)
            if code not in ("0", "1") or not isinstance(report, dict) or not report.get("runs"):
                raise ValueError("Scanner did not complete or valid SARIF is missing")
            statuses[kind]["status"] = "completed"
        except (ValueError, OSError) as exc:
            statuses[kind]["detail"] = str(exc)
    write(reports / "scan-status.json", {"app": app, "commit_sha": os.environ.get("GITHUB_SHA"),
        "run_id": os.environ.get("GITHUB_RUN_ID"), "scans": statuses})
    return all(row["status"] == "completed" for row in statuses.values())


def candidate_package(app, row, source, output, metadata, validation_report=None):
    """Additive v0.1 extension: one scan-only run per independent candidate."""
    bid, sha = identifier(row["batch_id"]), row.get("candidate_sha", "")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("Candidate evidence requires a full immutable SHA")
    parent = str(metadata["id"])
    run_id = candidate_run_id(parent, bid, sha, metadata.get("run_attempt", 1))
    errors, paths, scans = [], {}, {}
    try:
        status = read(source / "scan-status.json")
        if not isinstance(status, dict) or status.get("app") != app or status.get("batch_id") != bid \
                or status.get("commit_sha") != sha or status.get("after_fix_of") != parent \
                or str(status.get("run_attempt")) != str(metadata.get("run_attempt", 1)) \
                or status.get("pr_url") != row.get("pr_url") or status.get("source_verified") is not True \
                or not isinstance(status.get("scans"), dict) \
                or not all(isinstance(s, dict) for s in status["scans"].values()):
            raise ValueError("Candidate scan provenance missing or mismatched")
    except (ValueError, OSError) as exc:
        errors.append(str(exc))
        status = {}
    for kind in ("sast", "sca", "container"):
        recorded = status.get("scans", {}).get(kind, {})
        scans[kind] = {"status": "not_available", "detail": "Candidate scan evidence unavailable"}
        path = source / f"{kind}.sarif.json"
        if not status:
            continue
        scans[kind] = dict(recorded) if recorded.get("status") in ("completed", "failed", "not_available") else scans[kind]
        if scans[kind]["status"] == "completed" and str(recorded.get("exit_code")) not in ("0", "1"):
            scans[kind] = {"status": "failed", "detail": "Scanner completion exit code unavailable"}
        try:
            data = read(path)
            if not isinstance(data, dict) or not data.get("runs") or not all(
                    isinstance(r, dict) and isinstance(r.get("results"), list) for r in data["runs"]):
                raise ValueError("Valid SARIF was not produced")
            relative = f"scan/{kind}.sarif.json"
            write(output / relative, data)
            paths.setdefault("scan", {})[kind] = relative
        except (ValueError, OSError) as exc:
            if scans[kind]["status"] == "completed":
                scans[kind] = {"status": "failed", "detail": str(exc)}
        for log_name in (f"{kind}.log",):
            log = source / log_name
            if log.is_file():
                (output / "scan").mkdir(parents=True, exist_ok=True)
                shutil.copyfile(log, output / "scan" / log_name)
                paths.setdefault("scan_logs", []).append(f"scan/{log_name}")
    for name in ("install.log", "npm-version.log", "snyk-version.log", "image-build.log", "image-pull.log"):
        if status and (source / name).is_file():
            (output / "scan").mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / name, output / "scan" / name)
            paths.setdefault("scan_logs", []).append(f"scan/{name}")
    complete = all(s["status"] == "completed" for s in scans.values())
    findings, findings_status = [], "not_available"
    if status.get("normalise") == "completed" and any(s["status"] == "completed" for s in scans.values()):
        try:
            findings = read(source / "findings/ranked_unified_findings.json")
            if not isinstance(findings, list):
                raise ValueError("Normalised candidate findings missing")
            findings_status = "completed" if complete else "partial"
        except (ValueError, OSError) as exc:
            errors.append(str(exc))
            findings = []
    paths["findings"] = "findings/ranked_unified_findings.json"
    # Existing dashboards only understand not_available as an incomplete result.
    # Keep partial observations in a sidecar until readers can compare scan scopes.
    if findings_status == "partial":
        paths["partial_findings"] = "findings/partial_unified_findings.json"
        write(output / paths["partial_findings"], findings)
    write(output / paths["findings"], findings if findings_status == "completed" else [])
    paths["scan_status"] = "scan/scan-status.json"
    write(output / paths["scan_status"], {**status, "scans": scans})
    validation_stage = "not_available"
    if validation_report:
        paths["validation"] = [f"validation/{bid}.json"]
        write(output / paths["validation"][0], validation_report)
        validation_stage = "completed" if validation_report["result"] == "passed" else "failed"
    manifest = {"schema_version": "0.1", "app": app, "run_id": run_id,
        "commit_sha": sha, "candidate_sha": sha, "batch_id": bid, "pr_url": row.get("pr_url"),
        "branch": row.get("branch"), "workflow": metadata["name"], "workflow_url": metadata["html_url"],
        "created_at": metadata.get("run_started_at") or metadata["created_at"],
        "scan_kind": "after_fix", "after_fix_of": parent, "evidence_scope": "independent_candidate",
        "fix_generation": "disabled", "artifacts": paths,
        "artifact_status": {"findings": "completed" if findings_status == "completed" else "not_available",
                            **({"partial_findings": "partial"} if findings_status == "partial" else {})},
        "scan_status": scans,
        "stages": {"scan": "completed" if complete else "failed",
                   "normalise": "completed" if findings_status != "not_available" else
                                "failed" if status.get("normalise") == "failed" else "not_available",
                   "triage": "not_available", "fix": "not_available", "validate": validation_stage},
        "evidence_errors": errors}
    write(output / "manifest.json", manifest)
    return {"run_id": run_id, "batch_id": bid, "candidate_sha": sha, "pr_url": row.get("pr_url"),
            "manifest": f"{app}/{run_id}/manifest.json",
            "status": "completed" if complete and findings_status == "completed" else "failed"}


def package(app, artifacts_dir, output_dir, metadata, outcomes, scan_kind="initial", after_fix_of=None):
    """Only publish files from this app/run, retaining failure and missing-evidence status."""
    identifier(app)
    run_id = str(metadata["id"])
    identifier(run_id)
    if scan_kind not in ("initial", "after_fix"):
        raise ValueError("Invalid scan_kind")
    if scan_kind == "after_fix":
        if not re.fullmatch(r"[0-9]+", after_fix_of or "") or after_fix_of == run_id:
            raise ValueError("An after-fix run requires a different original run ID")
    elif after_fix_of:
        raise ValueError("after_fix_of is only valid for after_fix runs")
    sha = metadata["head_sha"]
    created = metadata.get("run_started_at") or metadata["created_at"]
    root, output = Path(artifacts_dir), Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("Dashboard package destination must be empty")
    scan = root / f"{app}-scan-results"
    fix = root / f"{app}-fix-output"
    errors, paths = [], {}
    def load(source, default, expected):
        try:
            value = read(source, default)
            if not isinstance(value, expected):
                raise ValueError(f"Expected {expected.__name__}")
            return value
        except (ValueError, OSError) as exc:
            errors.append(f"Unreadable {source.name}: {exc}")
            return default

    download_result = os.environ.get("EVIDENCE_DOWNLOAD_RESULT", "success")
    if download_result != "success":
        errors.append(f"Evidence download did not complete: {download_result}")
    scan_paths = {}
    for kind in ("sast", "sca", "container"):
        source = scan / ("image.sarif.json" if app == "nodegoat" and kind == "container" else f"{kind}.sarif.json")
        if source.is_file():
            try:
                report = read(source)
                if not isinstance(report, dict) or not report.get("runs"):
                    raise ValueError("No SARIF run found")
                dest = f"scan/{kind}.sarif.json"
                (output / "scan").mkdir(exist_ok=True)
                shutil.copyfile(source, output / dest)
                scan_paths[kind] = dest
            except (ValueError, OSError) as exc:
                errors.append(f"{kind} scan evidence unavailable: {exc}")
    if scan_paths:
        paths["scan"] = scan_paths
    findings = load(fix / "findings/ranked_unified_findings.json", None, list)
    # A manually requested after-fix run also stops at scanning. Normalise its
    # available reports here without invoking triage, the agent or GitOps.
    manual_normalise = None
    if scan_kind == "after_fix" and findings is None and scan_paths:
        from normaliser.normaliser import process_sarif_file, deduplicate, sort_findings, assign_priorities, build_ranked_unified
        try:
            observations = [finding for path in scan_paths.values()
                            for finding in process_sarif_file(output / path, strict=True)]
            findings = build_ranked_unified(assign_priorities(sort_findings(deduplicate(observations))))
            manual_normalise = "completed"
        except (OSError, ValueError, TypeError) as exc:
            errors.append(f"After-fix normalisation failed: {exc}")
            manual_normalise = "failed"
    findings_available = findings is not None
    # Peter requires this path even for incomplete runs. An explicit status prevents
    # an empty placeholder from being mistaken for a successful vulnerability-free scan.
    write(output / "findings/ranked_unified_findings.json", findings if findings_available else [])
    paths["findings"] = "findings/ranked_unified_findings.json"
    if not findings_available:
        errors.append("Normalised findings unavailable; required findings file is an empty placeholder")
    triage_path = fix / "findings/ranked_findings.json"
    triage = load(triage_path, None, list) if triage_path.is_file() else None
    if triage is not None:
        write(output / "findings/ranked_findings.json", triage)
        paths["triage"] = "findings/ranked_findings.json"
    batches = []
    for source in sorted((fix / "fix_batches").glob("*.json")):
        batch = load(source, {}, dict)
        try:
            bid = identifier(batch["batch_id"])
        except (ValueError, KeyError, TypeError):
            errors.append(f"Invalid batch evidence: {source.name}")
            continue
        relative = f"remediation/fix_batches/{bid}.json"
        write(output / relative, batch)
        batches.append(relative)
    if batches:
        paths["fix_batches"] = batches
    fixes = load(fix / "fixes.json", None, list) if (fix / "fixes.json").is_file() else None
    if fixes is not None and any(not isinstance(row, dict) or not row.get("batch_id") for row in fixes):
        errors.append("Invalid fix evidence rows")
        fixes = None
    if fixes is not None:
        write(output / "remediation/fixes.json", fixes)
        paths["remediation"] = "remediation/fixes.json"
        paths["fixes"] = "remediation/fixes.json"
    validations = []
    for row in fixes or []:
        if row.get("status") != "pr_opened":
            continue
        bid = identifier(row["batch_id"])
        source = root / f"{app}-validation-{bid}" / "validation" / f"{bid}.json"
        try:
            report = read(source)
        except (ValueError, OSError) as exc:
            errors.append(f"Unreadable validation report for {bid}: {exc}")
            report = None
        if report is not None and (not isinstance(report, dict) or report.get("batch_id") != bid
                or report.get("result") not in ("passed", "failed") or not report.get("checks")
                or not isinstance(report.get("app_started"), bool) or not report.get("checked_at")
                or not all(valid_check(c) for c in report.get("checks", []))
                or (report.get("result") == "passed" and (not report.get("app_started")
                    or any(c["status"] != "passed" for c in report["checks"])))):
            errors.append(f"Invalid validation report for {bid}")
            report = None
        if report and report.get("commit_sha") != row.get("candidate_sha"):
            errors.append(f"Validation SHA mismatch for {bid}; ignored stale report")
            report = None
        if report is None:
            report = {"batch_id": bid, "pr_url": row.get("pr_url"),
                "commit_sha": row.get("candidate_sha", ""),
                "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "app_started": False, "result": "failed", "evidence_available": False,
                "checks": [check("candidate validation evidence available", False,
                    f"Validation report unavailable; job outcome: {outcomes.get('validate', 'skipped')}")]}
        relative = f"validation/{bid}.json"
        write(output / relative, report)
        validations.append(relative)
    if validations:
        paths["validation"] = validations
    status = load(fix / "stage-status.json", {}, dict)
    errors.extend(f"Incomplete fix evidence for {bid}" for bid in status.get("evidence_errors", []))
    stages = {"scan": stage(outcomes.get("scan", "")),
              "normalise": stage(status.get("normalise", "")),
              "triage": stage(status.get("triage", "")),
              "fix": stage(status.get("fix", outcomes.get("fix", ""))),
              "validate": stage(outcomes.get("validate", ""))}
    if stages["scan"] == "completed" and len(scan_paths) != 3:
        stages["scan"] = "failed"
        errors.append("Scan job completed without all three valid SARIF reports")
    recorded_scan = load(scan / "scan-status.json", {}, dict)
    if recorded_scan:
        paths["scan_status"] = "scan/scan-status.json"
        write(output / paths["scan_status"], recorded_scan)
    for log in sorted(scan.glob("*.log")):
        (output / "scan").mkdir(parents=True, exist_ok=True)
        shutil.copyfile(log, output / "scan" / log.name)
        paths.setdefault("scan_logs", []).append(f"scan/{log.name}")
    if any(row.get("status") != "completed" for row in recorded_scan.get("scans", {}).values()):
        stages["scan"] = "failed"
    if status.get("evidence_errors"):
        stages["fix"] = "failed"
    if stages["normalise"] == "completed" and not findings_available:
        stages["normalise"] = "failed"
    if stages["triage"] == "completed" and triage is None:
        stages["triage"] = "failed"
    if stages["fix"] == "completed" and fixes is None:
        stages["fix"] = "failed"
    if validations:
        stages["validate"] = "completed" if all(read(output / p)["result"] == "passed" for p in validations) else "failed"
    manifest = {"schema_version": "0.1", "app": app, "run_id": run_id,
        "commit_sha": sha[:8], "branch": metadata["head_branch"], "workflow": metadata["name"],
        "created_at": created, "workflow_url": metadata["html_url"],
        "scan_kind": scan_kind, "stages": stages, "artifacts": paths,
        "artifact_status": {"findings": "completed" if findings_available else "not_available"},
        "job_outcomes": outcomes, "evidence_errors": errors}
    if manual_normalise:
        stages["normalise"] = manual_normalise
        if findings_available and stages["scan"] != "completed":
            paths["partial_findings"] = "findings/partial_unified_findings.json"
            write(output / paths["partial_findings"], findings)
            write(output / paths["findings"], [])
            manifest["artifact_status"].update(findings="not_available", partial_findings="partial")
    candidates = []
    for row in fixes or []:
        if row.get("status") != "pr_opened" or not row.get("candidate_sha"):
            continue
        bid = identifier(row["batch_id"])
        candidate_id = candidate_run_id(run_id, bid, row["candidate_sha"], metadata.get("run_attempt", 1))
        candidates.append(candidate_package(app, row, root / f"{app}-after-fix-{bid}",
            output / "candidates" / candidate_id, metadata, read(output / f"validation/{bid}.json")))
    if candidates:
        manifest["candidate_scans"] = candidates
    for baseline in sorted(root.glob(f"{app}-baseline-*"), reverse=True):
        baseline_report = load(baseline / f"{app}-baseline.json", {}, dict)
        if baseline_report and baseline_report.get("commit_sha") == sha:
            write(output / "validation/baseline.json", baseline_report)
            manifest["artifacts"]["baseline_validation"] = "validation/baseline.json"
            manifest["baseline_status"] = baseline_report["result"]
            break
    if scan_kind == "after_fix":
        manifest["after_fix_of"] = after_fix_of
    write(output / "manifest.json", manifest)
    return manifest


def upload(directory, app, run_id, legacy=False, run=subprocess.run, account=None, container=None):
    """Upload data first and the manifest last; no new dashboard run until data is ready.

    The Azure storage account and container come from the arguments, or else from
    ASVA_AZURE_STORAGE_ACCOUNT and ASVA_AZURE_STORAGE_CONTAINER."""
    account = account or os.environ.get("ASVA_AZURE_STORAGE_ACCOUNT")
    container = container or os.environ.get("ASVA_AZURE_STORAGE_CONTAINER")
    if not account or not container:
        raise ValueError("Set ASVA_AZURE_STORAGE_ACCOUNT and ASVA_AZURE_STORAGE_CONTAINER "
                         "(or pass --account and --container)")
    identifier(app)
    identifier(str(run_id))
    root = Path(directory).resolve()
    manifest = read(root / "manifest.json")
    if manifest["app"] != app or manifest["run_id"] != str(run_id):
        raise ValueError("Upload destination does not match the manifest")
    for candidate in manifest.get("candidate_scans", []):
        candidate_id = identifier(candidate["run_id"])
        folder = root / "candidates" / candidate_id
        if folder.is_symlink() or not folder.resolve().is_relative_to(root):
            raise ValueError("Candidate package escaped its parent folder")
        upload(folder, app, candidate_id, run=run, account=account, container=container)
    files = sorted(p for p in root.rglob("*") if p.is_file() and p.name != "manifest.json"
                   and p.relative_to(root).parts[0] != "candidates")
    for path in files:
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError("Package contains a path outside its folder")
        name = f"{app}/{run_id}/{path.relative_to(root).as_posix()}"
        run(["az", "storage", "blob", "upload", "--account-name", account,
             "--container-name", container, "--name", name, "--file", str(path),
             "--overwrite", "true", "--auth-mode", "login", "--content-type",
             "application/json" if path.suffix == ".json" else "text/plain",
             "--only-show-errors"], check=True)
    if legacy:
        for kind, relative in manifest["artifacts"].get("scan", {}).items():
            alias = "image" if kind == "container" else kind
            name = f"{app}/{alias}-{app}-{run_id}-{manifest['commit_sha'][:7]}.json"
            run(["az", "storage", "blob", "upload", "--account-name", account,
                 "--container-name", container, "--name", name, "--file", str(root / relative),
                 "--overwrite", "true", "--auth-mode", "login", "--only-show-errors"], check=True)
    run(["az", "storage", "blob", "upload", "--account-name", account,
         "--container-name", container, "--name", f"{app}/{run_id}/manifest.json",
         "--file", str(root / "manifest.json"), "--overwrite", "true", "--auth-mode", "login",
         "--content-type", "application/json", "--only-show-errors"], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    fixes = commands.add_parser("fixes")
    fixes.add_argument("--app", choices=APPS, required=True)
    fixes.add_argument("--results-dir", type=Path, required=True)
    fixes.add_argument("--source-dir", required=True)
    fixes.add_argument("--scanned-sha", required=True)
    fixes.add_argument("--agent-result", required=True)
    record = commands.add_parser("validate")
    record.add_argument("--app", choices=APPS, required=True)
    record.add_argument("--batch-id", required=True)
    record.add_argument("--pr-url", required=True)
    record.add_argument("--sha", default="")
    record.add_argument("--started", choices=("true", "false"), required=True)
    record.add_argument("--build-result", required=True)
    record.add_argument("--smoke-result", required=True)
    record.add_argument("--smoke-xml")
    record.add_argument("--smoke-json")
    record.add_argument("--matched-json")
    record.add_argument("--misuse-xml")
    record.add_argument("--selection-required", action="store_true")
    record.add_argument("--misuse-result", default="skipped")
    record.add_argument("--comment-result", default="skipped")
    record.add_argument("--output", required=True)
    pack = commands.add_parser("package")
    pack.add_argument("--app", choices=APPS, required=True)
    pack.add_argument("--artifacts", required=True)
    pack.add_argument("--output", required=True)
    pack.add_argument("--metadata", required=True)
    send = commands.add_parser("upload")
    send.add_argument("--directory", required=True)
    send.add_argument("--app", choices=APPS, required=True)
    send.add_argument("--run-id", required=True)
    send.add_argument("--legacy", action="store_true")
    send.add_argument("--account", help="Azure storage account (default: $ASVA_AZURE_STORAGE_ACCOUNT)")
    send.add_argument("--container", help="Blob container (default: $ASVA_AZURE_STORAGE_CONTAINER)")
    scan = commands.add_parser("scan-status")
    scan.add_argument("--app", choices=APPS, required=True)
    scan.add_argument("--directory", required=True)
    args = parser.parse_args()
    if args.operation == "fixes":
        rows, matrix, errors = collect_fixes(args.results_dir / "fix_batches", args.results_dir / "prs.json",
            args.source_dir, args.scanned_sha, args.app, args.agent_result)
        write(args.results_dir / "fixes.json", rows)
        write(args.results_dir / "stage-status.json", {
            "normalise": os.environ.get("NORMALISE_RESULT", "skipped"),
            "triage": os.environ.get("TRIAGE_RESULT", "skipped"), "fix": args.agent_result,
            "evidence_errors": errors})
        if os.environ.get("GITHUB_OUTPUT"):
            with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
                output.write("prs=" + json.dumps(matrix, separators=(",", ":")) + "\n")
        return 1 if errors else 0
    if args.operation == "validate":
        values = vars(args).copy()
        for key in ("operation", "output"):
            values.pop(key)
        values["started"] = args.started == "true"
        report = validation(**values)
        write(args.output, report)
        return 0 if report["result"] == "passed" else 1
    if args.operation == "package":
        package(args.app, args.artifacts, args.output, read(args.metadata),
                json.loads(os.environ["STAGE_OUTCOMES"]), os.environ.get("SCAN_KIND", "initial"),
                os.environ.get("AFTER_FIX_OF") or None)
    if args.operation == "upload":
        upload(args.directory, args.app, args.run_id, args.legacy,
               account=args.account, container=args.container)
    if args.operation == "scan-status":
        return 0 if scan_status(args.app, args.directory) else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

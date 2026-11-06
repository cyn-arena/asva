import time

import pytest
from fastapi.testclient import TestClient

from app.main import create_app, ensure_db

FINDING = {
    "finding_type": "sast", "cwe": "CWE-94", "rule_id": "javascript/CodeInjection",
    "title": "Code Injection", "summary": "User input flows into eval, where it is executed as code.",
}
TOKEN = "s3cret-admin-token"


@pytest.fixture
def client(db_path, fake_embedder, http_client):
    app = create_app(db_path=db_path, embedder=fake_embedder, client=http_client, admin_token=TOKEN)
    with TestClient(app) as test_client:
        yield test_client


def auth(token=TOKEN):
    return {"Authorization": f"Bearer {token}"}


def test_healthz_reports_status_snapshot_and_counts(client):
    body = client.get("/healthz").json()
    assert body["status"] == "ok"
    assert body["schema_version"] == "1"
    assert body["snapshot"]["MITRE CWE"]["version"] == "9.9 (2026-01-01)"
    assert body["counts"]["records"] == 4


def test_healthz_reports_empty_store(tmp_path, fake_embedder, http_client):
    app = create_app(db_path=tmp_path / "empty.db", embedder=fake_embedder, client=http_client)
    with TestClient(app) as empty:
        assert empty.get("/healthz").json()["status"] == "empty"


def test_context_returns_versioned_contract(client):
    response = client.post("/v1/context", json={"fix_type": "code_change", "findings": [FINDING]})
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"schema_version", "snapshot", "items", "references", "upgrades", "trials", "warnings", "debug"}
    assert body["schema_version"] == "1" and body["debug"] is None
    assert body["items"][0]["kind"] == "guidance"
    cwe_ref = next(r for r in body["references"] if r["type"] == "cwe")
    assert cwe_ref["id"] == "CWE-94" and cwe_ref["owasp_top10"] == ["A03:2021 - Injection", "A05:2025 - Injection"]


def test_context_dependency_upgrade_end_to_end(client):
    finding = {"finding_type": "sca", "cve": "CVE-2016-10531", "package": "marked@0.3.5", "ecosystem": "npm",
               "upgrade_to": "marked@0.3.6", "dependency_path": ["owasp-nodejs-goat@1.3.0", "marked@0.3.5"]}
    body = client.post("/v1/context", json={"fix_type": "version_upgrade", "findings": [finding]}).json()
    assert body["items"][0]["kind"] == "upgrade_notes"
    assert any(r["type"] == "cve" and r["cvss"] == 6.1 for r in body["references"])


def test_context_debug_explains_the_search(client):
    body = client.post("/v1/context", json={"fix_type": "code_change", "findings": [FINDING], "debug": True}).json()
    debug = body["debug"]
    assert debug["resolved_cwes"] == ["CWE-94"]
    assert debug["guidance_search"] == "ran"
    assert debug["queries"][0]["text"].startswith("JavaScript Node.js: how to prevent and fix Code Injection.")


def test_context_debug_says_why_guidance_was_skipped(client):
    body = client.post("/v1/context", json={"fix_type": "version_upgrade", "findings": [FINDING], "debug": True}).json()
    assert body["debug"]["guidance_search"] == "skipped (no prose guidance for version_upgrade)"


def test_context_ignores_extra_finding_fields(client):
    finding = {**FINDING, "location": {"file": "app/routes/contributions.js", "line": 32}, "priority": 63}
    assert client.post("/v1/context", json={"findings": [finding]}).status_code == 200


def test_context_rejects_empty_findings(client):
    assert client.post("/v1/context", json={"findings": []}).status_code == 422


def test_context_rejects_out_of_range_budget(client):
    assert client.post("/v1/context", json={"findings": [FINDING], "max_chars": 10}).status_code == 422


def test_get_cwe_returns_entry_parents_and_top10(client):
    body = client.get("/v1/cwe/94").json()
    assert body["key"] == "CWE-94"
    assert body["parents"] == ["CWE-74", "CWE-913"]
    assert body["owasp_top10"] == ["A03:2021 - Injection", "A05:2025 - Injection"]


def test_get_unknown_cwe_is_404(client):
    assert client.get("/v1/cwe/CWE-424242").status_code == 404


# -- admin sync ------------------------------------------------------------------------

def test_admin_sync_is_disabled_without_a_token(db_path, fake_embedder, http_client):
    app = create_app(db_path=db_path, embedder=fake_embedder, client=http_client, admin_token="")
    with TestClient(app) as no_admin:
        assert no_admin.post("/admin/sync", json={}, headers=auth()).status_code == 404


def test_admin_sync_rejects_a_wrong_token(client):
    assert client.post("/admin/sync", json={}, headers=auth("wrong")).status_code == 401
    assert client.get("/admin/sync").status_code == 401


def test_admin_sync_rejects_unknown_sources(client):
    assert client.post("/admin/sync", json={"sources": ["nope"]}, headers=auth()).status_code == 422


def test_admin_sync_runs_in_the_background(client):
    response = client.post("/admin/sync", json={"sources": ["kev"]}, headers=auth())
    assert response.status_code == 202 and response.json()["state"] == "running"
    for _ in range(100):
        status = client.get("/admin/sync", headers=auth()).json()
        if status["state"] != "running":
            break
        time.sleep(0.05)
    assert status["state"] == "done"
    assert "known-exploited CVEs" in status["results"][0]
    assert client.get("/healthz").json()["snapshot"]["CISA KEV"]["items"] == 2


def test_admin_sync_refuses_a_second_concurrent_run(client):
    runner = client.app.state.sync
    runner.status["state"] = "running"
    assert client.post("/admin/sync", json={}, headers=auth()).status_code == 409
    runner.status["state"] = "idle"


# -- startup ------------------------------------------------------------------------------

def test_ensure_db_seeds_an_empty_volume_from_the_snapshot(tmp_path, db_path):
    target = tmp_path / "volume" / "security_context.db"
    ensure_db(target, db_path)
    assert target.exists() and target.stat().st_size > 0


def test_ensure_db_leaves_a_current_database_alone(tmp_path, db_path):
    from app import store
    live = tmp_path / "live.db"
    with store.connect(live) as conn:  # new database: current format
        store.upsert_records(conn, "NVD", [{"key": "CVE-1", "kind": "cve", "text": "cached"}])
        conn.commit()
    assert ensure_db(live, db_path) == []


def test_ensure_db_reseeds_builtin_sources_after_an_upgrade_and_keeps_cached_lookups(tmp_path, db_path):
    from app import store
    live = tmp_path / "live.db"
    with store.connect(live) as conn:
        store.upsert_records(conn, "NVD", [{"key": "CVE-1", "kind": "cve", "text": "cached lookup"}])
        store.replace_source_records(conn, "MITRE CWE", [{"key": "CWE-1", "kind": "cwe", "text": "old"}])
        store.set_sync_state(conn, "MITRE CWE", "old", 1)
        conn.execute("DELETE FROM meta")  # pretend it was built by the POC (format 1)
        conn.commit()

    assert set(ensure_db(live, db_path)) == {"MITRE CWE", "OWASP Cheat Sheet Series"}
    with store.connect(live) as conn:
        assert store.get_record(conn, "CWE-94", "MITRE CWE") is not None      # from the snapshot
        assert store.get_record(conn, "CWE-1", "MITRE CWE") is None           # old copy replaced
        assert store.get_record(conn, "CVE-1", "NVD")["text"] == "cached lookup"  # cache kept
        assert store.linked(conn, "CWE-94", "owasp_top10")                    # Top 10 links arrived
        assert store.get_format(conn) == store.FORMAT
    assert ensure_db(live, db_path) == []  # second start: nothing to do


def test_ensure_db_takes_a_newer_version_of_a_builtin_source_and_keeps_the_cache(tmp_path, db_path):
    # the database kept between pipeline runs, started with a rebuilt image whose CWE copy is newer
    from app import store
    live = tmp_path / "live.db"
    with store.connect(live) as conn:
        store.upsert_records(conn, "NVD", [{"key": "CVE-1", "kind": "cve", "text": "cached lookup"}])
        store.replace_source_records(conn, "MITRE CWE", [{"key": "CWE-1", "kind": "cwe", "text": "old"}])
        store.set_sync_state(conn, "MITRE CWE", "old", 1, synced_at="2020-01-01T00:00:00Z")
        conn.commit()
    assert ensure_db(live, db_path) == ["MITRE CWE"]
    with store.connect(live) as conn:
        assert store.get_record(conn, "CWE-94", "MITRE CWE") is not None and store.get_record(conn, "CWE-1", "MITRE CWE") is None
        assert store.get_record(conn, "CVE-1", "NVD")["text"] == "cached lookup"
    assert ensure_db(live, db_path) == []  # now the same version


def test_ensure_db_keeps_a_builtin_source_the_database_synced_more_recently(tmp_path, db_path):
    from app import store
    live = tmp_path / "live.db"
    with store.connect(live) as conn:
        store.replace_source_records(conn, "MITRE CWE", [{"key": "CWE-1", "kind": "cwe", "text": "synced later"}])
        store.set_sync_state(conn, "MITRE CWE", "newer", 1, synced_at="2999-01-01T00:00:00Z")
        conn.commit()
    assert ensure_db(live, db_path) == []
    with store.connect(live) as conn:
        assert store.get_record(conn, "CWE-1", "MITRE CWE")["text"] == "synced later"


def test_context_returns_upgrade_data_for_a_dependency(client):
    finding = {"finding_type": "sca", "cve": "CVE-2016-10531", "package": "marked@0.3.5", "ecosystem": "npm",
               "upgrade_to": "marked@0.3.6", "dependency_path": ["owasp-nodejs-goat@1.3.0", "marked@0.3.5"]}
    body = client.post("/v1/context", json={"fix_type": "version_upgrade", "findings": [finding]}).json()
    assert body["upgrades"] == [{
        "kind": "package", "name": "marked", "ecosystem": "npm", "current": "0.3.5", "target": "0.3.6",
        "target_source": "scanner", "compatible_target": "0.3.6", "compatible_scope": "all", "min_fixed": "0.3.6",
        "major_change": False, "status": "ok",
        "fixes": ["CVE-2016-10531"], "candidates": None, "fallbacks": [], "note": None}]


def test_context_can_answer_without_a_source(client):
    finding = {"finding_type": "sca", "cve": "CVE-2016-10531", "package": "marked@0.3.5", "ecosystem": "npm",
               "upgrade_to": "marked@0.3.6"}
    request = {"fix_type": "version_upgrade", "findings": [finding], "debug": True}
    with_nvd = client.post("/v1/context", json=request).json()
    without = client.post("/v1/context", json={**request, "exclude_sources": ["nvd", "OSV"]}).json()
    assert next(r for r in with_nvd["references"] if r["type"] == "cve")["cvss"] == 6.1
    assert next(r for r in without["references"] if r["type"] == "cve")["cvss"] is None
    assert not any(r["type"] == "advisory" for r in without["references"])
    assert without["debug"]["excluded_sources"] == ["nvd", "osv"]


def test_context_warns_about_an_unknown_source_name(client):
    body = client.post("/v1/context", json={"findings": [FINDING], "exclude_sources": ["nvdd"]}).json()
    assert any("Unknown source(s) ignored: nvdd" in w for w in body["warnings"])


def test_healthz_lists_sources_switched_off_in_the_configuration(client, monkeypatch):
    from app import config
    monkeypatch.setattr(config, "DISABLED_SOURCES", frozenset({"dockerhub", "endoflife"}))
    assert client.get("/healthz").json()["disabled_sources"] == ["dockerhub", "endoflife"]


def test_api_returns_the_trial_plan_and_the_client_writes_it_for_the_pr(client, apis):
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "integration"))
    import asva_rag_client
    finding = {"finding_type": "sca", "cve": "CVE-2016-10531", "package": "mongodb@2.2.36", "ecosystem": "npm",
               "upgrade_to": "mongodb@3.1.13"}
    body = client.post("/v1/context", json={"fix_type": "version_upgrade", "findings": [finding],
                                            "manifest": {"file": "package.json", "content": '{"dependencies": {"mongodb": "^2.1.18"}}'}}).json()
    assert [(t["kind"], t["name"], t["target"]) for t in body["trials"]] == [("major_upgrade", "mongodb", "3.1.13")]
    markdown = asva_rag_client.trial_plan(body)
    assert markdown.startswith("### Upgrades to try next, one at a time") and "`mongodb` 2.2.36 → 3.1.13" in markdown

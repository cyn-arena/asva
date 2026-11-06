"""HTTP API.

  GET  /healthz          status, loaded snapshot and table counts (Docker/Kubernetes probes)
  POST /v1/context       prompt context, references and upgrade data for one file's findings
  GET  /v1/cwe/{cwe_id}  one CWE entry, its parents and OWASP Top 10 categories
  POST /admin/sync       start a background source sync (needs ADMIN_TOKEN)
  GET  /admin/sync       status of the last sync (needs ADMIN_TOKEN)

Run locally:  uvicorn app.main:app --port 8800
"""

import shutil
from contextlib import asynccontextmanager, closing
from pathlib import Path

import httpx
from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from app import admin, config, net, store
from app import sync as sync_sources
from app.context import ContextBuilder
from app.embed import Embedder
from app.models import SCHEMA_VERSION, ContextRequest, ContextResponse, SyncRequest
from app.retrieve import Retriever, normalise_cwe
from app.sources import cwe as cwe_source


def ensure_db(db_path: Path, snapshot_path: Path | None) -> list[str]:
    """Seed the data volume from the snapshot baked into the image: a full copy on first start;
    later, a refresh of each built-in source the image has a newer version or format of (cached
    online lookups are kept). Returns the re-seeded sources."""
    if not snapshot_path or not snapshot_path.exists():
        return []
    if not db_path.exists():
        db_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(snapshot_path, db_path)
        return ["(full copy)"]
    with closing(store.connect(db_path)) as conn:
        return store.reseed_from_snapshot(conn, snapshot_path)


def create_app(db_path: Path | None = None, embedder=None, client: httpx.Client | None = None,
               online: bool = config.ONLINE_LOOKUPS, admin_token: str = config.ADMIN_TOKEN) -> FastAPI:
    db_path = Path(db_path or config.DB_PATH)

    def db():
        return closing(store.connect(db_path))  # one connection per request (sqlite3 is per-thread)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        ensure_db(db_path, config.SNAPSHOT_PATH)
        active_embedder = embedder or Embedder()
        http = client or net.make_client()

        def load_retriever() -> Retriever:
            with db() as conn:
                return Retriever.from_db(conn, active_embedder)

        app.state.builder = ContextBuilder(load_retriever(), http, online=online)

        def run_sync(sources, force):
            with db() as conn:
                return sync_sources.run(conn, http, sources, force, embedder_factory=lambda: active_embedder)

        def reload():  # pick up re-embedded OWASP passages
            app.state.builder.retriever = load_retriever()

        app.state.sync = admin.SyncRunner(run_sync, reload)
        active_embedder.embed(["warm-up"])  # load the model now, not on the first request
        yield
        if client is None:
            http.close()

    app = FastAPI(title="ASVA Security Context Service", version="1.0.0", lifespan=lifespan)

    @app.get("/healthz")
    def healthz():
        with db() as conn:
            counts = store.counts(conn)
            return {"status": "ok" if counts["records"] and counts["chunks"] else "empty",
                    "schema_version": SCHEMA_VERSION,
                    "online": {"lookups": online, "nvd_api_key": bool(config.NVD_API_KEY),
                               "nvd_sync_mode": config.NVD_SYNC_MODE, "context7": bool(config.CONTEXT7_API_KEY)},
                    "disabled_sources": sorted(config.DISABLED_SOURCES),
                    "snapshot": store.snapshot(conn), "counts": counts}

    @app.post("/v1/context", response_model=ContextResponse)
    def context(body: ContextRequest, request: Request):
        trace = {} if body.debug else None
        with db() as conn:
            findings = [f.model_dump() for f in body.findings]
            builder = request.app.state.builder
            items, references, warnings, upgrades = builder.build(
                conn, findings, body.fix_type, body.max_chars, trace=trace, exclude=body.exclude_sources or ())
            trials = builder.plan_trials(conn, findings, upgrades, references,
                                         body.manifest.model_dump() if body.manifest else None, warnings,
                                         exclude=body.exclude_sources or ()) if upgrades else []
            return ContextResponse(snapshot=store.snapshot(conn), items=items, references=references,
                                   upgrades=upgrades, trials=trials, warnings=warnings, debug=trace)

    @app.get("/v1/cwe/{cwe_id}")
    def get_cwe(cwe_id: str):
        key = normalise_cwe(cwe_id)
        with db() as conn:
            record = store.get_record(conn, key, cwe_source.SOURCE) if key else None
            if record is None:
                raise HTTPException(status_code=404, detail=f"{cwe_id} not found")
            return {**{k: record[k] for k in ("key", "title", "text", "url", "license", "fetched_at")},
                    "parents": store.linked(conn, key, "child_of"), "owasp_top10": cwe_source.top10(conn, key)}

    def require_admin(authorization: str | None) -> None:
        if not admin_token:
            raise HTTPException(status_code=404, detail="admin endpoints are disabled (set ADMIN_TOKEN)")
        if not admin.token_ok(admin_token, authorization):
            raise HTTPException(status_code=401, detail="invalid admin token")

    @app.post("/admin/sync", status_code=202)
    def start_sync(body: SyncRequest, request: Request, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        unknown = set(body.sources or []) - set(sync_sources.SOURCES)
        if unknown:
            raise HTTPException(status_code=422, detail=f"unknown sources: {sorted(unknown)}")
        if not request.app.state.sync.start(body.sources, body.force):
            return JSONResponse(status_code=409, content={"detail": "a sync is already running",
                                                          **request.app.state.sync.status})
        return request.app.state.sync.status

    @app.get("/admin/sync")
    def sync_status(request: Request, authorization: str | None = Header(default=None)):
        require_admin(authorization)
        return request.app.state.sync.status

    return app


app = create_app()

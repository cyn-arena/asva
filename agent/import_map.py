"""
agent/import_map.py -- interactive import map of the target app (companion to 3.1 repo context).

repo_context.build_import_index() parses every file of the target app once per batch to find
who imports whom. This module turns that same index into a single self-contained HTML page
(no network, no external libraries) so a reviewer can see the dependency graph the agent
reasoned over:

  - every indexed file as a node, coloured by top-level folder, sized by how many files
    import it; arrows point from the importing file to the file it imports
  - the batch's files (the ones being fixed) ringed, with their findings
  - click a file to see its importers and imports (with the import line), the third-party
    packages it uses, and the exact repo context the agent adds to the fix prompt for it
  - "Include indirect" widens the highlight to everything that depends on a file
    transitively, i.e. what a change to it could break

Written automatically by agent_loop.py whenever it builds the index (see --import-map-dir),
or on demand:

  python -m agent.import_map --app-root target-apps/PyGoat --out import_map.html
  python -m agent.import_map --batch fix_batches/<batch>.json --out import_map.html
"""

from __future__ import annotations

import argparse
import html
import json
import posixpath
import sys
from datetime import datetime, timezone
from pathlib import Path

if __package__ in (None, ""):          # `python agent/import_map.py`
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from agent import repo_context  # noqa: E402


def _top_group(path: str) -> str:
    return path.split("/", 1)[0] if "/" in path else "(root)"


def _package_of_finding(finding: dict) -> str:
    """'pyyaml' from an SCA finding's location.package 'pyyaml@5.1' (or dependency path)."""
    loc = finding.get("location") or {}
    pkg = loc.get("package") or ""
    if not pkg:
        dep_path = (finding.get("dependency") or {}).get("path") or []
        pkg = dep_path[-1] if dep_path else ""
    if not pkg:
        return ""
    name = pkg.rsplit("@", 1)[0] if pkg.rfind("@") > 0 else pkg
    return name.strip().lower()


def build_map_data(
    index: "repo_context.ImportIndex",
    batch: dict | None = None,
    *,
    include_context: bool = True,
) -> dict:
    """Everything the page needs, as plain JSON-serialisable data."""
    batch = batch or {}
    is_logic = batch.get("batch_type") == "logic"
    findings_by_file: dict[str, list[dict]] = {}
    fix_type_by_file: dict[str, str] = {}
    flagged_pkgs: set[str] = set()
    for fe in batch.get("files_to_fix", []) or []:
        path = posixpath.normpath(str(fe.get("file", "")).replace("\\", "/"))
        findings = fe.get("findings", []) or []
        findings_by_file.setdefault(path, []).extend(findings)
        fix_type_by_file[path] = "logic_change" if is_logic else fe.get("fix_type", "")
        for f in findings:
            name = _package_of_finding(f)
            if name:
                flagged_pkgs.add(name)
                flagged_pkgs.update(n.lower() for n in repo_context.python_import_names(name))

    stdlib = set(getattr(sys, "stdlib_module_names", ())) | {"__future__"}
    pkgs_by_file: dict[str, set[str]] = {}
    for name, sites in index.package_usage.items():
        if name in stdlib and name.lower() not in flagged_pkgs:
            continue
        for f, _ in sites:
            pkgs_by_file.setdefault(f, set()).add(name)

    nodes = []
    for path in sorted(index.files):
        info = index.files[path]
        importers = {imp for imp, _ in index.importers.get(path, [])}
        imports = {t for _, t in index.imports.get(path, []) if t}
        pkgs = sorted(pkgs_by_file.get(path, ()))
        findings = findings_by_file.get(path, [])
        context = ""
        if include_context:
            parts = [
                repo_context.render_code_flow(path, findings, index) if findings else "",
                repo_context.gather_repo_context(path, index, findings=findings or None),
            ]
            context = "\n\n".join(p for p in parts if p)
        nodes.append({
            "id": path,
            "group": _top_group(path),
            "lang": info.language,
            "lines": len(info.lines),
            "fanin": len(importers),
            "fanout": len(imports),
            "pkgs": pkgs,
            "inBatch": path in fix_type_by_file,
            "fixType": fix_type_by_file.get(path, ""),
            "findings": [{
                "line": (f.get("location") or {}).get("line"),
                "severity": f.get("severity") or "",
                "title": f.get("title") or "",
                "rule": (f.get("identifiers") or {}).get("rule_id")
                        or (f.get("identifiers") or {}).get("cwe") or "",
            } for f in findings],
            "context": context,
        })

    edges = []
    for path in sorted(index.imports):
        for ref, target in index.imports[path]:
            if target:
                edges.append({"s": path, "t": target, "line": ref.line_no,
                              "stmt": ref.statement[:200], "bindings": list(ref.bindings)})

    # Standard-library modules are not dependencies anyone upgrades; leave them out
    packages = []
    for name in sorted(index.package_usage):
        if name in stdlib and name.lower() not in flagged_pkgs:
            continue
        sites = sorted({(f, ref.line_no) for f, ref in index.package_usage[name]})
        packages.append({"id": "pkg:" + name, "name": name,
                         "sites": [[f, ln] for f, ln in sites],
                         "flagged": name.lower() in flagged_pkgs})

    # Batch files the index doesn't know (e.g. requirements.txt for an SCA batch)
    unindexed = sorted(p for p in fix_type_by_file if p not in index.files)

    root = Path(index.app_root)
    languages = sorted({n["lang"] for n in nodes if n["lang"]})
    return {
        "meta": {
            "app": root.name or str(root),
            "appRoot": root.as_posix(),
            "languages": languages,
            "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "batchId": batch.get("batch_id", ""),
            "batchType": batch.get("batch_type", ""),
            "unindexedBatchFiles": unindexed,
        },
        "nodes": nodes,
        "edges": edges,
        "packages": packages,
    }


def render_html(data: dict) -> str:
    payload = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    payload = payload.replace("</", "<\\/").replace("<!--", "<\\!--")
    meta = data["meta"]
    title = f"Import map · {meta['app']}" + (f" · {meta['batchId']}" if meta["batchId"] else "")
    return _TEMPLATE.replace("__TITLE__", html.escape(title)).replace("__DATA__", payload)


def write_import_map(
    index: "repo_context.ImportIndex",
    out_path: str | Path,
    batch: dict | None = None,
) -> Path:
    """Render the index to `out_path` (parent folders are created). Returns the path."""
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(render_html(build_map_data(index, batch)), encoding="utf-8")
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write an interactive HTML import map of the target app.")
    parser.add_argument("--repo-dir", default=".", help="Repo root (default: .)")
    parser.add_argument("--app-root", help="App folder to index. Default: <repo-dir>/$ASVA_FIX_PATH_PREFIX")
    parser.add_argument("--batch", help="Optional fix batch JSON: rings its files and shows their findings")
    parser.add_argument("--out", default="import_map.html", help="Output HTML file (default: import_map.html)")
    args = parser.parse_args(argv)

    if args.app_root:
        app_root = Path(args.app_root)
    else:
        from gitops import config   # loads .env for ASVA_FIX_PATH_PREFIX
        app_root = repo_context.app_root_for(args.repo_dir, config.FIX_PATH_PREFIX)
    if not app_root.is_dir():
        print(f"[ERROR] app root not found: {app_root}", file=sys.stderr)
        return 1
    batch = json.loads(Path(args.batch).read_text(encoding="utf-8")) if args.batch else None
    index = repo_context.build_import_index(app_root)
    out = write_import_map(index, args.out, batch)
    n_edges = sum(1 for pairs in index.imports.values() for _, t in pairs if t)
    print(f"Import map: {len(index.files)} file(s), {n_edges} import edge(s) -> {out.resolve()}")
    return 0


_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>__TITLE__</title>
<style>
:root{
  --bg:#f4f6f9;--surface:#fff;--fg:#162030;--muted:#5d687a;--line:#d5dbe5;--soft:#e8ecf2;
  --accent:#1f5bd8;--accent-soft:#e2eafc;--imp:#c0561a;--imp-soft:#fbe9dd;--flag:#c62f45;--flag-soft:#fbe3e7;
  --edge:#9aa5b6;
  --c0:#1f5bd8;--c1:#0f8a7a;--c2:#b4561b;--c3:#8a5cc7;--c4:#a3870c;--c5:#c62f6e;--c6:#3c7f2c;--c7:#2f8fb8;--c8:#7a5a3a;--c9:#5d687a;
  --mono:ui-monospace,"Cascadia Mono","SF Mono",Menlo,Consolas,monospace;
  --sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  color-scheme:light;
}
@media (prefers-color-scheme:dark){:root{
  --bg:#0f141c;--surface:#171e29;--fg:#e3e8f0;--muted:#98a3b5;--line:#2c3646;--soft:#212a37;
  --accent:#73a0ff;--accent-soft:#1c2b4d;--imp:#f0975c;--imp-soft:#3a2518;--flag:#f5728a;--flag-soft:#3d1a22;
  --edge:#5b6678;
  --c0:#73a0ff;--c1:#3cc4b1;--c2:#f0975c;--c3:#b48cf0;--c4:#d9c050;--c5:#f06fa8;--c6:#7cc76a;--c7:#5cc0e8;--c8:#c9a27a;--c9:#98a3b5;
  color-scheme:dark}}
*{box-sizing:border-box}
html,body{height:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 var(--sans);display:flex;flex-direction:column}
header{padding:12px 16px 10px;display:flex;flex-wrap:wrap;gap:6px 24px;align-items:baseline;border-bottom:1px solid var(--line);background:var(--surface)}
h1{font-size:18px;margin:0;font-weight:650}
.stats{display:flex;flex-wrap:wrap;gap:4px 16px;color:var(--muted);font-size:13px}
.stats b{color:var(--fg);font-variant-numeric:tabular-nums;font-weight:600}
.tools{display:flex;flex-wrap:wrap;gap:8px 14px;align-items:center;padding:8px 16px;border-bottom:1px solid var(--line);background:var(--surface);font-size:13px}
input[type=search]{font:inherit;padding:5px 10px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);width:220px;max-width:100%}
label.tg{display:inline-flex;gap:6px;align-items:center;cursor:pointer;color:var(--muted)}
button{font:inherit;font-size:13px;padding:4px 10px;border:1px solid var(--line);border-radius:6px;background:var(--surface);color:var(--fg);cursor:pointer}
button:focus-visible,input:focus-visible,.item:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
.legend{display:flex;flex-wrap:wrap;gap:4px 12px;margin-left:auto;color:var(--muted)}
.legend span{display:inline-flex;align-items:center;gap:5px;cursor:pointer;user-select:none}
.legend span.off{opacity:.35}
.legend i{width:10px;height:10px;border-radius:50%;display:inline-block}
main{flex:1;display:flex;min-height:0}
#stage{flex:1;position:relative;min-width:0}
svg{width:100%;height:100%;display:block;cursor:grab;touch-action:none}
svg.panning{cursor:grabbing}
.e{stroke:var(--edge);stroke-width:1;fill:none;opacity:.55}
.n circle{stroke:var(--surface);stroke-width:1.5;cursor:pointer}
.n .ring{fill:none;stroke:var(--flag);stroke-width:2.2;pointer-events:none}
.n text{font-size:var(--fs,11px);font-family:var(--mono);fill:var(--fg);pointer-events:none;paint-order:stroke;stroke:var(--bg);stroke-width:var(--sw,3px);stroke-linejoin:round}
.n.pkg circle{stroke:var(--edge);stroke-dasharray:2 2}
.dim .n:not(.hl){opacity:.18}.dim .e:not(.hl){opacity:.06}
.dim .n.hl text{font-weight:600}
.e.in{stroke:var(--imp);opacity:1;stroke-width:1.6}.e.out{stroke:var(--accent);opacity:1;stroke-width:1.6}
.e.pkgl{stroke-dasharray:3 3}
.n.sel circle{stroke:var(--fg);stroke-width:2.5}
#hint{position:absolute;left:12px;bottom:10px;font-size:12px;color:var(--muted);background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:3px 8px}
#tip{position:absolute;pointer-events:none;background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:4px 8px;font:12px var(--mono);max-width:420px;display:none;box-shadow:0 2px 8px rgba(0,0,0,.12)}
aside{width:420px;max-width:45%;border-left:1px solid var(--line);background:var(--surface);overflow:auto;padding:14px 16px 24px}
@media (max-width:760px){main{flex-direction:column}aside{width:auto;max-width:none;border-left:0;border-top:1px solid var(--line);max-height:45%}#stage{min-height:55%}}
aside h2{font:600 15px var(--mono);margin:0 0 6px;word-break:break-all}
aside h3{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin:16px 0 6px;font-weight:600}
.pills{display:flex;flex-wrap:wrap;gap:5px}
.pill{font:11.5px var(--mono);border:1px solid var(--line);border-radius:999px;padding:0 8px;color:var(--muted)}
.pill.flag{border-color:var(--flag);color:var(--flag);background:var(--flag-soft)}
.list{display:grid;gap:4px}
.item{font:12px var(--mono);border:1px solid var(--soft);border-radius:6px;padding:4px 8px;cursor:pointer;background:var(--bg)}
.item:hover{border-color:var(--accent)}
.item .stmt{color:var(--muted);display:block;white-space:pre-wrap;word-break:break-word;margin-top:2px}
.item.in{border-left:3px solid var(--imp)}.item.out{border-left:3px solid var(--accent)}
.find{font-size:13px;border-left:3px solid var(--flag);padding:2px 8px;margin:4px 0}
.find small{color:var(--muted);font-family:var(--mono)}
pre.ctx{font:11.5px/1.45 var(--mono);white-space:pre-wrap;word-break:break-word;background:var(--bg);border:1px solid var(--soft);border-radius:6px;padding:8px 10px;margin:0;max-height:420px;overflow:auto}
.muted{color:var(--muted);font-size:13px}
summary{cursor:pointer;margin-bottom:4px}
.empty{color:var(--muted);font-size:12.5px}
</style>
</head>
<body>
<header>
  <h1 id="title"></h1>
  <div class="stats" id="stats"></div>
</header>
<div class="tools">
  <input type="search" id="q" placeholder="Find a file or package" aria-label="Find a file or package" list="names">
  <datalist id="names"></datalist>
  <label class="tg"><input type="checkbox" id="isolated"> Files with no local imports</label>
  <label class="tg"><input type="checkbox" id="pkgs"> Third-party packages</label>
  <label class="tg"><input type="checkbox" id="trans"> Include indirect</label>
  <button id="fit" type="button">Fit</button>
  <div class="legend" id="legend"></div>
</div>
<main>
  <div id="stage">
    <svg id="svg" role="img" aria-label="Import graph"><defs>
      <marker id="ar" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M0,0L10,5L0,10z" fill="var(--edge)"/></marker>
      <marker id="ar-in" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M0,0L10,5L0,10z" fill="var(--imp)"/></marker>
      <marker id="ar-out" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="5" markerHeight="5" orient="auto-start-reverse"><path d="M0,0L10,5L0,10z" fill="var(--accent)"/></marker>
    </defs><g id="vp"><g id="eg"></g><g id="ng"></g></g></svg>
    <div id="tip"></div>
    <div id="hint">Arrow = "imports". Drag to pan, scroll to zoom, click a file.</div>
  </div>
  <aside id="side" aria-live="polite"></aside>
</main>
<script id="data" type="application/json">__DATA__</script>
<script>
(function(){
const D=JSON.parse(document.getElementById("data").textContent);
const M=D.meta;
const $=id=>document.getElementById(id);
const esc=s=>String(s==null?"":s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
const NS="http://www.w3.org/2000/svg";
const mk=(t,a,p)=>{const e=document.createElementNS(NS,t);for(const k in a)e.setAttribute(k,a[k]);if(p)p.appendChild(e);return e};

// ----- model -----
const byId={};D.nodes.forEach(n=>{n.kind="file";byId[n.id]=n});
D.packages.forEach(p=>{p.kind="pkg";p.group="third-party";p.fanin=new Set(p.sites.map(s=>s[0])).size;byId[p.id]=p});
const out={},inn={};Object.keys(byId).forEach(k=>{out[k]=[];inn[k]=[]});
D.edges.forEach(e=>{out[e.s].push(e);inn[e.t].push(e)});
const pkgEdges=[];D.packages.forEach(p=>{const seen=new Set();p.sites.forEach(([f,ln])=>{if(seen.has(f)||!byId[f])return;seen.add(f);const e={s:f,t:p.id,line:ln,stmt:"",pkg:true};pkgEdges.push(e);out[f].push(e);inn[p.id].push(e)})});
const groups=[...new Set(D.nodes.map(n=>n.group))].sort((a,b)=>{const ca=D.nodes.filter(n=>n.group===a).length,cb=D.nodes.filter(n=>n.group===b).length;return cb-ca||a.localeCompare(b)});
const gColor=g=>g==="third-party"?"var(--c9)":`var(--c${Math.min(groups.indexOf(g),8)})`;
const hiddenGroups=new Set();
const baseCount={};D.nodes.forEach(n=>{const b=n.id.split("/").pop();baseCount[b]=(baseCount[b]||0)+1});
const shortName=id=>{const parts=id.split("/"),b=parts.pop();return baseCount[b]>1&&parts.length?parts.pop()+"/"+b:b};
const st={sel:null,isolated:false,pkgs:false,trans:false};
const anyFlagged=D.packages.some(p=>p.flagged);
if(anyFlagged)st.pkgs=true;
const batchIds=D.nodes.filter(n=>n.inBatch).map(n=>n.id);

// ----- header -----
$("title").textContent="Import map · "+M.app+(M.batchId?" · "+M.batchId:"");
const isolatedCount=D.nodes.filter(n=>!n.fanin&&!n.fanout).length;
const stat=(v,l)=>`<span><b>${v}</b> ${l}</span>`;
$("stats").innerHTML=[stat(D.nodes.length,"files indexed"),stat(D.edges.length,"local imports"),stat(D.packages.length,"third-party packages"),stat(isolatedCount,"with no local imports"),
  M.batchId?stat(batchIds.length+M.unindexedBatchFiles.length,"in this batch"+(M.batchType?" ("+esc(M.batchType)+")":"")):"",`<span>${esc(M.languages.join(", "))} · ${esc(M.generated)}</span>`].join("");
$("names").innerHTML=Object.keys(byId).map(k=>`<option value="${esc(byId[k].kind==="pkg"?byId[k].name:k)}">`).join("");

function legend(){
  const gs=groups.concat(st.pkgs?["third-party"]:[]);
  $("legend").innerHTML=gs.map(g=>`<span data-g="${esc(g)}" class="${hiddenGroups.has(g)?"off":""}" title="Click to hide or show"><i style="background:${gColor(g)}"></i>${esc(g)}</span>`).join("")+
    (batchIds.length?`<span style="cursor:default"><i style="background:transparent;border:2px solid var(--flag)"></i>in batch</span>`:"");
  $("legend").querySelectorAll("[data-g]").forEach(s=>s.onclick=()=>{const g=s.dataset.g;hiddenGroups.has(g)?hiddenGroups.delete(g):hiddenGroups.add(g);build()});
}

// ----- layout (small force simulation, deterministic) -----
let vis=[],visE=[],P={};
function visible(n){
  if(hiddenGroups.has(n.group))return false;
  if(n.kind==="pkg")return st.pkgs;
  if(n.inBatch||n.id===st.sel)return true;
  return st.isolated||n.fanin>0||n.fanout>0;
}
function radius(n){return n.kind==="pkg"?4+Math.sqrt(n.fanin)*1.6:5+Math.sqrt(n.fanin)*3}
function simulate(){
  const ids=vis.map(n=>n.id),idx={};ids.forEach((k,i)=>idx[k]=i);
  const N=ids.length;let seed=7;const rnd=()=>(seed=(seed*16807)%2147483647)/2147483647;
  const gi={};groups.concat(["third-party"]).forEach((g,i)=>gi[g]=i);const G=groups.length+1;
  const pos=vis.map((n,i)=>{const p=P[n.id];if(p)return{x:p.x,y:p.y,vx:0,vy:0};const a=2*Math.PI*gi[n.group]/G,r=220;return{x:Math.cos(a)*r+(rnd()-.5)*80,y:Math.sin(a)*r+(rnd()-.5)*80,vx:0,vy:0}});
  const links=visE.map(e=>[idx[e.s],idx[e.t]]);
  const deg=new Array(N).fill(0);links.forEach(([a,b])=>{deg[a]++;deg[b]++});
  for(let it=0;it<320;it++){
    const alpha=1-it/320;
    for(let i=0;i<N;i++)for(let j=i+1;j<N;j++){
      let dx=pos[j].x-pos[i].x,dy=pos[j].y-pos[i].y,d2=dx*dx+dy*dy+.01;if(d2>250000)continue;
      const f=1800/d2*alpha,d=Math.sqrt(d2);dx/=d;dy/=d;pos[i].vx-=dx*f;pos[i].vy-=dy*f;pos[j].vx+=dx*f;pos[j].vy+=dy*f}
    links.forEach(([a,b])=>{const dx=pos[b].x-pos[a].x,dy=pos[b].y-pos[a].y,d=Math.sqrt(dx*dx+dy*dy)||1;const f=(d-95)*.04*alpha;
      const fx=dx/d*f,fy=dy/d*f;pos[a].vx+=fx/Math.max(1,deg[a]*.5);pos[a].vy+=fy/Math.max(1,deg[a]*.5);pos[b].vx-=fx/Math.max(1,deg[b]*.5);pos[b].vy-=fy/Math.max(1,deg[b]*.5)});
    const cent={};vis.forEach((n,i)=>{const c=cent[n.group]||(cent[n.group]={x:0,y:0,k:0});c.x+=pos[i].x;c.y+=pos[i].y;c.k++});
    vis.forEach((n,i)=>{const c=cent[n.group];pos[i].vx+=(c.x/c.k-pos[i].x)*.012*alpha;pos[i].vy+=(c.y/c.k-pos[i].y)*.012*alpha;
      pos[i].vx-=pos[i].x*.008*alpha;pos[i].vy-=pos[i].y*.008*alpha;
      pos[i].x+=pos[i].vx;pos[i].y+=pos[i].vy;pos[i].vx*=.6;pos[i].vy*=.6});
  }
  vis.forEach((n,i)=>P[n.id]={x:pos[i].x,y:pos[i].y});
}

// ----- view (pan / zoom) -----
const svg=$("svg"),vp=$("vp");let T={x:0,y:0,k:1};
const apply=()=>{vp.setAttribute("transform",`translate(${T.x},${T.y}) scale(${T.k})`);vp.style.setProperty("--fs",(11/T.k)+"px");vp.style.setProperty("--sw",(3/T.k)+"px");vp.querySelectorAll(".n text").forEach(t=>t.setAttribute("x",+t.dataset.r+4/T.k))};
function fit(){
  if(!vis.length)return;const r=svg.getBoundingClientRect();
  let x0=1e9,y0=1e9,x1=-1e9,y1=-1e9;vis.forEach(n=>{const p=P[n.id];x0=Math.min(x0,p.x);y0=Math.min(y0,p.y);x1=Math.max(x1,p.x);y1=Math.max(y1,p.y)});
  const pad=90,w=x1-x0+pad*2,h=y1-y0+pad*2;T.k=Math.min(1.6,Math.max(.2,Math.min(r.width/w,r.height/h)));
  T.x=r.width/2-(x0+x1)/2*T.k;T.y=r.height/2-(y0+y1)/2*T.k;apply();
}
svg.addEventListener("wheel",e=>{e.preventDefault();const r=svg.getBoundingClientRect(),mx=e.clientX-r.left,my=e.clientY-r.top;
  const k=Math.min(4,Math.max(.15,T.k*Math.exp(-e.deltaY*.0015)));T.x=mx-(mx-T.x)*k/T.k;T.y=my-(my-T.y)*k/T.k;T.k=k;apply()},{passive:false});
let drag=null;
svg.addEventListener("pointerdown",e=>{const g=e.target.closest(".n");
  drag=g?{node:g.dataset.id,sx:e.clientX,sy:e.clientY,moved:false}:{pan:true,sx:e.clientX,sy:e.clientY,tx:T.x,ty:T.y,moved:false};
  svg.setPointerCapture(e.pointerId);if(!g)svg.classList.add("panning")});
svg.addEventListener("pointermove",e=>{
  if(!drag){tipMove(e);return}
  const dx=e.clientX-drag.sx,dy=e.clientY-drag.sy;if(Math.abs(dx)+Math.abs(dy)>3)drag.moved=true;
  if(drag.pan){T.x=drag.tx+dx;T.y=drag.ty+dy;apply()}
  else if(drag.moved){const p=P[drag.node];p.x+=dx/T.k;p.y+=dy/T.k;drag.sx=e.clientX;drag.sy=e.clientY;place()}});
svg.addEventListener("pointerup",e=>{if(drag&&!drag.moved){if(drag.node)select(drag.node);else select(null)}drag=null;svg.classList.remove("panning")});

// ----- tooltip -----
const tip=$("tip");
function tipMove(e){const g=e.target.closest(".n");if(!g){tip.style.display="none";return}
  const n=byId[g.dataset.id],r=$("stage").getBoundingClientRect();
  tip.innerHTML=n.kind==="pkg"?`${esc(n.name)} · used in ${n.fanin} file(s)`:`${esc(n.id)}<br><span style="color:var(--muted)">imported by ${n.fanin} · imports ${n.fanout}${n.findings.length?" · "+n.findings.length+" finding(s)":""}</span>`;
  tip.style.display="block";tip.style.left=Math.min(e.clientX-r.left+14,r.width-260)+"px";tip.style.top=(e.clientY-r.top+14)+"px"}
svg.addEventListener("pointerleave",()=>tip.style.display="none");

// ----- draw -----
let nodeEls={},edgeEls=[];
function build(keepView){
  vis=Object.values(byId).filter(visible);const vs=new Set(vis.map(n=>n.id));
  visE=D.edges.concat(st.pkgs?pkgEdges:[]).filter(e=>vs.has(e.s)&&vs.has(e.t));
  simulate();
  const eg=$("eg"),ng=$("ng");eg.innerHTML="";ng.innerHTML="";nodeEls={};edgeEls=[];
  visE.forEach(e=>{const p=mk("path",{class:"e"+(e.pkg?" pkgl":""),"marker-end":"url(#ar)"},eg);edgeEls.push([e,p])});
  vis.slice().sort((a,b)=>a.fanin-b.fanin).forEach(n=>{
    const g=mk("g",{class:"n"+(n.kind==="pkg"?" pkg":"")},ng);g.dataset.id=n.id;
    const r=radius(n);
    mk("circle",{r,fill:n.kind==="pkg"?(n.flagged?"var(--flag)":"var(--surface)"):gColor(n.group)},g);
    if(n.inBatch||(n.kind==="pkg"&&n.flagged))mk("circle",{class:"ring",r:r+3.5},g);
    const showLabel=n.inBatch||n.fanin>=2||n.kind==="pkg"||vis.length<45;
    const t=mk("text",{x:r+4,y:4},g);t.dataset.r=r;t.setAttribute("dominant-baseline","middle");t.setAttribute("y",0);t.textContent=n.kind==="pkg"?n.name:shortName(n.id);
    if(!showLabel)t.setAttribute("data-small","1");
    nodeEls[n.id]=g;
  });
  place();legend();
  if(!keepView)fit();else apply();
  highlight();
}
function place(){
  Object.entries(nodeEls).forEach(([id,g])=>{const p=P[id];g.setAttribute("transform",`translate(${p.x},${p.y})`)});
  edgeEls.forEach(([e,p])=>{const a=P[e.s],b=P[e.t],rb=radius(byId[e.t])+2;
    const dx=b.x-a.x,dy=b.y-a.y,d=Math.sqrt(dx*dx+dy*dy)||1;const ex=b.x-dx/d*rb,ey=b.y-dy/d*rb;
    const mx=(a.x+ex)/2-dy*.08,my=(a.y+ey)/2+dx*.08;p.setAttribute("d",`M${a.x},${a.y}Q${mx},${my} ${ex},${ey}`)});
  // hide crowded small labels when zoomed out
  vp.querySelectorAll("text[data-small]").forEach(t=>t.style.display=(st.sel?"":"none"));
}
function closure(id,adj,key){const seen=new Set([id]),stack=[id];while(stack.length){const x=stack.pop();(adj[x]||[]).forEach(e=>{const y=e[key];if(!seen.has(y)){seen.add(y);stack.push(y)}})}seen.delete(id);return seen}
function highlight(){
  const id=st.sel&&nodeEls[st.sel]?st.sel:null;
  vp.classList.toggle("dim",!!id);
  Object.values(nodeEls).forEach(g=>g.classList.remove("hl","sel"));
  edgeEls.forEach(([e,p])=>{p.classList.remove("hl","in","out");p.setAttribute("marker-end","url(#ar)")});
  if(!id){vp.querySelectorAll("text[data-small]").forEach(t=>t.style.display="none");return}
  const ups=st.trans?closure(id,inn,"s"):new Set(inn[id].map(e=>e.s));
  const downs=st.trans?closure(id,out,"t"):new Set(out[id].map(e=>e.t));
  nodeEls[id].classList.add("hl","sel");
  [...ups,...downs].forEach(k=>nodeEls[k]&&nodeEls[k].classList.add("hl"));
  edgeEls.forEach(([e,p])=>{
    const isIn=(e.t===id||ups.has(e.t))&&ups.has(e.s),isOut=(e.s===id||downs.has(e.s))&&downs.has(e.t);
    if(isIn){p.classList.add("hl","in");p.setAttribute("marker-end","url(#ar-in)")}
    else if(isOut){p.classList.add("hl","out");p.setAttribute("marker-end","url(#ar-out)")}});
  vp.querySelectorAll("text[data-small]").forEach(t=>{t.style.display=t.parentNode.classList.contains("hl")?"":"none"});
}

// ----- side panel -----
function itemList(list,cls){return list.length?`<div class="list">${list.map(x=>`<div class="item ${cls}" tabindex="0" data-go="${esc(x.go)}">${esc(x.label)}${x.stmt?`<span class="stmt">${esc(x.stmt)}</span>`:""}</div>`).join("")}</div>`:`<div class="empty">none</div>`}
function sevSummary(fs){const c={};fs.forEach(f=>{const k=(f.severity||"unknown").toLowerCase();c[k]=(c[k]||0)+1});
  return ["critical","high","medium","low","unknown"].filter(k=>c[k]).map(k=>c[k]+" "+k).join(" · ")+" (show)"}
function side(){
  const s=$("side"),n=st.sel&&byId[st.sel];
  if(!n){
    const top=D.nodes.slice().sort((a,b)=>b.fanin-a.fanin).filter(x=>x.fanin>0).slice(0,8);
    const batch=D.nodes.filter(x=>x.inBatch);
    s.innerHTML=`<h2>${esc(M.app)}</h2><p class="muted">${esc(M.appRoot)}</p>
      <p class="muted">The graph the fix agent builds before writing a fix. Click any file to see who depends on it and the context the agent adds to its prompt.</p>
      ${batch.length?`<h3>Files in this batch</h3>${itemList(batch.map(x=>({go:x.id,label:x.id,stmt:`${x.findings.length} finding(s) · imported by ${x.fanin} · imports ${x.fanout}`})),"")}`:""}
      ${M.unindexedBatchFiles.length?`<h3>Batch files outside the index</h3><div class="muted">${M.unindexedBatchFiles.map(esc).join(", ")}${D.packages.some(p=>p.flagged)?" · the packages it upgrades are ringed in red":""}</div>`:""}
      <h3>Most imported files</h3>${itemList(top.map(x=>({go:x.id,label:x.id,stmt:`imported by ${x.fanin} file(s)`})),"")}`;
  }else if(n.kind==="pkg"){
    s.innerHTML=`<h2>${esc(n.name)}</h2><div class="pills"><span class="pill">third-party</span>${n.flagged?`<span class="pill flag">upgraded in this batch</span>`:""}</div>
      <h3>Used in (${n.fanin} file${n.fanin===1?"":"s"})</h3>${itemList(n.sites.map(([f,ln])=>({go:f,label:f+":"+ln})),"in")}`;
  }else{
    const ins=(st.trans?[...closure(n.id,inn,"s")].map(k=>({go:k,label:k})):inn[n.id].filter(e=>!e.pkg).map(e=>({go:e.s,label:e.s+":"+e.line,stmt:e.stmt})));
    const outs=(st.trans?[...closure(n.id,out,"t")].filter(k=>!k.startsWith("pkg:")).map(k=>({go:k,label:k})):out[n.id].filter(e=>!e.pkg).map(e=>({go:e.t,label:e.t,stmt:"L"+e.line+": "+e.stmt})));
    s.innerHTML=`<h2>${esc(n.id)}</h2>
      <div class="pills"><span class="pill">${esc(n.lang)}</span><span class="pill">${n.lines} lines</span>${n.inBatch?`<span class="pill flag">in batch${n.fixType?" · "+esc(n.fixType):""}</span>`:""}</div>
      <h3>${st.trans?"Everything that depends on it":"Imported by"} (${ins.length})</h3>${itemList(ins,"in")}
      <h3>${st.trans?"Everything it depends on":"Imports"} (${outs.length})</h3>${itemList(outs,"out")}
      <h3>Third-party packages (${n.pkgs.length})</h3>${n.pkgs.length?`<div class="pills">${n.pkgs.map(p=>`<span class="pill item" style="cursor:pointer" data-go="pkg:${esc(p)}" tabindex="0">${esc(p)}</span>`).join("")}</div>`:`<div class="empty">none</div>`}
      <h3>Repo context sent to the fix prompt</h3>${n.context?`<pre class="ctx">${esc(n.context)}</pre>`:`<div class="empty">Nothing: no file imports it and it imports no local module${n.findings.length?", and no scanner data flow":""}.</div>`}
      ${n.findings.length?`<h3>Findings (${n.findings.length})</h3><details${n.findings.length<=6?" open":""}><summary class="muted">${sevSummary(n.findings)}</summary>${n.findings.map(f=>`<div class="find">${esc(f.title||f.rule)} <small>${f.line?"L"+f.line+" · ":""}${esc(f.severity)}${f.rule?" · "+esc(f.rule):""}</small></div>`).join("")}</details>`:""}`;
  }
  s.querySelectorAll("[data-go]").forEach(x=>{const go=()=>select(x.dataset.go);x.onclick=go;x.onkeydown=e=>{if(e.key==="Enter"){e.preventDefault();go()}}});
}
function select(id){
  if(id&&byId[id]&&!nodeEls[id]){const n=byId[id];hiddenGroups.delete(n.group);if(n.kind==="pkg"){st.pkgs=true;$("pkgs").checked=true}st.sel=id;build(true)}
  st.sel=id&&byId[id]?id:null;highlight();side();
}

// ----- controls -----
$("isolated").checked=st.isolated;$("pkgs").checked=st.pkgs;$("trans").checked=st.trans;
$("isolated").onchange=e=>{st.isolated=e.target.checked;build()};
$("pkgs").onchange=e=>{st.pkgs=e.target.checked;build()};
$("trans").onchange=e=>{st.trans=e.target.checked;highlight();side()};
$("fit").onclick=fit;
$("q").addEventListener("change",e=>{const v=e.target.value.trim().toLowerCase();if(!v)return;
  const hit=Object.values(byId).find(n=>(n.kind==="pkg"?n.name:n.id).toLowerCase()===v)||Object.values(byId).find(n=>(n.kind==="pkg"?n.name:n.id).toLowerCase().includes(v));
  if(hit)select(hit.id)});
window.addEventListener("resize",()=>fit());
build();side();
})();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    sys.exit(main())

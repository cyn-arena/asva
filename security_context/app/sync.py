"""Download or refresh knowledge sources into the SQLite store.

    python -m app.sync                         # all sources
    python -m app.sync --source kev            # one source (repeatable)
    python -m app.sync --source nvd --nvd-mode full
    python -m app.sync --force                 # re-process even if unchanged

Sources: cwe (MITRE CWE + OWASP Top 10 categories), owasp (cheat sheets, embedded),
kev (CISA KEV), nvd (lazy: refresh cached CVEs; full: mirror + incremental updates).
OSV.dev and Context7 are looked up on demand and cached; they have no bulk sync.
A source is only re-processed when it changed.
"""

import argparse
from contextlib import closing

import httpx

from app import config, net, store
from app.sources import cwe, kev, nvd, owasp

SOURCES = ("cwe", "owasp", "kev", "nvd")


def run(conn, client: httpx.Client, sources: list[str] | None = None, force: bool = False,
        embedder_factory=None, nvd_mode: str = config.NVD_SYNC_MODE) -> list[str]:
    """Sync the given sources; returns one result line per source. Errors are reported, not raised."""
    results = []
    for source in sources or SOURCES:
        try:
            if source == "cwe":
                results.append(cwe.sync(conn, client, force=force))
            elif source == "owasp":
                if embedder_factory is None:
                    from app.embed import Embedder
                    embedder_factory = Embedder
                results.append(owasp.sync(conn, client, embedder_factory(), force=force))
            elif source == "kev":
                results.append(kev.sync(conn, client, force=force))
            elif source == "nvd":
                results.append(nvd.sync(conn, client, mode=nvd_mode, force=force))
            else:
                results.append(f"{source}: unknown source (choose from {', '.join(SOURCES)})")
        except (net.LookupFailed, httpx.HTTPError) as error:
            results.append(f"{source}: FAILED, {error}")
    return results


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--source", action="append", choices=SOURCES, help="Source to sync (repeatable). Default: all.")
    parser.add_argument("--force", action="store_true", help="Re-download and re-process even if unchanged.")
    parser.add_argument("--nvd-mode", choices=("lazy", "full"), default=config.NVD_SYNC_MODE,
                        help=f"Default: NVD_SYNC_MODE ({config.NVD_SYNC_MODE}).")
    args = parser.parse_args(argv)

    print(f"Database: {config.DB_PATH}")
    with closing(store.connect(config.DB_PATH)) as conn, net.make_client(timeout=60) as client:
        for line in run(conn, client, args.source, args.force, nvd_mode=args.nvd_mode):
            print(line)
        print(f"Totals: {store.counts(conn)}")


if __name__ == "__main__":
    main()

"""endoflife.date: release and end-of-support dates per release line of a product.

Version context only, not a security authority, and community-maintained (each product page
links the vendor's own lifecycle policy). Used to tell supported image lines from ones that
are past end of life or only just released. Looked up per product and cached
(LIFECYCLE_CACHE_DAYS).
"""

from datetime import timedelta

import httpx

from app import config, net, store

SOURCE = "endoflife.date"
API_URL = "https://endoflife.date/api/{product}.json"
PAGE_URL = "https://endoflife.date/{product}"
LICENSE = "endoflife.date (MIT), community-maintained: https://endoflife.date"

# Image names that differ from the product's name on endoflife.date.
PRODUCT_ALIASES = {"mongo": "mongodb", "postgres": "postgresql", "node": "nodejs", "golang": "go",
                   "httpd": "apache-http-server"}


def product_of(image_name: str) -> str:
    name = image_name.rsplit("/", 1)[-1].lower()
    return PRODUCT_ALIASES.get(name, name)


def parse(payload: list[dict]) -> dict[str, dict]:
    """cycle -> {"released", "eol", "latest"}; `eol` is a date, or True/False when no date is given."""
    return {str(c.get("cycle")): {"released": c.get("releaseDate"), "eol": c.get("eol"), "latest": c.get("latest")}
            for c in payload if c.get("cycle") is not None}


def cycles(conn, client: httpx.Client | None, image_name: str, warnings: list[str], *, online: bool = True,
           max_age: timedelta | None = None) -> dict[str, dict] | None:
    """Release lines of the product behind an image, or None if unknown or it couldn't be asked."""
    product = product_of(image_name)
    max_age = timedelta(days=config.LIFECYCLE_CACHE_DAYS) if max_age is None else max_age
    key = f"product:{product}"
    row = store.get_record(conn, key, SOURCE)
    if store.is_fresh(row, max_age) or not online or client is None:
        return store.record_data(row)
    try:
        response = net.request(client, "GET", API_URL.format(product=product), ok_statuses=(404,), retries=1)
    except net.LookupFailed:
        warnings.append(f"endoflife.date unavailable for {product}; support dates not shown")
        return store.record_data(row)
    data = parse(response.json()) if response.status_code == 200 else {}
    store.upsert_records(conn, SOURCE, [{
        "key": key, "kind": "lifecycle", "title": product, "text": f"{len(data)} release lines of {product}",
        "url": PAGE_URL.format(product=product), "license": LICENSE, "data": data}])
    conn.commit()
    return data

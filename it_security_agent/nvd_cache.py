import datetime
import json
import sqlite3
from pathlib import Path

from it_security_agent import nvd_client

DB_PATH = Path(__file__).resolve().parent.parent / "nvd_cache.db"

# Bump when _products_in() changes what it extracts, to force a rebuild of cve_products.
PRODUCT_INDEX_VERSION = 1


def get_connection(db_path=None):
    conn = sqlite3.connect(db_path or DB_PATH)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS cves (
            id TEXT PRIMARY KEY, published TEXT, last_modified TEXT, raw_json TEXT
        )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cves_modified ON cves(last_modified)")
    # Inverted index: CPE product name -> CVE id. query_by_product_name() used to be a
    # `raw_json LIKE '%:name:%'` scan, whose cost is proportional to the *whole table's*
    # bytes and so grew with cache coverage - measured 0.4s per call over a 234MB/42k-CVE
    # cache, and matching calls it once per name variant per component (~300x a scan).
    # At full catalog coverage (~365k CVEs, ~1.7GB) that is 15+ minutes of disk scanning
    # per scan, and on a small-RAM host the table can't stay in page cache so every call
    # re-reads it. WITHOUT ROWID makes the (product, cve_id) primary key itself the
    # lookup structure, so a product probe is a B-tree seek rather than a table scan.
    conn.execute(
        """CREATE TABLE IF NOT EXISTS cve_products (
            product TEXT NOT NULL, cve_id TEXT NOT NULL, PRIMARY KEY (product, cve_id)
        ) WITHOUT ROWID"""
    )
    conn.execute("CREATE TABLE IF NOT EXISTS cache_meta (key TEXT PRIMARY KEY, value TEXT)")
    conn.commit()
    # Caches built before cve_products existed are backfilled on first open rather than
    # in the scan path: correctness of query_by_product_name depends on the index being
    # complete, so it must not be possible to open this cache and query it unindexed.
    ensure_product_index(conn)
    return conn


def _products_in(item) -> set:
    """Every CPE product name (field 4 of the CPE 2.3 URI) referenced by one CVE record.

    Lower-cased to match matching.name_variants(), which lower-cases before comparing.
    """
    products = set()
    for group in item.get("cve", {}).get("configurations") or []:
        for node in group.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = m.get("criteria", "").split(":")
                if len(parts) > 5:
                    products.add(parts[4].lower())
    return products


def _product_rows(vulns):
    return [
        (product, item["cve"]["id"])
        for item in vulns
        for product in _products_in(item)
    ]


def _store_vulns(conn, vulns):
    rows = [
        (item["cve"]["id"], item["cve"].get("published"), item["cve"].get("lastModified"), json.dumps(item))
        for item in vulns
    ]
    conn.executemany(
        "INSERT OR REPLACE INTO cves (id, published, last_modified, raw_json) VALUES (?, ?, ?, ?)",
        rows,
    )
    # Re-storing a CVE can drop products it no longer references (NVD re-scores and
    # rewrites configurations), so clear its old rows before inserting the current set.
    conn.executemany("DELETE FROM cve_products WHERE cve_id = ?", [(item["cve"]["id"],) for item in vulns])
    conn.executemany("INSERT OR REPLACE INTO cve_products (product, cve_id) VALUES (?, ?)", _product_rows(vulns))
    conn.commit()


def ensure_product_index(conn, on_progress=None, batch_size=5000) -> int:
    """Backfill cve_products for a cache populated before the index existed.

    Idempotent and cheap once built (one indexed read of cache_meta). The marker is
    written only after the whole backfill commits, so an interrupted run rebuilds from
    scratch next time rather than leaving a half-filled index that looks complete -
    a silently partial index would under-report vulnerabilities, which is the one
    failure mode this cache must never have.
    """
    current = conn.execute(
        "SELECT value FROM cache_meta WHERE key = 'product_index_version'").fetchone()
    if current and current[0] == str(PRODUCT_INDEX_VERSION):
        return 0

    conn.execute("DELETE FROM cve_products")
    total = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    done = 0
    read_cur = conn.execute("SELECT raw_json FROM cves")
    while True:
        chunk = read_cur.fetchmany(batch_size)
        if not chunk:
            break
        conn.executemany(
            "INSERT OR REPLACE INTO cve_products (product, cve_id) VALUES (?, ?)",
            _product_rows(json.loads(raw) for (raw,) in chunk),
        )
        done += len(chunk)
        if on_progress is not None:
            on_progress(done, total)
    conn.execute(
        "INSERT OR REPLACE INTO cache_meta (key, value) VALUES ('product_index_version', ?)",
        (str(PRODUCT_INDEX_VERSION),),
    )
    conn.commit()
    return done


def _sync(params, conn, fetch_fn, on_progress=None):
    """Fetch `params` from NVD and store the results, returning how many were stored.

    Pages are written to SQLite as they arrive rather than accumulated, so even a full
    catalog sync (~370k CVEs) stays flat in memory. `on_progress(fetched, total)` is
    forwarded per page so callers can show movement during what is otherwise a long
    silent wait.
    """
    stored = 0

    def on_page(vulns, fetched, total):
        nonlocal stored
        _store_vulns(conn, vulns)
        stored += len(vulns)
        if on_progress is not None:
            on_progress(fetched, total)

    vulns, _ = fetch_fn(params, on_page=on_page)
    if vulns:
        # A fetch_fn that ignored on_page (an older client, or a test double) returns
        # everything at once instead - store that rather than silently dropping it.
        _store_vulns(conn, vulns)
        stored += len(vulns)
    return stored


def sync_full(conn=None, fetch_fn=nvd_client.fetch_all_pages, on_progress=None):
    return _sync({}, conn or get_connection(), fetch_fn, on_progress)


def sync_incremental(since: datetime.datetime, conn=None, fetch_fn=nvd_client.fetch_all_pages,
                     on_progress=None):
    params = {
        "lastModStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000"),
    }
    return _sync(params, conn or get_connection(), fetch_fn, on_progress)


def query_by_product_name(name: str, conn=None):
    """Every cached CVE whose CPE configurations name `name` as the affected product.

    Narrower than the old `raw_json LIKE '%:name:%'` scan by design: that matched the
    string anywhere in the record (vendor field, description prose, reference URLs),
    but matching.find_candidates only ever keeps a CVE whose CPE *product* field equals
    the name, so the extra hits were fetched, JSON-parsed and then discarded. Same
    results, without reading the whole table.
    """
    conn = conn or get_connection()
    cur = conn.execute(
        "SELECT c.raw_json FROM cve_products p JOIN cves c ON c.id = p.cve_id WHERE p.product = ?",
        (name.lower(),),
    )
    return [json.loads(row[0]) for row in cur.fetchall()]

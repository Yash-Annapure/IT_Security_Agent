import datetime
import json
import sqlite3
from pathlib import Path

from it_security_agent import nvd_client

DB_PATH = Path(__file__).resolve().parent.parent / "nvd_cache.db"

# Bump when _products_in() changes what it extracts, to force a rebuild of cve_products.
PRODUCT_INDEX_VERSION = 1
# The server opens this cache from more than one place at once: the request path holds a
# connection while _start_background_sync() writes NVD/KEV updates from a daemon thread.
# SQLite's 5s default busy timeout is shorter than either a catalog sync or a one-time
# product-index backfill over ~365k CVEs, so a concurrent writer used to fail outright
# with "database is locked" instead of waiting its turn.
BUSY_TIMEOUT_SECONDS = 180


def get_connection(db_path=None, index_progress=None):
    conn = sqlite3.connect(db_path or DB_PATH, timeout=BUSY_TIMEOUT_SECONDS)
    # WAL lets the scan path keep reading while the background sync writes - under the
    # default rollback journal a writer blocks every reader for the length of its
    # transaction, which on this workload means a sync stalling live scans.
    #
    # Switching journal mode needs a brief exclusive lock that the busy timeout does NOT
    # cover, so a connection opened while another holds a write transaction would fail
    # here with "database is locked". The mode is persistent once set and is a
    # performance setting rather than a correctness one, so check first and let a
    # contended attempt pass: the next open converts it.
    try:
        if conn.execute("PRAGMA journal_mode").fetchone()[0].lower() != "wal":
            conn.execute("PRAGMA journal_mode=WAL")
    except sqlite3.OperationalError:
        pass
    conn.execute("PRAGMA synchronous=NORMAL")  # durable enough for a rebuildable cache
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
    ensure_product_index(conn, on_progress=index_progress)
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


def _index_is_current(conn) -> bool:
    row = conn.execute(
        "SELECT value FROM cache_meta WHERE key = 'product_index_version'").fetchone()
    return bool(row) and row[0] == str(PRODUCT_INDEX_VERSION)


def ensure_product_index(conn, on_progress=None, batch_size=5000) -> int:
    """Backfill cve_products for a cache populated before the index existed.

    Idempotent and cheap once built (one indexed read of cache_meta). The marker is
    written only in the same transaction as the rows, so an interrupted run rebuilds
    from scratch next time rather than leaving a half-filled index that looks complete -
    a silently partial index would under-report vulnerabilities, which is the one
    failure mode this cache must never have.

    Concurrency matters here because the server opens this cache from the request path
    and from the background sync thread at the same time. BEGIN IMMEDIATE makes the
    backfill mutually exclusive: whichever connection gets there first does the work,
    and the other blocks (up to BUSY_TIMEOUT_SECONDS), then re-checks the marker inside
    the lock and returns having done nothing, rather than duplicating a long rebuild.
    """
    if _index_is_current(conn):
        return 0

    prior_isolation = conn.isolation_level
    conn.isolation_level = None  # take explicit control; no implicit BEGIN underneath us
    try:
        conn.execute("BEGIN IMMEDIATE")
        try:
            if _index_is_current(conn):
                conn.execute("ROLLBACK")  # another connection built it while we waited
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
            conn.execute("COMMIT")
            return done
        except Exception:
            conn.execute("ROLLBACK")
            raise
    finally:
        conn.isolation_level = prior_isolation


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

import datetime
import json
import os
import sqlite3
from pathlib import Path

from it_security_agent import nvd_client

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "nvd_cache.db"
# Kept as a module constant for backward compatibility; the NVD_CACHE_DB override is
# applied in get_connection (read at call time, so a .env loaded at startup still wins).
DB_PATH = DEFAULT_DB_PATH

# Bump when _products_in() changes what it extracts, to force a rebuild of cve_products.
PRODUCT_INDEX_VERSION = 1
# Longer than a catalog sync or a product-index backfill, so the server's request path
# and its background sync thread wait for each other instead of failing "database is
# locked" on SQLite's 5s default.
BUSY_TIMEOUT_SECONDS = 180

_VALID_JOURNAL_MODES = {"WAL", "DELETE", "TRUNCATE", "PERSIST", "MEMORY", "OFF"}


def _journal_mode() -> str:
    """SQLite journal mode to use, read at call time (not import) so a .env loaded after
    this module is imported still applies - mcp_server imports nvd_cache before it calls
    load_dotenv().

    WAL is the right default on local disk: readers stay unblocked while the sync thread
    writes. But WAL needs an mmap'd shared-memory (-shm) file that network filesystems
    (NFS) cannot provide - there SQLite fails to open the DB at all, even read-only, with
    "attempt to write a readonly database". Set NVD_CACHE_JOURNAL_MODE=DELETE when the
    cache lives on NFS to use rollback-journal locking, which NFSv4 does support. An
    existing WAL DB must also be converted once (PRAGMA locking_mode=EXCLUSIVE; PRAGMA
    journal_mode=DELETE) - the header journal mode is persisted, and this code will not
    fight it back to WAL.
    """
    mode = os.environ.get("NVD_CACHE_JOURNAL_MODE", "WAL").strip().upper()
    return mode if mode in _VALID_JOURNAL_MODES else "WAL"


def get_connection(db_path=None):
    conn = sqlite3.connect(db_path or os.environ.get("NVD_CACHE_DB") or DB_PATH,
                           timeout=BUSY_TIMEOUT_SECONDS)
    # Journal mode keeps readers unblocked while the sync thread writes (WAL on local disk;
    # DELETE on NFS - see _journal_mode). Setting the mode needs a brief exclusive lock the
    # busy timeout does NOT cover, so check first and let a contended attempt pass - it's a
    # performance setting, and the next open converts it.
    mode = _journal_mode()
    try:
        if conn.execute("PRAGMA journal_mode").fetchone()[0].upper() != mode:
            conn.execute(f"PRAGMA journal_mode={mode}")
    except sqlite3.OperationalError:
        pass
    conn.execute("PRAGMA synchronous=NORMAL")  # durable enough for a rebuildable cache
    conn.execute(
        """CREATE TABLE IF NOT EXISTS cves (
            id TEXT PRIMARY KEY, published TEXT, last_modified TEXT, raw_json TEXT
        )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cves_modified ON cves(last_modified)")
    # Inverted index: CPE product -> CVE id. query_by_product_name() was a
    # `raw_json LIKE '%:name:%'` scan costing time proportional to the whole table, run
    # ~300x a scan; over a 2GB cache that is 15+ minutes. WITHOUT ROWID makes the primary
    # key itself the lookup structure, so a probe is a B-tree seek, not a table scan.
    conn.execute(
        """CREATE TABLE IF NOT EXISTS cve_products (
            product TEXT NOT NULL, cve_id TEXT NOT NULL, PRIMARY KEY (product, cve_id)
        ) WITHOUT ROWID"""
    )
    conn.execute("CREATE TABLE IF NOT EXISTS cache_meta (key TEXT PRIMARY KEY, value TEXT)")
    conn.commit()
    # Correctness of query_by_product_name depends on the index being complete, so it
    # must not be possible to open this cache and query it unindexed.
    ensure_product_index(conn)
    return conn


def _products_in(item) -> set:
    """CPE product names (field 4 of the CPE 2.3 URI) a CVE names, lower-cased to match
    matching.name_variants()."""
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

    The version marker is written in the same transaction as the rows, so an interrupted
    run rebuilds next time rather than leaving a partial index that looks complete - a
    silently partial index would under-report vulnerabilities.

    BEGIN IMMEDIATE makes the backfill mutually exclusive, since the server opens this
    cache from the request path and the sync thread at once: the winner does the work,
    the loser blocks, re-checks inside the lock, and returns having done nothing.
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

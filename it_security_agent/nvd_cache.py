import datetime
import json
import sqlite3
from pathlib import Path

from it_security_agent import nvd_client

DB_PATH = Path(__file__).resolve().parent.parent / "nvd_cache.db"


def get_connection(db_path=None):
    conn = sqlite3.connect(db_path or DB_PATH)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS cves (
            id TEXT PRIMARY KEY, published TEXT, last_modified TEXT, raw_json TEXT
        )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_cves_modified ON cves(last_modified)")
    conn.commit()
    return conn


def _store_vulns(conn, vulns):
    rows = [
        (item["cve"]["id"], item["cve"].get("published"), item["cve"].get("lastModified"), json.dumps(item))
        for item in vulns
    ]
    conn.executemany(
        "INSERT OR REPLACE INTO cves (id, published, last_modified, raw_json) VALUES (?, ?, ?, ?)",
        rows,
    )
    conn.commit()


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
    conn = conn or get_connection()
    pattern = f"%:{name}:%"
    cur = conn.execute("SELECT raw_json FROM cves WHERE raw_json LIKE ?", (pattern,))
    return [json.loads(row[0]) for row in cur.fetchall()]

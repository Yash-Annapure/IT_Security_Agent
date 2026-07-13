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


def sync_full(conn=None, fetch_fn=nvd_client.fetch_all_pages):
    conn = conn or get_connection()
    vulns, _ = fetch_fn({})
    _store_vulns(conn, vulns)
    return len(vulns)


def sync_incremental(since: datetime.datetime, conn=None, fetch_fn=nvd_client.fetch_all_pages):
    conn = conn or get_connection()
    params = {
        "lastModStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000"),
    }
    vulns, _ = fetch_fn(params)
    _store_vulns(conn, vulns)
    return len(vulns)


def query_by_product_name(name: str, conn=None):
    conn = conn or get_connection()
    pattern = f"%:{name}:%"
    cur = conn.execute("SELECT raw_json FROM cves WHERE raw_json LIKE ?", (pattern,))
    return [json.loads(row[0]) for row in cur.fetchall()]

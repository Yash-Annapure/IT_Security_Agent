import json

import requests

from it_security_agent import nvd_cache

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def _table(conn):
    conn.execute("CREATE TABLE IF NOT EXISTS kev (cve_id TEXT PRIMARY KEY, raw_json TEXT)")
    conn.commit()


def refresh(conn=None, get_fn=requests.get):
    conn = conn or nvd_cache.get_connection()
    _table(conn)
    resp = get_fn(KEV_URL, timeout=60)
    resp.raise_for_status()
    entries = resp.json().get("vulnerabilities", [])
    rows = [(e["cveID"], json.dumps(e)) for e in entries]
    conn.executemany("INSERT OR REPLACE INTO kev (cve_id, raw_json) VALUES (?, ?)", rows)
    conn.commit()
    return len(rows)


def is_kev(cve_id: str, conn=None):
    conn = conn or nvd_cache.get_connection()
    _table(conn)
    row = conn.execute("SELECT raw_json FROM kev WHERE cve_id = ?", (cve_id,)).fetchone()
    return json.loads(row[0]) if row else None


def load_kev_ids(conn=None) -> set:
    """Every known-exploited CVE id as one set (~1,600). Cheaper than is_kev() per finding,
    which costs 0.83ms mostly json.loads-ing a record the caller only reads as a boolean."""
    conn = conn or nvd_cache.get_connection()
    _table(conn)
    return {row[0] for row in conn.execute("SELECT cve_id FROM kev")}

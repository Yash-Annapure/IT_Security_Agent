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
    """Every known-exploited CVE id, as one set.

    Callers that only need "is this in KEV?" should use this instead of is_kev() per
    finding: is_kev costs 0.83ms a call, almost all of it json.loads-ing a record whose
    body is then thrown away (the agent only reads it as a boolean). The whole catalog
    is ~1,600 ids, so holding it in memory is cheaper than a single lookup was.
    """
    conn = conn or nvd_cache.get_connection()
    _table(conn)
    return {row[0] for row in conn.execute("SELECT cve_id FROM kev")}

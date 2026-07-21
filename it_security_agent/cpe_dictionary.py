import json

import requests

from it_security_agent import nvd_cache

CPE_BASE = "https://services.nvd.nist.gov/rest/json/cpes/2.0"


def _table(conn):
    conn.execute(
        """CREATE TABLE IF NOT EXISTS cpe_dictionary (
            keyword TEXT PRIMARY KEY, raw_json TEXT, fetched_at TEXT
        )"""
    )
    conn.commit()


def is_cached(keyword: str, conn=None) -> bool:
    """True if search() would be answered from the local cache, with no NVD request.

    Callers that rate-limit around search() (sleeping between calls to respect NVD's
    request spacing) use this to skip the sleep entirely for cached keywords - a
    cache hit makes no network request, so there is nothing to space out.
    """
    conn = conn or nvd_cache.get_connection()
    _table(conn)
    return conn.execute(
        "SELECT 1 FROM cpe_dictionary WHERE keyword = ?", (keyword,)
    ).fetchone() is not None


def search(keyword: str, conn=None, api_key=None, get_fn=requests.get):
    conn = conn or nvd_cache.get_connection()
    _table(conn)
    row = conn.execute(
        "SELECT raw_json FROM cpe_dictionary WHERE keyword = ?", (keyword,)
    ).fetchone()
    if row:
        return json.loads(row[0])
    headers = {"apiKey": api_key} if api_key else {}
    resp = get_fn(CPE_BASE, params={"keywordSearch": keyword}, headers=headers, timeout=90)
    resp.raise_for_status()
    products = resp.json().get("products", [])
    conn.execute(
        "INSERT OR REPLACE INTO cpe_dictionary (keyword, raw_json, fetched_at) VALUES (?, ?, datetime('now'))",
        (keyword, json.dumps(products)),
    )
    conn.commit()
    return products

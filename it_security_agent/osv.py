import json

import requests

from it_security_agent import nvd_cache

OSV_URL = "https://api.osv.dev/v1/query"
OSV_ECOSYSTEM = {"PyPI": "PyPI", "npm": "npm"}


def _table(conn):
    conn.execute(
        """CREATE TABLE IF NOT EXISTS osv_cache (
            ecosystem TEXT, name TEXT, version TEXT, raw_json TEXT,
            PRIMARY KEY (ecosystem, name, version)
        )"""
    )
    conn.commit()


def query(ecosystem: str, name: str, version: str, conn=None, post_fn=requests.post):
    osv_eco = OSV_ECOSYSTEM.get(ecosystem)
    if osv_eco is None:
        return []
    conn = conn or nvd_cache.get_connection()
    _table(conn)
    row = conn.execute(
        "SELECT raw_json FROM osv_cache WHERE ecosystem=? AND name=? AND version=?",
        (ecosystem, name, version),
    ).fetchone()
    if row:
        return json.loads(row[0])
    resp = post_fn(OSV_URL, json={"version": version, "package": {"name": name, "ecosystem": osv_eco}}, timeout=30)
    resp.raise_for_status()
    vulns = resp.json().get("vulns", [])
    conn.execute(
        "INSERT OR REPLACE INTO osv_cache (ecosystem, name, version, raw_json) VALUES (?, ?, ?, ?)",
        (ecosystem, name, version, json.dumps(vulns)),
    )
    conn.commit()
    return vulns

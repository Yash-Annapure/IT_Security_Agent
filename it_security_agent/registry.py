import json

import requests

from it_security_agent import nvd_cache


def pypi_metadata(name: str, get_fn=requests.get):
    resp = get_fn(f"https://pypi.org/pypi/{name}/json", timeout=15)
    if resp.status_code != 200:
        return None
    info = resp.json().get("info", {})
    urls = [info.get("home_page") or ""] + list((info.get("project_urls") or {}).values())
    return {"urls": [u for u in urls if u]}


def npm_metadata(name: str, get_fn=requests.get):
    resp = get_fn(f"https://registry.npmjs.org/{name}", timeout=15)
    if resp.status_code != 200:
        return None
    data = resp.json()
    repo = data.get("repository")
    repo_url = repo.get("url") if isinstance(repo, dict) else repo
    urls = [data.get("homepage") or "", repo_url or ""]
    return {"urls": [u for u in urls if u]}


REGISTRY_FETCHERS = {"PyPI": pypi_metadata, "npm": npm_metadata}


def fetch_metadata(ecosystem: str, name: str, get_fn=requests.get):
    fetcher = REGISTRY_FETCHERS.get(ecosystem)
    if fetcher is None:
        return None
    return fetcher(name, get_fn=get_fn)


def _table(conn):
    conn.execute(
        """CREATE TABLE IF NOT EXISTS registry_cache (
            ecosystem TEXT, name TEXT, raw_json TEXT, fetched_at TEXT,
            PRIMARY KEY (ecosystem, name)
        )"""
    )
    conn.commit()


def cached_fetch_metadata(ecosystem: str, name: str, conn=None, get_fn=requests.get):
    conn = conn or nvd_cache.get_connection()
    _table(conn)
    row = conn.execute(
        "SELECT raw_json FROM registry_cache WHERE ecosystem=? AND name=?", (ecosystem, name)
    ).fetchone()
    if row:
        return json.loads(row[0])
    metadata = fetch_metadata(ecosystem, name, get_fn=get_fn)
    conn.execute(
        "INSERT OR REPLACE INTO registry_cache (ecosystem, name, raw_json, fetched_at) VALUES (?, ?, ?, datetime('now'))",
        (ecosystem, name, json.dumps(metadata)),
    )
    conn.commit()
    return metadata

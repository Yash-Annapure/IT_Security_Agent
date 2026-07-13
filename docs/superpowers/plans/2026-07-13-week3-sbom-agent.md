# Week 3 SBOM Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the notebook-only Week 1/2 prototype into a tested Python package that ingests SBOMs, container images, and repo lockfiles; matches components against a locally cached NVD + CPE Dictionary + OSV.dev; scores match confidence with two compared, SHAP-explained models; and triages findings through an autonomous agent policy into a structured, machine-readable report.

**Architecture:** A linear pipeline of small, single-responsibility modules under `it_security_agent/`, each consuming/producing the shared `Component` schema or plain dicts — no module reaches into another's internals. Three input paths (`sbom.py`, `image_scan.py`, `repo_scan.py`) converge on `Component`. Matching (`matching.py` + `normalize.py`) reads a local SQLite cache (`nvd_cache.py`) instead of live NVD calls. Model training (`labeling.py` + `model.py`) is an offline step producing a persisted model + threshold that `agent.py` loads, never retrains, at scan time. `agent.py` is the only module that makes a decision; everything below it only supplies evidence.

**Tech Stack:** Python 3.11+, `uv` for dependency management, `pytest` + `pytest-cov` for testing, `scikit-learn` (LogisticRegression + RandomForestClassifier), `shap` for explanations, `rapidfuzz` for string similarity, stdlib `sqlite3` for the local cache, `requests` for all HTTP clients, `packaging` for version parsing (already a transitive dependency via Week 2's code), `joblib` for model persistence.

## Global Constraints

- Coverage target: **80%** on `it_security_agent/`, measured via `pytest-cov`.
- Risk weighting for all model/threshold comparisons: **FN×10 + FP×1**, copied verbatim from Week 2's notebook — do not re-derive or change these weights.
- `registry_overlap` must **never** appear in `model.py`'s `FEATURES` list (leakage — see spec's normalize.py section). Any task touching `FEATURES` must preserve this.
- No live network calls anywhere in the test suite — every HTTP/subprocess call is dependency-injected (`get_fn`, `post_fn`, `run_fn` parameters defaulting to the real thing) and mocked in tests.
- New gitignore entries required: `nvd_cache.db`, `*.joblib` (persisted models) — added in Task 1.
- Use `uv add <package>` to add dependencies and `uv run pytest` / `uv run python` to execute anything, matching this project's existing uv-managed convention (see `pyproject.toml`, `uv.lock`).
- Package lives at `it_security_agent/` (repo root, alongside `notebooks/`), tests at `tests/`.

---

### Task 1: Project setup — dependencies, package skeleton, test config

**Files:**
- Modify: `pyproject.toml`
- Modify: `.gitignore`
- Create: `it_security_agent/__init__.py`
- Create: `tests/__init__.py`
- Test: `tests/test_package_import.py`

**Interfaces:**
- Produces: an importable `it_security_agent` package that all later tasks add modules to; a working `uv run pytest --cov=it_security_agent` command.

- [ ] **Step 1: Add new dependencies**

Run:
```bash
uv add rapidfuzz shap joblib
uv add --dev pytest pytest-cov
```

- [ ] **Step 2: Add pytest/coverage config to `pyproject.toml`**

Append to `pyproject.toml`:
```toml
[tool.pytest.ini_options]
testpaths = ["tests"]

[tool.coverage.run]
source = ["it_security_agent"]
```

- [ ] **Step 3: Add gitignore entries**

In `.gitignore`, add two lines:
```
nvd_cache.db
*.joblib
```

- [ ] **Step 4: Create the package skeleton**

`it_security_agent/__init__.py`:
```python
```
(empty file — modules are imported explicitly, e.g. `from it_security_agent import schema`)

`tests/__init__.py`:
```python
```
(empty file)

- [ ] **Step 5: Write the smoke test**

`tests/test_package_import.py`:
```python
def test_package_is_importable():
    import it_security_agent
    assert it_security_agent is not None
```

- [ ] **Step 6: Run test to verify it passes**

Run: `uv run pytest tests/test_package_import.py -v`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml uv.lock .gitignore it_security_agent/__init__.py tests/__init__.py tests/test_package_import.py
git commit -m "chore: scaffold it_security_agent package and test config"
```

---

### Task 2: `schema.py` — Component schema

**Files:**
- Create: `it_security_agent/schema.py`
- Test: `tests/test_schema.py`

**Interfaces:**
- Produces: `Component` dataclass (`name`, `version`, `ecosystem`, `source`, `purl`), `PURL_TYPE: dict[str, str]`, `build_purl(ecosystem, name, version) -> str`. Every later task that produces or consumes components uses this exact class.

- [ ] **Step 1: Write the failing tests**

`tests/test_schema.py`:
```python
from it_security_agent.schema import Component, build_purl


def test_build_purl_known_ecosystem():
    assert build_purl("PyPI", "requests", "2.31.0") == "pkg:pypi/requests@2.31.0"


def test_build_purl_unknown_ecosystem_falls_back_to_lowercase():
    assert build_purl("Nuget", "Foo", "1.0.0") == "pkg:nuget/Foo@1.0.0"


def test_component_auto_builds_purl():
    c = Component(name="requests", version="2.31.0", ecosystem="PyPI", source="test")
    assert c.purl == "pkg:pypi/requests@2.31.0"


def test_component_keeps_explicit_purl():
    c = Component(name="foo", version="1.0", ecosystem="Debian", source="test",
                   purl="pkg:deb/debian/foo@1.0")
    assert c.purl == "pkg:deb/debian/foo@1.0"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_schema.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'it_security_agent.schema'`

- [ ] **Step 3: Write the implementation**

`it_security_agent/schema.py`:
```python
from dataclasses import dataclass

PURL_TYPE = {
    "PyPI": "pypi",
    "npm": "npm",
    "Debian": "deb",
    "Alpine": "apk",
    "Go": "golang",
    "Maven": "maven",
    "Cargo": "cargo",
    "RubyGems": "gem",
}


def build_purl(ecosystem: str, name: str, version: str) -> str:
    ptype = PURL_TYPE.get(ecosystem, ecosystem.lower())
    return f"pkg:{ptype}/{name}@{version}"


@dataclass
class Component:
    name: str
    version: str
    ecosystem: str
    source: str
    purl: str = ""

    def __post_init__(self):
        if not self.purl:
            self.purl = build_purl(self.ecosystem, self.name, self.version)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_schema.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add it_security_agent/schema.py tests/test_schema.py
git commit -m "feat: add Component schema"
```

---

### Task 3: `nvd_client.py` — extracted NVD CVE API client

**Files:**
- Create: `it_security_agent/nvd_client.py`
- Test: `tests/test_nvd_client.py`

**Interfaces:**
- Produces: `nvd_get(params, retries=5, get_fn=requests.get, sleep_fn=time.sleep) -> dict`, `fetch_all_pages(params, page_size=2000, get_fn=requests.get, sleep_fn=time.sleep) -> tuple[list[dict], int]`, module constants `NVD_BASE`, `NVD_API_KEY`, `REQUEST_SPACING_SECONDS`.
- Consumes: nothing (leaf module, other than `requests`/`dotenv`).

- [ ] **Step 1: Write the failing tests**

`tests/test_nvd_client.py`:
```python
from unittest.mock import MagicMock

from it_security_agent import nvd_client


def _response(status_code=200, json_body=None):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = json_body or {}
    return resp


def test_nvd_get_returns_json_on_200():
    get_fn = MagicMock(return_value=_response(200, {"totalResults": 0, "vulnerabilities": []}))
    result = nvd_client.nvd_get({"foo": "bar"}, get_fn=get_fn)
    assert result == {"totalResults": 0, "vulnerabilities": []}
    get_fn.assert_called_once()


def test_nvd_get_retries_on_429_then_succeeds():
    get_fn = MagicMock(side_effect=[_response(429), _response(200, {"ok": True})])
    result = nvd_client.nvd_get({}, retries=3, get_fn=get_fn, sleep_fn=MagicMock())
    assert result == {"ok": True}
    assert get_fn.call_count == 2


def test_fetch_all_pages_paginates_until_total_reached():
    page1 = _response(200, {"totalResults": 3, "vulnerabilities": [1, 2]})
    page2 = _response(200, {"totalResults": 3, "vulnerabilities": [3]})
    get_fn = MagicMock(side_effect=[page1, page2])
    vulns, total = nvd_client.fetch_all_pages({}, page_size=2, get_fn=get_fn, sleep_fn=MagicMock())
    assert vulns == [1, 2, 3]
    assert total == 3
    assert get_fn.call_count == 2
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_nvd_client.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

`it_security_agent/nvd_client.py`:
```python
import os
import time

import requests
from dotenv import load_dotenv

load_dotenv()

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY")
REQUEST_SPACING_SECONDS = 1 if NVD_API_KEY else 6


def nvd_get(params, retries=5, get_fn=requests.get, sleep_fn=time.sleep):
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    for attempt in range(retries):
        try:
            resp = get_fn(NVD_BASE, params=params, headers=headers, timeout=90)
        except requests.exceptions.RequestException:
            if attempt < retries - 1:
                sleep_fn(REQUEST_SPACING_SECONDS * 2)
                continue
            raise
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code in (403, 429, 503) and attempt < retries - 1:
            sleep_fn(REQUEST_SPACING_SECONDS * 2)
            continue
        resp.raise_for_status()
    raise RuntimeError("NVD request failed after retries")


def fetch_all_pages(params, page_size=2000, get_fn=requests.get, sleep_fn=time.sleep):
    all_vulns = []
    start_index = 0
    total_results = None
    while True:
        page = nvd_get(
            {**params, "resultsPerPage": page_size, "startIndex": start_index},
            get_fn=get_fn, sleep_fn=sleep_fn,
        )
        all_vulns.extend(page["vulnerabilities"])
        total_results = page["totalResults"]
        start_index += page_size
        if start_index >= total_results:
            break
        sleep_fn(REQUEST_SPACING_SECONDS)
    return all_vulns, total_results
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_nvd_client.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add it_security_agent/nvd_client.py tests/test_nvd_client.py
git commit -m "feat: extract nvd_client from week1/2 notebooks"
```

---

### Task 4: `nvd_cache.py` — local SQLite CVE cache + sync

**Files:**
- Create: `it_security_agent/nvd_cache.py`
- Test: `tests/test_nvd_cache.py`

**Interfaces:**
- Consumes: `nvd_client.fetch_all_pages` (Task 3).
- Produces: `get_connection(db_path=None) -> sqlite3.Connection`, `sync_full(conn=None, fetch_fn=nvd_client.fetch_all_pages) -> int`, `sync_incremental(since: datetime, conn=None, fetch_fn=...) -> int`, `query_by_product_name(name: str, conn=None) -> list[dict]`, module constant `DB_PATH`.

- [ ] **Step 1: Write the failing tests**

`tests/test_nvd_cache.py`:
```python
from unittest.mock import MagicMock

from it_security_agent import nvd_cache


def _cve(cve_id, product="django", vendor="djangoproject"):
    return {
        "cve": {
            "id": cve_id,
            "published": "2024-01-01T00:00:00.000",
            "lastModified": "2024-01-02T00:00:00.000",
            "configurations": [{"nodes": [{"cpeMatch": [
                {"criteria": f"cpe:2.3:a:{vendor}:{product}:1.0:*:*:*:*:*:*:*"}
            ]}]}],
        }
    }


def test_sync_full_stores_and_query_finds_by_product_name():
    conn = nvd_cache.get_connection(":memory:")
    fetch_fn = MagicMock(return_value=([_cve("CVE-2024-0001")], 1))
    count = nvd_cache.sync_full(conn=conn, fetch_fn=fetch_fn)
    assert count == 1
    results = nvd_cache.query_by_product_name("django", conn=conn)
    assert len(results) == 1
    assert results[0]["cve"]["id"] == "CVE-2024-0001"


def test_query_by_product_name_no_match_returns_empty():
    conn = nvd_cache.get_connection(":memory:")
    fetch_fn = MagicMock(return_value=([_cve("CVE-2024-0001")], 1))
    nvd_cache.sync_full(conn=conn, fetch_fn=fetch_fn)
    assert nvd_cache.query_by_product_name("flask", conn=conn) == []


def test_sync_upserts_on_repeated_id():
    conn = nvd_cache.get_connection(":memory:")
    fetch_fn = MagicMock(return_value=([_cve("CVE-2024-0001")], 1))
    nvd_cache.sync_full(conn=conn, fetch_fn=fetch_fn)
    nvd_cache.sync_full(conn=conn, fetch_fn=fetch_fn)
    row_count = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    assert row_count == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_nvd_cache.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

`it_security_agent/nvd_cache.py`:
```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_nvd_cache.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add it_security_agent/nvd_cache.py tests/test_nvd_cache.py
git commit -m "feat: add local SQLite NVD cache with full/incremental sync"
```

---

### Task 5: `cpe_dictionary.py` — CPE Dictionary client + cache

**Files:**
- Create: `it_security_agent/cpe_dictionary.py`
- Test: `tests/test_cpe_dictionary.py`

**Interfaces:**
- Consumes: `nvd_cache.get_connection` (Task 4).
- Produces: `search(keyword: str, conn=None, api_key=None, get_fn=requests.get) -> list[dict]` (list of CPE Dictionary "product" entries).

- [ ] **Step 1: Write the failing tests**

`tests/test_cpe_dictionary.py`:
```python
from unittest.mock import MagicMock

from it_security_agent import cpe_dictionary, nvd_cache


def _response(products):
    resp = MagicMock()
    resp.json.return_value = {"products": products}
    resp.raise_for_status = MagicMock()
    return resp


def test_search_calls_api_and_caches():
    conn = nvd_cache.get_connection(":memory:")
    products = [{"cpe": {"cpeName": "cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*"}}]
    get_fn = MagicMock(return_value=_response(products))
    result = cpe_dictionary.search("django", conn=conn, get_fn=get_fn)
    assert result == products
    get_fn.assert_called_once()


def test_search_second_call_hits_cache_not_network():
    conn = nvd_cache.get_connection(":memory:")
    products = [{"cpe": {"cpeName": "cpe:2.3:a:djangoproject:django:*:*:*:*:*:*:*:*"}}]
    get_fn = MagicMock(return_value=_response(products))
    cpe_dictionary.search("django", conn=conn, get_fn=get_fn)
    cpe_dictionary.search("django", conn=conn, get_fn=get_fn)
    assert get_fn.call_count == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_cpe_dictionary.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

`it_security_agent/cpe_dictionary.py`:
```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_cpe_dictionary.py -v`
Expected: PASS (2 tests)

- [ ] **Step 5: Commit**

```bash
git add it_security_agent/cpe_dictionary.py tests/test_cpe_dictionary.py
git commit -m "feat: add CPE Dictionary client with local cache"
```

---

### Task 6: `registry.py` — PyPI/npm registry metadata client + cache

**Files:**
- Create: `it_security_agent/registry.py`
- Test: `tests/test_registry.py`

**Interfaces:**
- Consumes: `nvd_cache.get_connection` (Task 4).
- Produces: `fetch_metadata(ecosystem: str, name: str, get_fn=requests.get) -> dict | None`, `cached_fetch_metadata(ecosystem: str, name: str, conn=None, get_fn=requests.get) -> dict | None` (both return `{"urls": list[str]}` or `None`).

- [ ] **Step 1: Write the failing tests**

`tests/test_registry.py`:
```python
from unittest.mock import MagicMock

from it_security_agent import registry, nvd_cache


def _response(status_code, body):
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body
    return resp


def test_fetch_metadata_pypi():
    body = {"info": {"home_page": "https://www.djangoproject.com/",
                      "project_urls": {"Source": "https://github.com/django/django"}}}
    get_fn = MagicMock(return_value=_response(200, body))
    result = registry.fetch_metadata("PyPI", "django", get_fn=get_fn)
    assert "https://www.djangoproject.com/" in result["urls"]
    assert "https://github.com/django/django" in result["urls"]


def test_fetch_metadata_npm():
    body = {"homepage": "https://lodash.com", "repository": {"url": "git+https://github.com/lodash/lodash.git"}}
    get_fn = MagicMock(return_value=_response(200, body))
    result = registry.fetch_metadata("npm", "lodash", get_fn=get_fn)
    assert "https://lodash.com" in result["urls"]


def test_fetch_metadata_unknown_ecosystem_returns_none():
    assert registry.fetch_metadata("Debian", "libssl", get_fn=MagicMock()) is None


def test_fetch_metadata_404_returns_none():
    get_fn = MagicMock(return_value=_response(404, {}))
    assert registry.fetch_metadata("PyPI", "does-not-exist", get_fn=get_fn) is None


def test_cached_fetch_metadata_dedupes_network_calls():
    conn = nvd_cache.get_connection(":memory:")
    body = {"info": {"home_page": "https://www.djangoproject.com/", "project_urls": {}}}
    get_fn = MagicMock(return_value=_response(200, body))
    registry.cached_fetch_metadata("PyPI", "django", conn=conn, get_fn=get_fn)
    registry.cached_fetch_metadata("PyPI", "django", conn=conn, get_fn=get_fn)
    assert get_fn.call_count == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_registry.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

`it_security_agent/registry.py`:
```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_registry.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add it_security_agent/registry.py tests/test_registry.py
git commit -m "feat: add PyPI/npm registry metadata client with cache"
```

---

### Task 7: `sbom.py` — CycloneDX + SPDX parsers

**Files:**
- Create: `it_security_agent/sbom.py`
- Create: `tests/fixtures/sample_cyclonedx.json`
- Create: `tests/fixtures/sample_spdx.json`
- Test: `tests/test_sbom.py`

**Interfaces:**
- Consumes: `schema.Component`, `schema.PURL_TYPE` (Task 2).
- Produces: `parse_cyclonedx(data: dict, source_label="SBOM (CycloneDX)") -> list[Component]`, `parse_spdx(data: dict, source_label="SBOM (SPDX)") -> tuple[list[Component], int]`.

- [ ] **Step 1: Create fixture files**

`tests/fixtures/sample_cyclonedx.json`:
```json
{
  "bomFormat": "CycloneDX",
  "components": [
    {"type": "library", "name": "requests", "version": "2.31.0", "purl": "pkg:pypi/requests@2.31.0"},
    {"type": "library", "name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"},
    {"type": "library", "name": "no-purl-component", "version": "1.0.0"}
  ]
}
```

`tests/fixtures/sample_spdx.json`:
```json
{
  "spdxVersion": "SPDX-2.3",
  "packages": [
    {
      "name": "requests",
      "versionInfo": "2.31.0",
      "externalRefs": [
        {"referenceType": "purl", "referenceLocator": "pkg:pypi/requests@2.31.0"}
      ]
    },
    {
      "name": "unresolvable-package",
      "versionInfo": "1.0.0",
      "externalRefs": []
    }
  ]
}
```

- [ ] **Step 2: Write the failing tests**

`tests/test_sbom.py`:
```python
import json
from pathlib import Path

from it_security_agent import sbom

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_cyclonedx_maps_components_with_purl():
    data = json.loads((FIXTURES / "sample_cyclonedx.json").read_text())
    components = sbom.parse_cyclonedx(data)
    names = {c.name for c in components}
    assert names == {"requests", "lodash"}
    requests_component = next(c for c in components if c.name == "requests")
    assert requests_component.ecosystem == "PyPI"
    assert requests_component.version == "2.31.0"


def test_parse_cyclonedx_skips_components_without_purl():
    data = json.loads((FIXTURES / "sample_cyclonedx.json").read_text())
    components = sbom.parse_cyclonedx(data)
    assert "no-purl-component" not in {c.name for c in components}


def test_parse_spdx_uses_external_ref_purl():
    data = json.loads((FIXTURES / "sample_spdx.json").read_text())
    components, unparsed = sbom.parse_spdx(data)
    assert len(components) == 1
    assert components[0].name == "requests"
    assert components[0].ecosystem == "PyPI"


def test_parse_spdx_counts_packages_without_purl_as_unparsed():
    data = json.loads((FIXTURES / "sample_spdx.json").read_text())
    _, unparsed = sbom.parse_spdx(data)
    assert unparsed == 1
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/test_sbom.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 4: Write the implementation**

`it_security_agent/sbom.py`:
```python
from it_security_agent.schema import Component, PURL_TYPE

_SCHEME_TO_ECOSYSTEM = {ptype: eco for eco, ptype in PURL_TYPE.items()}


def _ecosystem_from_purl(purl: str) -> str:
    scheme = purl.replace("pkg:", "").split("/")[0]
    return _SCHEME_TO_ECOSYSTEM.get(scheme, scheme)


def parse_cyclonedx(data: dict, source_label: str = "SBOM (CycloneDX)"):
    components = []
    for c in data.get("components", []):
        purl = c.get("purl")
        if not purl:
            continue
        components.append(Component(
            name=c.get("name", ""), version=c.get("version", ""),
            ecosystem=_ecosystem_from_purl(purl), source=source_label, purl=purl,
        ))
    return components


def parse_spdx(data: dict, source_label: str = "SBOM (SPDX)"):
    components = []
    unparsed = 0
    for pkg in data.get("packages", []):
        purl = next(
            (r.get("referenceLocator") for r in pkg.get("externalRefs", [])
             if r.get("referenceType") == "purl"),
            None,
        )
        if not purl:
            unparsed += 1
            continue
        components.append(Component(
            name=pkg.get("name", ""), version=pkg.get("versionInfo", ""),
            ecosystem=_ecosystem_from_purl(purl), source=source_label, purl=purl,
        ))
    return components, unparsed
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_sbom.py -v`
Expected: PASS (4 tests)

- [ ] **Step 6: Commit**

```bash
git add it_security_agent/sbom.py tests/test_sbom.py tests/fixtures/sample_cyclonedx.json tests/fixtures/sample_spdx.json
git commit -m "feat: add CycloneDX and SPDX SBOM parsers"
```

---

### Task 8: `repo_scan.py` — generate components from repo lockfiles

**Files:**
- Create: `it_security_agent/repo_scan.py`
- Create: `tests/fixtures/sample_uv.lock`
- Create: `tests/fixtures/sample_package-lock.json`
- Test: `tests/test_repo_scan.py`

**Interfaces:**
- Consumes: `schema.Component` (Task 2).
- Produces: `parse_uv_lock(path: Path, source_label="uv.lock") -> list[Component]`, `parse_package_lock(path: Path, source_label="package-lock.json") -> list[Component]`.

- [ ] **Step 1: Create fixture files**

`tests/fixtures/sample_uv.lock`:
```toml
version = 1
requires-python = ">=3.11"

[[package]]
name = "it-security-agent"
version = "0.1.0"
source = { virtual = "." }

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "urllib3"
version = "2.2.1"
source = { registry = "https://pypi.org/simple" }
```

`tests/fixtures/sample_package-lock.json`:
```json
{
  "name": "sample-project",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "sample-project", "version": "1.0.0"},
    "node_modules/lodash": {"version": "4.17.21"},
    "node_modules/axios": {"version": "1.6.0"}
  }
}
```

- [ ] **Step 2: Write the failing tests**

`tests/test_repo_scan.py`:
```python
from pathlib import Path

from it_security_agent import repo_scan

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_uv_lock_excludes_virtual_project_package():
    components = repo_scan.parse_uv_lock(FIXTURES / "sample_uv.lock")
    names = {c.name for c in components}
    assert "it-security-agent" not in names
    assert names == {"requests", "urllib3"}


def test_parse_uv_lock_sets_exact_pinned_version():
    components = repo_scan.parse_uv_lock(FIXTURES / "sample_uv.lock")
    requests_component = next(c for c in components if c.name == "requests")
    assert requests_component.version == "2.31.0"
    assert requests_component.ecosystem == "PyPI"


def test_parse_package_lock_excludes_root_package():
    components = repo_scan.parse_package_lock(FIXTURES / "sample_package-lock.json")
    names = {c.name for c in components}
    assert "sample-project" not in names
    assert names == {"lodash", "axios"}


def test_parse_package_lock_sets_ecosystem_npm():
    components = repo_scan.parse_package_lock(FIXTURES / "sample_package-lock.json")
    lodash = next(c for c in components if c.name == "lodash")
    assert lodash.ecosystem == "npm"
    assert lodash.version == "4.17.21"
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/test_repo_scan.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 4: Write the implementation**

`it_security_agent/repo_scan.py`:
```python
import json
import tomllib
from pathlib import Path

from it_security_agent.schema import Component


def parse_uv_lock(path: Path, source_label: str = "uv.lock"):
    lock = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    components = []
    for pkg in lock.get("package", []):
        if "registry" not in pkg.get("source", {}):
            continue  # skips the virtual project package itself
        components.append(Component(
            name=pkg["name"], version=pkg["version"], ecosystem="PyPI", source=source_label,
        ))
    return components


def parse_package_lock(path: Path, source_label: str = "package-lock.json"):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    components = []
    for key, pkg in data.get("packages", {}).items():
        if key == "":
            continue  # the root project package itself
        name = key.split("node_modules/")[-1]
        version = pkg.get("version")
        if not version:
            continue
        components.append(Component(
            name=name, version=version, ecosystem="npm", source=source_label,
        ))
    return components
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_repo_scan.py -v`
Expected: PASS (4 tests)

- [ ] **Step 6: Commit**

```bash
git add it_security_agent/repo_scan.py tests/test_repo_scan.py tests/fixtures/sample_uv.lock tests/fixtures/sample_package-lock.json
git commit -m "feat: add repo lockfile scanning (uv.lock, package-lock.json)"
```

---

### Task 9: `image_scan.py` — Syft-based container image scanning

**Files:**
- Create: `it_security_agent/image_scan.py`
- Create: `tests/fixtures/sample_syft_cyclonedx.json`
- Test: `tests/test_image_scan.py`

**Interfaces:**
- Consumes: `sbom.parse_cyclonedx` (Task 7).
- Produces: `scan_image(image_ref: str, run_fn=subprocess.run) -> list[Component]`, `ImageScanError` exception class.

- [ ] **Step 1: Create fixture file**

`tests/fixtures/sample_syft_cyclonedx.json`:
```json
{
  "bomFormat": "CycloneDX",
  "components": [
    {"type": "library", "name": "openssl", "version": "3.0.2", "purl": "pkg:deb/debian/openssl@3.0.2"},
    {"type": "library", "name": "flask", "version": "2.0.1", "purl": "pkg:pypi/flask@2.0.1"}
  ]
}
```

- [ ] **Step 2: Write the failing tests**

`tests/test_image_scan.py`:
```python
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from it_security_agent import image_scan

FIXTURES = Path(__file__).parent / "fixtures"


def test_scan_image_parses_syft_output():
    stdout = (FIXTURES / "sample_syft_cyclonedx.json").read_text()
    run_fn = MagicMock(return_value=MagicMock(returncode=0, stdout=stdout, stderr=""))
    components = image_scan.scan_image("python:3.11-slim", run_fn=run_fn)
    names = {c.name for c in components}
    assert names == {"openssl", "flask"}
    run_fn.assert_called_once()
    args = run_fn.call_args[0][0]
    assert args[0] == "syft"
    assert "python:3.11-slim" in args


def test_scan_image_raises_on_syft_not_found():
    run_fn = MagicMock(side_effect=FileNotFoundError())
    with pytest.raises(image_scan.ImageScanError):
        image_scan.scan_image("python:3.11-slim", run_fn=run_fn)


def test_scan_image_raises_on_nonzero_exit():
    run_fn = MagicMock(return_value=MagicMock(returncode=1, stdout="", stderr="image not found"))
    with pytest.raises(image_scan.ImageScanError, match="image not found"):
        image_scan.scan_image("does-not-exist:latest", run_fn=run_fn)
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `uv run pytest tests/test_image_scan.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 4: Write the implementation**

`it_security_agent/image_scan.py`:
```python
import json
import subprocess

from it_security_agent.sbom import parse_cyclonedx


class ImageScanError(RuntimeError):
    pass


def scan_image(image_ref: str, run_fn=subprocess.run):
    try:
        result = run_fn(
            ["syft", image_ref, "-o", "cyclonedx-json"],
            capture_output=True, text=True, timeout=300,
        )
    except FileNotFoundError as exc:
        raise ImageScanError("syft CLI not found - install it before scanning images") from exc
    if result.returncode != 0:
        raise ImageScanError(f"syft failed for {image_ref}: {result.stderr.strip()}")
    data = json.loads(result.stdout)
    return parse_cyclonedx(data, source_label=f"container image ({image_ref})")
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `uv run pytest tests/test_image_scan.py -v`
Expected: PASS (3 tests)

- [ ] **Step 6: Commit**

```bash
git add it_security_agent/image_scan.py tests/test_image_scan.py tests/fixtures/sample_syft_cyclonedx.json
git commit -m "feat: add Syft-based container image scanning"
```

---

### Task 10: `osv.py` — OSV.dev client (PyPI/npm only)

**Files:**
- Create: `it_security_agent/osv.py`
- Test: `tests/test_osv.py`

**Interfaces:**
- Consumes: `nvd_cache.get_connection` (Task 4).
- Produces: `query(ecosystem: str, name: str, version: str, conn=None, post_fn=requests.post) -> list[dict]`.

- [ ] **Step 1: Write the failing tests**

`tests/test_osv.py`:
```python
from unittest.mock import MagicMock

from it_security_agent import osv, nvd_cache


def _response(vulns):
    resp = MagicMock()
    resp.json.return_value = {"vulns": vulns}
    resp.raise_for_status = MagicMock()
    return resp


def test_query_calls_osv_for_pypi():
    conn = nvd_cache.get_connection(":memory:")
    post_fn = MagicMock(return_value=_response([{"id": "GHSA-xxxx"}]))
    result = osv.query("PyPI", "django", "2.2.0", conn=conn, post_fn=post_fn)
    assert result == [{"id": "GHSA-xxxx"}]
    post_fn.assert_called_once()


def test_query_debian_short_circuits_no_network_call():
    conn = nvd_cache.get_connection(":memory:")
    post_fn = MagicMock()
    result = osv.query("Debian", "openssl", "3.0.2", conn=conn, post_fn=post_fn)
    assert result == []
    post_fn.assert_not_called()


def test_query_second_call_hits_cache_not_network():
    conn = nvd_cache.get_connection(":memory:")
    post_fn = MagicMock(return_value=_response([{"id": "GHSA-xxxx"}]))
    osv.query("npm", "lodash", "4.17.15", conn=conn, post_fn=post_fn)
    osv.query("npm", "lodash", "4.17.15", conn=conn, post_fn=post_fn)
    assert post_fn.call_count == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_osv.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

`it_security_agent/osv.py`:
```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_osv.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add it_security_agent/osv.py tests/test_osv.py
git commit -m "feat: add OSV.dev client scoped to PyPI/npm"
```

---

### Task 11: `normalize.py` — purl-to-CPE vendor resolution (raw signals only)

**Files:**
- Create: `it_security_agent/normalize.py`
- Test: `tests/test_normalize.py`

**Interfaces:**
- Consumes: `cpe_dictionary.search` (Task 5), `registry.cached_fetch_metadata` (Task 6).
- Produces: `VendorCandidate` dataclass (`vendor`, `product`, `signals: dict`), `resolve_vendor(package_name: str, ecosystem: str, conn=None) -> list[VendorCandidate]`, `PY_KEYWORDS`, `JS_KEYWORDS` constants.

- [ ] **Step 1: Write the failing tests**

`tests/test_normalize.py`:
```python
from unittest.mock import patch

from it_security_agent import normalize, nvd_cache


def _cpe_product(vendor, product, title, refs=None):
    return {
        "cpe": {
            "cpeName": f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*",
            "titles": [{"lang": "en", "title": title}],
            "refs": [{"ref": r} for r in (refs or [])],
        }
    }


def test_resolve_vendor_computes_name_similarity_and_vendor_equals_package():
    products = [_cpe_product("djangoproject", "django", "Django web framework")]
    with patch("it_security_agent.cpe_dictionary.search", return_value=products), \
         patch("it_security_agent.registry.cached_fetch_metadata", return_value=None):
        candidates = normalize.resolve_vendor("django", "PyPI")
    assert len(candidates) == 1
    c = candidates[0]
    assert c.vendor == "djangoproject"
    assert c.signals["vendor_equals_package"] == 0
    assert c.signals["name_similarity"] == 1.0


def test_resolve_vendor_registry_overlap_true_when_domains_match():
    products = [_cpe_product("djangoproject", "django", "Django", refs=["https://github.com/django/django"])]
    registry_meta = {"urls": ["https://github.com/django/django"]}
    with patch("it_security_agent.cpe_dictionary.search", return_value=products), \
         patch("it_security_agent.registry.cached_fetch_metadata", return_value=registry_meta):
        candidates = normalize.resolve_vendor("django", "PyPI")
    assert candidates[0].signals["registry_overlap"] is True


def test_resolve_vendor_registry_overlap_none_when_no_registry_data():
    products = [_cpe_product("djangoproject", "django", "Django")]
    with patch("it_security_agent.cpe_dictionary.search", return_value=products), \
         patch("it_security_agent.registry.cached_fetch_metadata", return_value=None):
        candidates = normalize.resolve_vendor("django", "PyPI")
    assert candidates[0].signals["registry_overlap"] is None


def test_resolve_vendor_does_not_combine_signals_into_a_score():
    products = [_cpe_product("djangoproject", "django", "Django")]
    with patch("it_security_agent.cpe_dictionary.search", return_value=products), \
         patch("it_security_agent.registry.cached_fetch_metadata", return_value=None):
        candidates = normalize.resolve_vendor("django", "PyPI")
    assert not hasattr(candidates[0], "score")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_normalize.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

`it_security_agent/normalize.py`:
```python
from dataclasses import dataclass, field

from rapidfuzz import fuzz

from it_security_agent import cpe_dictionary, registry

PY_KEYWORDS = ["python", "pypi", "pip ", "django", "flask", "wsgi", "cpython"]
JS_KEYWORDS = ["javascript", "node.js", "nodejs", "npm ", "react", "webpack", "ecmascript"]


@dataclass
class VendorCandidate:
    vendor: str
    product: str
    signals: dict = field(default_factory=dict)


def _domain(url: str) -> str:
    url = url.lower().replace("https://", "").replace("http://", "")
    return url.split("/")[0].replace("www.", "")


def _registry_overlap(ecosystem, name, product_refs, conn):
    metadata = registry.cached_fetch_metadata(ecosystem, name, conn=conn)
    if not metadata or not metadata.get("urls"):
        return None
    reg_domains = {_domain(u) for u in metadata["urls"]}
    ref_domains = {_domain(u) for u in product_refs}
    return bool(reg_domains & ref_domains)


def resolve_vendor(package_name: str, ecosystem: str, conn=None):
    products = cpe_dictionary.search(package_name, conn=conn)
    candidates = []
    for p in products:
        cpe = p.get("cpe", {})
        parts = cpe.get("cpeName", "").split(":")
        if len(parts) < 5:
            continue
        vendor, product = parts[3], parts[4]
        title = next((t["title"] for t in cpe.get("titles", []) if t.get("lang") == "en"), product)
        refs = [r.get("ref", "") for r in cpe.get("refs", [])]

        name_similarity = fuzz.token_set_ratio(package_name.lower(), product.lower()) / 100.0
        overlap = _registry_overlap(ecosystem, package_name, refs, conn)
        text = title.lower()
        py_score = sum(text.count(k) for k in PY_KEYWORDS)
        js_score = sum(text.count(k) for k in JS_KEYWORDS)
        alignment = (py_score - js_score) if ecosystem == "PyPI" else (js_score - py_score)

        candidates.append(VendorCandidate(
            vendor=vendor, product=product,
            signals={
                "vendor_equals_package": int(vendor.lower() == package_name.lower()),
                "name_similarity": name_similarity,
                "registry_overlap": overlap,
                "py_keyword_score": py_score,
                "js_keyword_score": js_score,
                "keyword_alignment": alignment,
            },
        ))
    return candidates
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_normalize.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add it_security_agent/normalize.py tests/test_normalize.py
git commit -m "feat: add normalize.py purl-to-CPE vendor resolution"
```

---

### Task 12: `matching.py` — candidate CVE matching against the local cache

**Files:**
- Create: `it_security_agent/matching.py`
- Test: `tests/test_matching.py`

**Interfaces:**
- Consumes: `nvd_cache.query_by_product_name` (Task 4), `normalize.resolve_vendor` (Task 11), `schema.Component` (Task 2).
- Produces: `parse_version`, `name_variants`, `version_applies`, `best_cvss`, `cwe_ids`, `english_description`, `find_candidates(component: Component, conn=None) -> tuple[list[dict], list[str]]` (matches, rejected CVE ids).

- [ ] **Step 1: Write the failing tests**

`tests/test_matching.py`:
```python
from unittest.mock import patch

from it_security_agent import matching, nvd_cache
from it_security_agent.normalize import VendorCandidate
from it_security_agent.schema import Component


def _cve(cve_id, vendor, product, version_field="1.0.0", metrics=None):
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": "A test vulnerability"}],
            "metrics": metrics or {"cvssMetricV31": [{"baseSeverity": "HIGH", "cvssData": {"baseScore": 7.5}}]},
            "weaknesses": [],
            "configurations": [{"nodes": [{"cpeMatch": [
                {"criteria": f"cpe:2.3:a:{vendor}:{product}:{version_field}:*:*:*:*:*:*:*", "vulnerable": True}
            ]}]}],
        }
    }


def test_find_candidates_matches_version_and_attaches_vendor_candidate():
    conn = nvd_cache.get_connection(":memory:")
    component = Component(name="django", version="1.0.0", ecosystem="PyPI", source="test")
    candidate = VendorCandidate(vendor="djangoproject", product="django", signals={"vendor_equals_package": 0})
    with patch("it_security_agent.nvd_cache.query_by_product_name",
               return_value=[_cve("CVE-2024-0001", "djangoproject", "django")]), \
         patch("it_security_agent.normalize.resolve_vendor", return_value=[candidate]):
        matches, rejected = matching.find_candidates(component, conn=conn)
    assert len(matches) == 1
    assert matches[0]["cve"] == "CVE-2024-0001"
    assert matches[0]["vendor_candidate"] is candidate
    assert rejected == []


def test_find_candidates_rejects_when_version_does_not_apply():
    conn = nvd_cache.get_connection(":memory:")
    component = Component(name="django", version="9.9.9", ecosystem="PyPI", source="test")
    with patch("it_security_agent.nvd_cache.query_by_product_name",
               return_value=[_cve("CVE-2024-0001", "djangoproject", "django", version_field="1.0.0")]), \
         patch("it_security_agent.normalize.resolve_vendor", return_value=[]):
        matches, rejected = matching.find_candidates(component, conn=conn)
    assert matches == []
    assert rejected == ["CVE-2024-0001"]


def test_known_collision_babel_stays_a_collision():
    # Regression case from Week 2: babel (PyPI, our package) collides with babeljs (npm).
    # normalize.resolve_vendor returning no candidate for the collision vendor means
    # find_candidates cannot attach a vendor_candidate, so it can never become "confirmed".
    conn = nvd_cache.get_connection(":memory:")
    component = Component(name="babel", version="2.18.0", ecosystem="PyPI", source="test")
    with patch("it_security_agent.nvd_cache.query_by_product_name",
               return_value=[_cve("CVE-2024-0002", "babeljs", "babel")]), \
         patch("it_security_agent.normalize.resolve_vendor", return_value=[]):
        matches, rejected = matching.find_candidates(component, conn=conn)
    assert len(matches) == 1
    assert matches[0]["vendor_candidate"] is None


def test_version_applies_exact_version():
    m = {"criteria": "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*", "vulnerable": True}
    assert matching.version_applies(m, matching.parse_version("1.0.0")) is True
    assert matching.version_applies(m, matching.parse_version("2.0.0")) is False


def test_version_applies_range():
    m = {
        "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", "vulnerable": True,
        "versionStartIncluding": "1.0.0", "versionEndExcluding": "2.0.0",
    }
    assert matching.version_applies(m, matching.parse_version("1.5.0")) is True
    assert matching.version_applies(m, matching.parse_version("2.0.0")) is False
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_matching.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

`it_security_agent/matching.py`:
```python
from packaging.version import InvalidVersion, Version

from it_security_agent import normalize, nvd_cache


def parse_version(text):
    try:
        return Version(text)
    except (InvalidVersion, TypeError):
        return None


def name_variants(name):
    n = name.lower()
    return sorted({n, n.replace("-", "_"), n.replace("_", "-")})


def version_applies(m, pinned):
    if pinned is None:
        return False
    if not m.get("vulnerable", True):
        return False
    cpe_version = m["criteria"].split(":")[5]
    if cpe_version not in ("*", "-"):
        return parse_version(cpe_version) == pinned
    checks = (
        ("versionStartIncluding", lambda b: pinned < b),
        ("versionStartExcluding", lambda b: pinned <= b),
        ("versionEndIncluding", lambda b: pinned > b),
        ("versionEndExcluding", lambda b: pinned >= b),
    )
    for field_name, fails in checks:
        if field_name not in m:
            continue
        bound = parse_version(m[field_name])
        if bound is None or fails(bound):
            return False
    return True


def best_cvss(metrics):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m = metrics[key][0]
            data = m.get("cvssData", {})
            return data.get("baseScore"), m.get("baseSeverity", data.get("baseSeverity"))
    return None, None


def cwe_ids(weaknesses):
    ids = []
    for w in weaknesses or []:
        for d in w.get("description", []):
            if d.get("lang") == "en" and d.get("value", "").startswith("CWE-"):
                ids.append(d["value"])
    return ids


def english_description(cve):
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d["value"]
    return ""


def find_candidates(component, conn=None):
    pinned = parse_version(component.version)
    resolved = {c.vendor: c for c in normalize.resolve_vendor(component.name, component.ecosystem, conn=conn)}
    seen = set()
    matches, rejected = [], []
    for spelling in name_variants(component.name):
        for item in nvd_cache.query_by_product_name(spelling, conn=conn):
            cve = item["cve"]
            if cve["id"] in seen:
                continue
            matched_vendor, name_matched_at_all = None, False
            for group in cve.get("configurations") or []:
                for node in group.get("nodes", []):
                    for m in node.get("cpeMatch", []):
                        parts = m.get("criteria", "").split(":")
                        if len(parts) > 5 and parts[4].lower() == spelling:
                            name_matched_at_all = True
                            if version_applies(m, pinned):
                                matched_vendor = parts[3]
                                break
                    if matched_vendor:
                        break
                if matched_vendor:
                    break
            seen.add(cve["id"])
            if matched_vendor:
                score, severity = best_cvss(cve.get("metrics", {}))
                matches.append({
                    "cve": cve["id"], "severity": severity or "UNKNOWN", "cvss_score": score,
                    "cwe_ids": cwe_ids(cve.get("weaknesses")), "description": english_description(cve),
                    "vendor": matched_vendor, "vendor_candidate": resolved.get(matched_vendor),
                })
            elif name_matched_at_all:
                rejected.append(cve["id"])
    return matches, rejected
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_matching.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add it_security_agent/matching.py tests/test_matching.py
git commit -m "feat: add matching.py - candidate CVE matching against local cache"
```

---

### Task 13: `kev.py` — CISA KEV enrichment

**Files:**
- Create: `it_security_agent/kev.py`
- Test: `tests/test_kev.py`

**Interfaces:**
- Consumes: `nvd_cache.get_connection` (Task 4).
- Produces: `refresh(conn=None, get_fn=requests.get) -> int`, `is_kev(cve_id: str, conn=None) -> dict | None`.

- [ ] **Step 1: Write the failing tests**

`tests/test_kev.py`:
```python
from unittest.mock import MagicMock

from it_security_agent import kev, nvd_cache


def _response(entries):
    resp = MagicMock()
    resp.json.return_value = {"vulnerabilities": entries}
    resp.raise_for_status = MagicMock()
    return resp


def test_refresh_stores_entries():
    conn = nvd_cache.get_connection(":memory:")
    entries = [{"cveID": "CVE-2024-0001", "dueDate": "2024-02-01"}]
    get_fn = MagicMock(return_value=_response(entries))
    count = kev.refresh(conn=conn, get_fn=get_fn)
    assert count == 1


def test_is_kev_returns_entry_when_present():
    conn = nvd_cache.get_connection(":memory:")
    entries = [{"cveID": "CVE-2024-0001", "dueDate": "2024-02-01"}]
    kev.refresh(conn=conn, get_fn=MagicMock(return_value=_response(entries)))
    result = kev.is_kev("CVE-2024-0001", conn=conn)
    assert result["dueDate"] == "2024-02-01"


def test_is_kev_returns_none_when_absent():
    conn = nvd_cache.get_connection(":memory:")
    kev.refresh(conn=conn, get_fn=MagicMock(return_value=_response([])))
    assert kev.is_kev("CVE-9999-9999", conn=conn) is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_kev.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

`it_security_agent/kev.py`:
```python
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_kev.py -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add it_security_agent/kev.py tests/test_kev.py
git commit -m "feat: add CISA KEV enrichment"
```

---

### Task 14: `labeling.py` — training-label dataset (no leakage)

**Files:**
- Create: `it_security_agent/labeling.py`
- Test: `tests/test_labeling.py`

**Interfaces:**
- Consumes: `normalize.resolve_vendor` (Task 11), `osv.query` (Task 10), `schema.Component` (Task 2).
- Produces: `FEATURES: list[str]` (module constant, excludes `registry_overlap`), `build_training_row(...) -> dict`, `build_dataset(components, conn=None) -> pandas.DataFrame`.

- [ ] **Step 1: Write the failing tests**

`tests/test_labeling.py`:
```python
from unittest.mock import patch

from it_security_agent import labeling
from it_security_agent.normalize import VendorCandidate
from it_security_agent.schema import Component


def test_features_never_includes_registry_overlap():
    assert "registry_overlap" not in labeling.FEATURES


def test_build_dataset_labels_true_when_registry_overlap_true():
    component = Component(name="django", version="2.2.0", ecosystem="PyPI", source="test")
    candidate = VendorCandidate(
        vendor="djangoproject", product="django",
        signals={"vendor_equals_package": 0, "name_similarity": 1.0, "registry_overlap": True,
                 "py_keyword_score": 5, "js_keyword_score": 0, "keyword_alignment": 5},
    )
    with patch("it_security_agent.normalize.resolve_vendor", return_value=[candidate]), \
         patch("it_security_agent.osv.query", return_value=[]):
        df = labeling.build_dataset([component])
    assert len(df) == 1
    assert df.iloc[0]["label_real_match"] == True


def test_build_dataset_skips_candidates_with_unknown_overlap():
    component = Component(name="foo", version="1.0.0", ecosystem="Debian", source="test")
    candidate = VendorCandidate(
        vendor="foo", product="foo",
        signals={"vendor_equals_package": 1, "name_similarity": 1.0, "registry_overlap": None,
                 "py_keyword_score": 0, "js_keyword_score": 0, "keyword_alignment": 0},
    )
    with patch("it_security_agent.normalize.resolve_vendor", return_value=[candidate]), \
         patch("it_security_agent.osv.query", return_value=[]):
        df = labeling.build_dataset([component])
    assert len(df) == 0


def test_build_dataset_includes_osv_corroborated_as_a_feature():
    component = Component(name="axios", version="0.21.0", ecosystem="npm", source="test")
    candidate = VendorCandidate(
        vendor="axios", product="axios",
        signals={"vendor_equals_package": 1, "name_similarity": 1.0, "registry_overlap": True,
                 "py_keyword_score": 0, "js_keyword_score": 3, "keyword_alignment": 3},
    )
    with patch("it_security_agent.normalize.resolve_vendor", return_value=[candidate]), \
         patch("it_security_agent.osv.query", return_value=[{"id": "GHSA-xxxx"}]):
        df = labeling.build_dataset([component])
    assert df.iloc[0]["osv_corroborated"] == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_labeling.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

`it_security_agent/labeling.py`:
```python
import pandas as pd

from it_security_agent import normalize, osv

FEATURES = [
    "vendor_equals_package", "name_similarity", "py_keyword_score",
    "js_keyword_score", "keyword_alignment", "ecosystem_pypi", "osv_corroborated",
]


def build_training_row(package_name, ecosystem, vendor_candidate, component_version, label, conn=None):
    osv_vulns = osv.query(ecosystem, package_name, component_version, conn=conn)
    signals = vendor_candidate.signals
    return {
        "package": package_name, "ecosystem": ecosystem, "vendor": vendor_candidate.vendor,
        "vendor_equals_package": signals["vendor_equals_package"],
        "name_similarity": signals["name_similarity"],
        "py_keyword_score": signals["py_keyword_score"],
        "js_keyword_score": signals["js_keyword_score"],
        "keyword_alignment": signals["keyword_alignment"],
        "ecosystem_pypi": int(ecosystem == "PyPI"),
        "osv_corroborated": int(len(osv_vulns) > 0),
        "label_real_match": label,
    }


def build_dataset(components, conn=None) -> pd.DataFrame:
    rows = []
    for component in components:
        for candidate in normalize.resolve_vendor(component.name, component.ecosystem, conn=conn):
            overlap = candidate.signals.get("registry_overlap")
            if overlap is None:
                continue  # can't confidently label without registry data
            rows.append(build_training_row(
                component.name, component.ecosystem, candidate, component.version, bool(overlap), conn=conn,
            ))
    return pd.DataFrame(rows)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_labeling.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add it_security_agent/labeling.py tests/test_labeling.py
git commit -m "feat: add labeling.py - registry-overlap ground truth, no leakage"
```

---

### Task 15: `model.py` — LR/RandomForest training, comparison, persistence

**Files:**
- Create: `it_security_agent/model.py`
- Test: `tests/test_model.py`

**Interfaces:**
- Consumes: `labeling.FEATURES` (Task 14).
- Produces: `FN_WEIGHT = 10`, `FP_WEIGHT = 1`, `train_and_compare(df: pd.DataFrame, model_dir: Path, random_state=42) -> dict`, `load_winning_model(model_dir: Path) -> tuple[str, object, float]`, `predict_confidence(model, signals: dict) -> float`.

- [ ] **Step 1: Write the failing tests**

`tests/test_model.py`:
```python
import numpy as np
import pandas as pd
import pytest

from it_security_agent import labeling, model


def _synthetic_dataset(n=60, seed=0):
    rng = np.random.default_rng(seed)
    rows = []
    for i in range(n):
        is_real = i % 2 == 0
        rows.append({
            "vendor_equals_package": int(is_real) if rng.random() > 0.2 else int(not is_real),
            "name_similarity": rng.uniform(0.7, 1.0) if is_real else rng.uniform(0.0, 0.5),
            "py_keyword_score": rng.integers(0, 5),
            "js_keyword_score": rng.integers(0, 5),
            "keyword_alignment": rng.integers(-3, 3),
            "ecosystem_pypi": 1,
            "osv_corroborated": int(is_real) if rng.random() > 0.3 else int(not is_real),
            "label_real_match": is_real,
        })
    return pd.DataFrame(rows)


def test_train_and_compare_returns_both_models_and_a_winner(tmp_path):
    df = _synthetic_dataset()
    result = model.train_and_compare(df, model_dir=tmp_path)
    assert set(result["results"].keys()) == {"logistic_regression", "random_forest"}
    assert result["winner"] in ("logistic_regression", "random_forest")
    assert 0.0 <= result["threshold"] <= 1.0


def test_train_and_compare_persists_model_file(tmp_path):
    df = _synthetic_dataset()
    model.train_and_compare(df, model_dir=tmp_path)
    saved_files = list(tmp_path.glob("*.joblib"))
    assert len(saved_files) == 1


def test_load_winning_model_round_trips(tmp_path):
    df = _synthetic_dataset()
    model.train_and_compare(df, model_dir=tmp_path)
    name, loaded_model, threshold = model.load_winning_model(model_dir=tmp_path)
    assert name in ("logistic_regression", "random_forest")
    assert hasattr(loaded_model, "predict_proba")


def test_registry_overlap_leakage_regression(tmp_path):
    # If registry_overlap leaked into FEATURES, a model trained where it perfectly
    # predicts the label would show near-1.0 accuracy. Assert FEATURES excludes it,
    # which is the actual guard - this test fails loudly if that guard is removed.
    assert "registry_overlap" not in labeling.FEATURES


def test_predict_confidence_returns_probability(tmp_path):
    df = _synthetic_dataset()
    model.train_and_compare(df, model_dir=tmp_path)
    _, loaded_model, _ = model.load_winning_model(model_dir=tmp_path)
    signals = {f: 0.5 for f in labeling.FEATURES}
    confidence = model.predict_confidence(loaded_model, signals)
    assert 0.0 <= confidence <= 1.0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_model.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

`it_security_agent/model.py`:
```python
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import confusion_matrix
from sklearn.model_selection import train_test_split

from it_security_agent.labeling import FEATURES

FN_WEIGHT, FP_WEIGHT = 10, 1


def _risk_score(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    fn, fp = cm[1][0], cm[0][1]
    return fn * FN_WEIGHT + fp * FP_WEIGHT


def _best_threshold(model, X_test, y_test):
    probs = model.predict_proba(X_test)[:, 1]
    best_threshold, best_risk = 0.5, None
    for threshold in np.linspace(0.05, 0.95, 19):
        y_pred = (probs >= threshold).astype(int)
        risk = _risk_score(y_test, y_pred)
        if best_risk is None or risk < best_risk:
            best_risk, best_threshold = risk, float(threshold)
    return best_threshold, best_risk


def train_and_compare(df: pd.DataFrame, model_dir: Path, random_state=42):
    model_dir = Path(model_dir)
    model_dir.mkdir(parents=True, exist_ok=True)
    X = df[FEATURES].astype(float)
    y = df["label_real_match"].astype(int)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=random_state, stratify=y)

    candidates = {
        "logistic_regression": LogisticRegression(max_iter=1000, class_weight="balanced"),
        "random_forest": RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=random_state),
    }
    results = {}
    for name, candidate in candidates.items():
        candidate.fit(X_train, y_train)
        threshold, risk = _best_threshold(candidate, X_test, y_test)
        results[name] = {"model": candidate, "threshold": threshold, "risk_score": risk}

    winner = min(results, key=lambda k: results[k]["risk_score"])
    winning_model, winning_threshold = results[winner]["model"], results[winner]["threshold"]

    for path in model_dir.glob("*.joblib"):
        path.unlink()
    joblib.dump(
        {"name": winner, "model": winning_model, "threshold": winning_threshold},
        model_dir / f"{winner}.joblib",
    )
    return {"results": results, "winner": winner, "threshold": winning_threshold}


def load_winning_model(model_dir: Path):
    model_dir = Path(model_dir)
    files = list(model_dir.glob("*.joblib"))
    if not files:
        raise FileNotFoundError(f"no trained model found in {model_dir} - run train_and_compare first")
    payload = joblib.load(files[0])
    return payload["name"], payload["model"], payload["threshold"]


def predict_confidence(model, candidate_signals: dict) -> float:
    row = pd.DataFrame([{f: candidate_signals.get(f, 0) for f in FEATURES}]).astype(float)
    return float(model.predict_proba(row)[0][1])
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_model.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add it_security_agent/model.py tests/test_model.py
git commit -m "feat: add model.py - offline LR/RandomForest training with persisted winner"
```

---

### Task 16: `explain.py` — SHAP explanations

**Files:**
- Create: `it_security_agent/explain.py`
- Test: `tests/test_explain.py`

**Interfaces:**
- Consumes: `labeling.FEATURES` (Task 14), fitted models from `model.py` (Task 15).
- Produces: `make_explainer(model_name: str, model, background: pd.DataFrame)`, `explain_match(explainer, row: pd.DataFrame) -> dict`.

- [ ] **Step 1: Write the failing tests**

`tests/test_explain.py`:
```python
import pandas as pd
import pytest
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier

from it_security_agent import explain, labeling

X = pd.DataFrame([{f: i % 2 for f in labeling.FEATURES} for i in range(20)])
y = pd.Series([i % 2 for i in range(20)])


def test_make_explainer_logistic_regression():
    lr = LogisticRegression().fit(X, y)
    explainer = explain.make_explainer("logistic_regression", lr, X)
    assert explainer is not None


def test_make_explainer_random_forest():
    rf = RandomForestClassifier(n_estimators=10).fit(X, y)
    explainer = explain.make_explainer("random_forest", rf, X)
    assert explainer is not None


def test_make_explainer_unknown_model_raises():
    with pytest.raises(ValueError):
        explain.make_explainer("unknown_model", object(), X)


def test_explain_match_returns_dict_keyed_by_feature():
    rf = RandomForestClassifier(n_estimators=10).fit(X, y)
    explainer = explain.make_explainer("random_forest", rf, X)
    row = X.iloc[[0]]
    result = explain.explain_match(explainer, row)
    assert set(result.keys()) == set(labeling.FEATURES)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_explain.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

`it_security_agent/explain.py`:
```python
import shap


def make_explainer(model_name: str, model, background):
    if model_name == "logistic_regression":
        return shap.LinearExplainer(model, background)
    if model_name == "random_forest":
        return shap.TreeExplainer(model)
    raise ValueError(f"no SHAP explainer wired up for {model_name}")


def explain_match(explainer, row) -> dict:
    shap_values = explainer.shap_values(row)
    if isinstance(shap_values, list):
        values = shap_values[1][0]
    elif getattr(shap_values, "ndim", 1) == 3:
        values = shap_values[0, :, 1]
    else:
        values = shap_values[0]
    return dict(zip(row.columns, [float(v) for v in values]))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_explain.py -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add it_security_agent/explain.py tests/test_explain.py
git commit -m "feat: add explain.py - SHAP wrappers for both models"
```

---

### Task 17: `agent.py` — orchestrator + triage policy

**Files:**
- Create: `it_security_agent/agent.py`
- Test: `tests/test_agent.py`

**Interfaces:**
- Consumes: `matching.find_candidates` (Task 12), `osv.query` (Task 10), `kev.is_kev` (Task 13), `model.predict_confidence` (Task 15), `explain.explain_match` (Task 16), `schema.Component` (Task 2).
- Produces: `Finding` dataclass, `ScanResult` dataclass (`confirmed`, `escalated`, `review_queue`, `rejected`, all `list[Finding]`), `scan(components, winning_model_name, winning_model, threshold, explainer, conn=None) -> ScanResult`.

- [ ] **Step 1: Write the failing tests**

`tests/test_agent.py`:
```python
from unittest.mock import MagicMock, patch

from it_security_agent import agent
from it_security_agent.normalize import VendorCandidate
from it_security_agent.schema import Component


def _match(cve="CVE-2024-0001", vendor_candidate=None):
    return {"cve": cve, "severity": "HIGH", "cvss_score": 7.5, "vendor": "vendor", "vendor_candidate": vendor_candidate}


def _run_scan(component, matches, rejected, osv_vulns, kev_entry, confidence):
    with patch("it_security_agent.matching.find_candidates", return_value=(matches, rejected)), \
         patch("it_security_agent.osv.query", return_value=osv_vulns), \
         patch("it_security_agent.kev.is_kev", return_value=kev_entry), \
         patch("it_security_agent.model.predict_confidence", return_value=confidence), \
         patch("it_security_agent.explain.explain_match", return_value={"name_similarity": 0.1}):
        return agent.scan([component], "random_forest", MagicMock(), 0.7, MagicMock())


def test_high_confidence_confirms_even_when_osv_disagrees():
    # High confidence alone is enough to confirm - but corroboration is still
    # computed and recorded (for the OSV agreement-rate report), not skipped.
    component = Component(name="django", version="2.2.0", ecosystem="PyPI", source="test")
    candidate = VendorCandidate(vendor="djangoproject", product="django", signals={})
    result = _run_scan(component, [_match(vendor_candidate=candidate)], [], osv_vulns=[], kev_entry=None, confidence=0.9)
    assert len(result.confirmed) == 1
    assert result.confirmed[0].corroboration == "osv_disagrees"


def test_high_confidence_non_osv_ecosystem_is_not_checked():
    component = Component(name="openssl", version="3.0.2", ecosystem="Debian", source="test")
    candidate = VendorCandidate(vendor="openssl", product="openssl", signals={})
    result = _run_scan(component, [_match(vendor_candidate=candidate)], [], osv_vulns=[], kev_entry=None, confidence=0.9)
    assert len(result.confirmed) == 1
    assert result.confirmed[0].corroboration == "not_checked"


def test_low_confidence_osv_agrees_confirms():
    component = Component(name="lodash", version="4.17.15", ecosystem="npm", source="test")
    candidate = VendorCandidate(vendor="lodash", product="lodash", signals={})
    result = _run_scan(component, [_match(vendor_candidate=candidate)], [], osv_vulns=[{"id": "GHSA-x"}], kev_entry=None, confidence=0.3)
    assert len(result.confirmed) == 1
    assert result.confirmed[0].corroboration == "osv_agrees"


def test_low_confidence_osv_disagrees_goes_to_review_queue():
    component = Component(name="lodash", version="4.17.15", ecosystem="npm", source="test")
    candidate = VendorCandidate(vendor="lodash", product="lodash", signals={})
    result = _run_scan(component, [_match(vendor_candidate=candidate)], [], osv_vulns=[], kev_entry=None, confidence=0.3)
    assert len(result.review_queue) == 1
    assert result.review_queue[0].corroboration == "osv_disagrees"
    assert result.review_queue[0].explanation is not None


def test_low_confidence_not_checked_goes_to_review_queue():
    component = Component(name="openssl", version="3.0.2", ecosystem="Debian", source="test")
    candidate = VendorCandidate(vendor="openssl", product="openssl", signals={})
    result = _run_scan(component, [_match(vendor_candidate=candidate)], [], osv_vulns=[], kev_entry=None, confidence=0.3)
    assert len(result.review_queue) == 1
    assert result.review_queue[0].corroboration == "not_checked"


def test_kev_hit_escalates_instead_of_confirms():
    component = Component(name="django", version="2.2.0", ecosystem="PyPI", source="test")
    candidate = VendorCandidate(vendor="djangoproject", product="django", signals={})
    result = _run_scan(component, [_match(vendor_candidate=candidate)], [], osv_vulns=[], kev_entry={"dueDate": "2024-01-01"}, confidence=0.9)
    assert result.confirmed == []
    assert len(result.escalated) == 1
    assert result.escalated[0].kev_hit is True


def test_rejected_findings_are_kept_not_dropped():
    component = Component(name="django", version="2.2.0", ecosystem="PyPI", source="test")
    result = _run_scan(component, [], ["CVE-2024-0002"], osv_vulns=[], kev_entry=None, confidence=0.9)
    assert len(result.rejected) == 1
    assert result.rejected[0].cve == "CVE-2024-0002"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_agent.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

`it_security_agent/agent.py`:
```python
from dataclasses import dataclass, field

from it_security_agent import explain, kev, matching, model, osv

OSV_ECOSYSTEMS = {"PyPI", "npm"}


@dataclass
class Finding:
    component: object
    cve: str
    severity: str
    cvss_score: float
    confidence: float | None = None
    corroboration: str = "not_checked"
    explanation: dict | None = None
    kev_hit: bool = False
    note: str = ""


@dataclass
class ScanResult:
    confirmed: list = field(default_factory=list)
    escalated: list = field(default_factory=list)
    review_queue: list = field(default_factory=list)
    rejected: list = field(default_factory=list)


def _corroboration(component, cve_id, conn):
    # Loose match by design: OSV doesn't always populate CVE aliases cleanly, so
    # requiring an exact CVE-ID match here would systematically undercount real
    # agreement. "OSV found anything for this exact (ecosystem, name, version)"
    # is the practical bar - independent evidence a vulnerability exists here at all.
    if component.ecosystem not in OSV_ECOSYSTEMS:
        return "not_checked"
    vulns = osv.query(component.ecosystem, component.name, component.version, conn=conn)
    return "osv_agrees" if vulns else "osv_disagrees"


def triage_component(component, winning_model_name, winning_model, threshold, explainer, conn=None):
    result = ScanResult()
    matches, rejected_ids = matching.find_candidates(component, conn=conn)

    for cve_id in rejected_ids:
        result.rejected.append(Finding(component=component, cve=cve_id, severity="UNKNOWN", cvss_score=None))

    for finding_data in matches:
        candidate = finding_data.get("vendor_candidate")
        kev_entry = kev.is_kev(finding_data["cve"], conn=conn)

        if candidate is None:
            result.rejected.append(Finding(
                component=component, cve=finding_data["cve"], severity=finding_data["severity"],
                cvss_score=finding_data["cvss_score"],
            ))
            continue

        confidence = model.predict_confidence(winning_model, candidate.signals)
        # Always computed, for every PyPI/npm finding, regardless of confidence -
        # report.py's OSV agreement rate (the evaluation-oracle metric) aggregates
        # over confirmed findings, so a corroboration value that's only checked
        # sometimes would silently corrupt that statistic.
        corroboration = _corroboration(component, finding_data["cve"], conn)
        f = Finding(
            component=component, cve=finding_data["cve"], severity=finding_data["severity"],
            cvss_score=finding_data["cvss_score"], confidence=confidence, kev_hit=bool(kev_entry),
            corroboration=corroboration,
        )

        if confidence >= threshold or corroboration == "osv_agrees":
            (result.escalated if kev_entry else result.confirmed).append(f)
        else:
            f.explanation = explain.explain_match(explainer, __import__("pandas").DataFrame([candidate.signals]))
            f.note = "not corroborated by OSV" if corroboration == "osv_disagrees" else "OSV not applicable to this ecosystem"
            result.review_queue.append(f)

    return result


def scan(components, winning_model_name, winning_model, threshold, explainer, conn=None) -> ScanResult:
    total = ScanResult()
    for component in components:
        partial = triage_component(component, winning_model_name, winning_model, threshold, explainer, conn=conn)
        total.confirmed += partial.confirmed
        total.escalated += partial.escalated
        total.review_queue += partial.review_queue
        total.rejected += partial.rejected
    return total
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_agent.py -v`
Expected: PASS (7 tests)

- [ ] **Step 5: Commit**

```bash
git add it_security_agent/agent.py tests/test_agent.py
git commit -m "feat: add agent.py - orchestrator and triage policy"
```

---

### Task 18: `report.py` — JSON/HTML report output

**Files:**
- Create: `it_security_agent/report.py`
- Test: `tests/test_report.py`

**Interfaces:**
- Consumes: `agent.ScanResult`, `agent.Finding` (Task 17).
- Produces: `to_dict(result) -> dict`, `osv_agreement_summary(result) -> dict`, `to_json(result, out_path) -> dict`, `to_html(result, out_path) -> str`, `write_report(result, out_dir) -> None`.

- [ ] **Step 1: Write the failing tests**

`tests/test_report.py`:
```python
import json
from pathlib import Path

from it_security_agent import report
from it_security_agent.agent import Finding, ScanResult
from it_security_agent.schema import Component


def _finding(cve="CVE-2024-0001"):
    component = Component(name="django", version="2.2.0", ecosystem="PyPI", source="test")
    return Finding(component=component, cve=cve, severity="HIGH", cvss_score=7.5)



def test_to_dict_has_all_four_buckets_plus_osv_summary():
    result = ScanResult(confirmed=[_finding()], rejected=[_finding("CVE-2024-0002")])
    payload = report.to_dict(result)
    assert set(payload.keys()) == {"confirmed", "escalated", "review_queue", "rejected", "osv_agreement_summary"}
    assert len(payload["confirmed"]) == 1
    assert len(payload["rejected"]) == 1


def test_osv_agreement_summary_counts_pypi_npm_confirmed_only():
    pypi_component = Component(name="django", version="2.2.0", ecosystem="PyPI", source="test")
    debian_component = Component(name="openssl", version="3.0.2", ecosystem="Debian", source="test")
    agreeing = Finding(component=pypi_component, cve="CVE-2024-0001", severity="HIGH", cvss_score=7.5, corroboration="osv_agrees")
    not_checked = Finding(component=debian_component, cve="CVE-2024-0002", severity="HIGH", cvss_score=7.5, corroboration="not_checked")
    disagreeing = Finding(component=pypi_component, cve="CVE-2024-0003", severity="HIGH", cvss_score=7.5, corroboration="osv_disagrees")
    result = ScanResult(confirmed=[agreeing, not_checked, disagreeing])
    summary = report.osv_agreement_summary(result)
    assert summary["eligible"] == 2  # only the two PyPI findings count; Debian is excluded
    assert summary["agreed"] == 1
    assert summary["agreement_rate"] == 0.5


def test_to_json_writes_file(tmp_path):
    result = ScanResult(confirmed=[_finding()])
    out_path = tmp_path / "findings.json"
    report.to_json(result, out_path)
    data = json.loads(out_path.read_text())
    assert data["confirmed"][0]["cve"] == "CVE-2024-0001"


def test_to_html_includes_rejected_section_not_omitted(tmp_path):
    result = ScanResult(rejected=[_finding("CVE-2024-0003")])
    out_path = tmp_path / "report.html"
    html = report.to_html(result, out_path)
    assert "CVE-2024-0003" in html
    assert "Rejected" in html


def test_write_report_creates_both_files(tmp_path):
    result = ScanResult(confirmed=[_finding()])
    report.write_report(result, tmp_path)
    assert (tmp_path / "findings.json").exists()
    assert (tmp_path / "report.html").exists()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_report.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write the implementation**

`it_security_agent/report.py`:
```python
import json
from pathlib import Path

import pandas as pd


def _finding_to_dict(f):
    return {
        "package": f.component.name, "version": f.component.version, "ecosystem": f.component.ecosystem,
        "cve": f.cve, "severity": f.severity, "cvss_score": f.cvss_score,
        "confidence": f.confidence, "corroboration": f.corroboration, "kev_hit": f.kev_hit,
        "note": f.note, "explanation": f.explanation,
    }


OSV_ECOSYSTEMS = {"PyPI", "npm"}


def osv_agreement_summary(result) -> dict:
    eligible = [f for f in result.confirmed if f.component.ecosystem in OSV_ECOSYSTEMS]
    agreed = [f for f in eligible if f.corroboration == "osv_agrees"]
    rate = (len(agreed) / len(eligible)) if eligible else None
    return {"eligible": len(eligible), "agreed": len(agreed), "agreement_rate": rate}


def to_dict(result) -> dict:
    return {
        "confirmed": [_finding_to_dict(f) for f in result.confirmed],
        "escalated": [_finding_to_dict(f) for f in result.escalated],
        "review_queue": [_finding_to_dict(f) for f in result.review_queue],
        "rejected": [_finding_to_dict(f) for f in result.rejected],
        "osv_agreement_summary": osv_agreement_summary(result),
    }


def to_json(result, out_path: Path) -> dict:
    payload = to_dict(result)
    Path(out_path).write_text(json.dumps(payload, indent=2))
    return payload


def _table_html(findings, title):
    if not findings:
        return f"<h3>{title}</h3><p>None</p>"
    df = pd.DataFrame([_finding_to_dict(f) for f in findings])
    return f"<h3>{title}</h3>" + df.to_html(index=False)


def to_html(result, out_path: Path) -> str:
    summary = osv_agreement_summary(result)
    rate_text = f"{summary['agreement_rate']:.0%}" if summary["agreement_rate"] is not None else "n/a"
    sections = [
        f"<h3>OSV agreement (PyPI/npm confirmed findings)</h3>"
        f"<p>{summary['agreed']}/{summary['eligible']} corroborated ({rate_text})</p>",
        _table_html(result.escalated, "Escalated (KEV-confirmed exploitation)"),
        _table_html(result.confirmed, "Confirmed findings"),
        _table_html(result.review_queue, "Human review queue"),
        "<details><summary>Rejected candidates</summary>" + _table_html(result.rejected, "Rejected") + "</details>",
    ]
    html = "<html><body>" + "\n".join(sections) + "</body></html>"
    Path(out_path).write_text(html)
    return html


def write_report(result, out_dir: Path) -> None:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    to_json(result, out_dir / "findings.json")
    to_html(result, out_dir / "report.html")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `uv run pytest tests/test_report.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add it_security_agent/report.py tests/test_report.py
git commit -m "feat: add report.py - JSON/HTML report output"
```

---

### Task 19: Notebook wiring + full coverage verification

**Files:**
- Create: `notebooks/week3_agent.ipynb`
- Modify: none (verification task)

**Interfaces:**
- Consumes: all modules from Tasks 2-18.
- Produces: the Week 3 presentation notebook; a verified `pytest --cov` run at ≥80%.

- [ ] **Step 1: Run the full test suite with coverage**

Run: `uv run pytest --cov=it_security_agent --cov-report=term-missing -v`
Expected: all tests PASS; note the coverage percentage and any modules under 80%.

- [ ] **Step 2: Backfill tests for any module under 80% coverage**

For each module reported under 80% in Step 1's `--cov-report=term-missing` output, add targeted tests for the specific uncovered line ranges shown (not a rewrite — add the missing case to that module's existing test file, following the same mocking pattern already used in that file).

- [ ] **Step 3: Re-run coverage to confirm ≥80% overall**

Run: `uv run pytest --cov=it_security_agent --cov-report=term-missing`
Expected: `TOTAL` line shows ≥80%.

- [ ] **Step 4: Build the presentation notebook**

Create `notebooks/week3_agent.ipynb` with markdown + code cells. Open with a Weekly Status markdown cell (what we did / challenges / next steps, same format as `week1_analysis.ipynb`/`week2_dependency_scan.ipynb`), then code cells implementing this sequence (translate each block into its own cell, with markdown explaining it in between, consistent with the existing notebooks' style):

```python
from pathlib import Path
from it_security_agent import (
    repo_scan, sbom, nvd_cache, kev, labeling, model, explain, agent, report,
)

# 1. Build the component list from all three input paths
components = repo_scan.parse_uv_lock(Path("..") / "uv.lock")
# components += sbom.parse_cyclonedx(json.loads(Path("path/to/sample.json").read_text()))
# components += image_scan.scan_image("python:3.11-slim")  # if Docker/Syft available

# 2. Sync the local cache once, up front - no live per-component NVD calls after this
conn = nvd_cache.get_connection()
nvd_cache.sync_full(conn=conn)
kev.refresh(conn=conn)

# 3. Train and compare both models offline, persist the winner
dataset = labeling.build_dataset(components, conn=conn)
training_result = model.train_and_compare(dataset, model_dir=Path("..") / "models")
print(training_result["winner"], training_result["threshold"])
for name, r in training_result["results"].items():
    print(name, "risk score:", r["risk_score"])

# 4. XAI: SHAP summary plot for the winning model
import shap
winner_name, winning_model, threshold = model.load_winning_model(model_dir=Path("..") / "models")
background = dataset[labeling.FEATURES].astype(float)
explainer = explain.make_explainer(winner_name, winning_model, background)
shap_values = explainer.shap_values(background)
shap.summary_plot(shap_values, background)

# 5. Run the agent's triage policy over every component
result = agent.scan(components, winner_name, winning_model, threshold, explainer, conn=conn)
print("confirmed:", len(result.confirmed), "escalated:", len(result.escalated),
      "review_queue:", len(result.review_queue), "rejected:", len(result.rejected))
print("OSV agreement:", report.osv_agreement_summary(result))

# 6. Write the report
report.write_report(result, Path("..") / "reports" / "week3")
```

Finish with a markdown cell pasting the actual `pytest --cov` summary table from Step 3 — a stated, verified result, not a claim.

- [ ] **Step 5: Execute the notebook top-to-bottom**

Run: `uv run jupyter nbconvert --to notebook --execute --inplace notebooks/week3_agent.ipynb`
Expected: exits 0, no cell errors.

- [ ] **Step 6: Commit**

```bash
git add notebooks/week3_agent.ipynb
git commit -m "docs: add Week 3 presentation notebook wiring the full agent pipeline"
```

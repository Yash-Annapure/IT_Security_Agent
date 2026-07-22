"""End-to-end proof that a scan runs entirely off the server's local cache.

The deployment this project targets: the NVD cache lives on the datalab server next
to the MCP server, the user's machine runs one `curl`, and the only thing that lands
in their repo is the report. Nothing in a scan may depend on reaching NVD.

That was not true until recently. resolve_vendor called NVD's CPE dictionary API once
per package name - rate-limited to one request a second, behind a 90s budget - so a
257-package `package-lock.json` spent minutes on the network and then had its streamed
response dropped by the proxy mid-scan. `uv.lock` scans looked fine only because those
names had been cached by earlier runs. These tests pin the fix: with the caches warm,
every supported lockfile format scans with the network completely unavailable.
"""
import json
from unittest.mock import patch

import pytest

from it_security_agent import mcp_server, nvd_cache

UV_LOCK = (
    '[[package]]\nname = "django"\nversion = "1.0.0"\n'
    'source = { registry = "https://pypi.org/simple" }\n'
)
REQUIREMENTS_TXT = "django==1.0.0\n"
PACKAGE_LOCK = json.dumps({
    "name": "app", "lockfileVersion": 3,
    "packages": {"node_modules/django": {"version": "1.0.0"}},
})

LOCKFILES = {
    "uv.lock": UV_LOCK,
    "requirements.txt": REQUIREMENTS_TXT,
    "package-lock.json": PACKAGE_LOCK,
}


def _seeded_cache():
    """An in-memory cache holding one CVE plus warm registry/OSV entries.

    Seeding registry_cache and osv_cache is not a convenience: those two are the only
    other things a scan reads over the network, and warming them is what `warm_cache.py`
    and previous scans do on the real server.
    """
    conn = nvd_cache.get_connection(":memory:")
    cve = {
        "cve": {
            "id": "CVE-2024-0001",
            "descriptions": [{"lang": "en", "value": "A test vulnerability in django"}],
            "references": [{"url": "https://github.com/django/django"}],
            "metrics": {"cvssMetricV31": [{"baseSeverity": "HIGH", "cvssData": {"baseScore": 7.5}}]},
            "weaknesses": [],
            "configurations": [{"nodes": [{"cpeMatch": [
                {"criteria": "cpe:2.3:a:djangoproject:django:1.0.0:*:*:*:*:*:*:*", "vulnerable": True}
            ]}]}],
        }
    }
    conn.execute("INSERT INTO cves (id, published, last_modified, raw_json) VALUES (?,?,?,?)",
                 ("CVE-2024-0001", "2024-01-01", "2024-01-01", json.dumps(cve)))
    conn.execute("INSERT INTO cve_products (product, cve_id) VALUES (?,?)",
                 ("django", "CVE-2024-0001"))
    for ecosystem in ("PyPI", "npm"):
        conn.execute(
            "CREATE TABLE IF NOT EXISTS registry_cache (ecosystem TEXT, name TEXT, raw_json TEXT, "
            "fetched_at TEXT, PRIMARY KEY (ecosystem, name))")
        conn.execute(
            "INSERT OR REPLACE INTO registry_cache (ecosystem, name, raw_json, fetched_at) "
            "VALUES (?,?,?,datetime('now'))",
            (ecosystem, "django", json.dumps({"urls": ["https://github.com/django/django"]})))
        conn.execute(
            "CREATE TABLE IF NOT EXISTS osv_cache (ecosystem TEXT, name TEXT, version TEXT, "
            "raw_json TEXT, PRIMARY KEY (ecosystem, name, version))")
        conn.execute(
            "INSERT OR REPLACE INTO osv_cache (ecosystem, name, version, raw_json) VALUES (?,?,?,?)",
            (ecosystem, "django", "1.0.0", json.dumps([])))
    conn.commit()
    return conn


@pytest.fixture
def no_network():
    """Make any outbound HTTP call a hard failure, so a regression can't pass quietly.

    Patched at the transport layer on purpose. Patching `requests.get` does NOT work
    here: several call sites take it as a default argument (`def nvd_get(..., get_fn=
    requests.get)`), which binds the original function at import time and ignores any
    later patch of the module attribute. An earlier version of this fixture did exactly
    that and the "offline" tests spent 90 seconds talking to NVD for real. Every
    requests call, however it was bound, ends up in HTTPAdapter.send.
    """
    def blocked(self, request, *a, **k):
        raise AssertionError(f"scan attempted a network call: {request.method} {request.url}")

    with patch("requests.adapters.HTTPAdapter.send", blocked):
        yield


@pytest.fixture
def complete_cache():
    """Report the seeded cache as covering all of NVD, as the datalab server's does.

    A cache the server considers thin triggers a top-up sync at scan time; the real
    deployment holds ~100% of the catalog, so that branch never runs there and must
    not run here either.
    """
    with patch.object(mcp_server, "NVD_CATALOG_SIZE", 1):
        yield


@pytest.mark.parametrize("kind", sorted(LOCKFILES))
def test_scan_runs_fully_offline_for_every_lockfile_format(kind, no_network, complete_cache):
    conn = _seeded_cache()
    with patch.object(mcp_server, "get_connection", return_value=conn):
        report = mcp_server._run_scan(LOCKFILES[kind], kind)
    assert "Vulnerability scan result" in report
    assert "## Pipeline" in report  # the report is complete, not a truncated stream


@pytest.mark.parametrize("kind", sorted(LOCKFILES))
def test_scan_finds_the_cached_cve_for_every_lockfile_format(kind, no_network, complete_cache):
    # Offline isn't enough on its own - an offline scan that finds nothing would pass
    # the test above. Each format must resolve the vendor out of the cached CVE and
    # actually report the match.
    conn = _seeded_cache()
    with patch.object(mcp_server, "get_connection", return_value=conn):
        report = mcp_server._run_scan(LOCKFILES[kind], kind)
    assert "CVE-2024-0001" in report


def test_resolve_vendor_reads_the_vendor_out_of_the_cached_cve(no_network):
    from it_security_agent import normalize

    conn = _seeded_cache()
    candidates = normalize.resolve_vendor("django", "PyPI", conn=conn)
    assert [c.vendor for c in candidates] == ["djangoproject"]
    assert candidates[0].signals["registry_overlap"] is True

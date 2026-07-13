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

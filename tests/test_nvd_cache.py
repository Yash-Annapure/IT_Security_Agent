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


def test_sync_stores_pages_as_they_arrive_and_reports_progress(tmp_path):
    # The real client streams via on_page; each page must be written immediately (so a
    # 370k-CVE catalog never sits in RAM) and reported (so the CLI doesn't look hung).
    conn = nvd_cache.get_connection(tmp_path / "t.db")
    seen = []

    def streaming_fetch(params, on_page=None):
        on_page([_cve("CVE-2024-0001")], 1, 2)
        on_page([_cve("CVE-2024-0002")], 2, 2)
        return [], 2  # streaming mode returns nothing to accumulate

    count = nvd_cache.sync_full(conn=conn, fetch_fn=streaming_fetch, on_progress=lambda f, t: seen.append((f, t)))
    assert count == 2
    assert seen == [(1, 2), (2, 2)]
    stored = conn.execute("SELECT id FROM cves ORDER BY id").fetchall()
    assert [row[0] for row in stored] == ["CVE-2024-0001", "CVE-2024-0002"]


def test_sync_still_stores_results_from_a_client_that_ignores_on_page(tmp_path):
    # Back-compat: a fetch_fn that returns everything at once (older client, or a test
    # double) must not have its results silently dropped.
    conn = nvd_cache.get_connection(tmp_path / "t.db")
    legacy_fetch = MagicMock(return_value=([_cve("CVE-2024-0003")], 1))
    assert nvd_cache.sync_full(conn=conn, fetch_fn=legacy_fetch) == 1
    assert conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0] == 1

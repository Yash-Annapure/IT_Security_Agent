from unittest.mock import MagicMock, patch

import pytest

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


def test_query_matches_the_product_field_not_the_vendor_field():
    # The index replaced a `raw_json LIKE '%:name:%'` scan, which also matched the vendor
    # field and description prose. matching.find_candidates only ever keeps a CVE whose
    # CPE *product* equals the name, so narrowing to the product column must not change
    # results - but a CVE whose vendor happens to equal another package's name must not
    # come back for that name.
    conn = nvd_cache.get_connection(":memory:")
    nvd_cache.sync_full(conn=conn, fetch_fn=MagicMock(
        return_value=([_cve("CVE-2024-0001", product="django", vendor="acme")], 1)))
    assert [r["cve"]["id"] for r in nvd_cache.query_by_product_name("django", conn=conn)] == ["CVE-2024-0001"]
    assert nvd_cache.query_by_product_name("acme", conn=conn) == []


def test_query_by_product_name_is_case_insensitive():
    conn = nvd_cache.get_connection(":memory:")
    nvd_cache.sync_full(conn=conn, fetch_fn=MagicMock(
        return_value=([_cve("CVE-2024-0001", product="Django")], 1)))
    assert len(nvd_cache.query_by_product_name("django", conn=conn)) == 1


def test_restoring_a_cve_drops_products_it_no_longer_references():
    # NVD re-scores records and rewrites their configurations. If the index kept the old
    # product rows, a package would keep matching a CVE that no longer names it.
    conn = nvd_cache.get_connection(":memory:")
    nvd_cache._store_vulns(conn, [_cve("CVE-2024-0001", product="django")])
    nvd_cache._store_vulns(conn, [_cve("CVE-2024-0001", product="flask")])
    assert nvd_cache.query_by_product_name("django", conn=conn) == []
    assert len(nvd_cache.query_by_product_name("flask", conn=conn)) == 1


def test_ensure_product_index_backfills_a_cache_built_before_the_index(tmp_path):
    import json as _json
    import sqlite3

    db = tmp_path / "legacy.db"
    legacy = sqlite3.connect(db)
    legacy.execute("CREATE TABLE cves (id TEXT PRIMARY KEY, published TEXT, last_modified TEXT, raw_json TEXT)")
    legacy.execute("INSERT INTO cves VALUES (?, ?, ?, ?)",
                   ("CVE-2024-0001", "p", "m", _json.dumps(_cve("CVE-2024-0001", product="django"))))
    legacy.commit()
    legacy.close()

    conn = nvd_cache.get_connection(db)  # opening a legacy cache must backfill it
    assert len(nvd_cache.query_by_product_name("django", conn=conn)) == 1
    # ...and be a no-op the second time, rather than rebuilding on every open.
    assert nvd_cache.ensure_product_index(conn) == 0


def test_interrupted_backfill_is_not_recorded_as_complete(tmp_path):
    # The version marker is written only after the whole backfill commits. If a partial
    # index could be marked complete, later scans would silently under-report.
    import json as _json
    import sqlite3

    db = tmp_path / "legacy.db"
    legacy = sqlite3.connect(db)
    legacy.execute("CREATE TABLE cves (id TEXT PRIMARY KEY, published TEXT, last_modified TEXT, raw_json TEXT)")
    legacy.executemany("INSERT INTO cves VALUES (?, ?, ?, ?)", [
        (f"CVE-2024-{i:04d}", "p", "m", _json.dumps(_cve(f"CVE-2024-{i:04d}", product=f"pkg{i}")))
        for i in range(10)
    ])
    legacy.commit()
    legacy.close()

    conn = sqlite3.connect(db)
    conn.execute("""CREATE TABLE cve_products (product TEXT NOT NULL, cve_id TEXT NOT NULL,
                    PRIMARY KEY (product, cve_id)) WITHOUT ROWID""")
    conn.execute("CREATE TABLE cache_meta (key TEXT PRIMARY KEY, value TEXT)")
    conn.commit()

    boom = RuntimeError("interrupted mid-backfill")
    with patch.object(nvd_cache, "_product_rows", side_effect=boom):
        with pytest.raises(RuntimeError):
            nvd_cache.ensure_product_index(conn, batch_size=2)
    conn.rollback()  # as a crashed process would, by releasing the connection
    assert conn.execute("SELECT COUNT(*) FROM cache_meta").fetchone()[0] == 0

    # A later attempt rebuilds from scratch and lands complete.
    assert nvd_cache.ensure_product_index(conn) == 10
    assert len(nvd_cache.query_by_product_name("pkg7", conn=conn)) == 1


def test_sync_still_stores_results_from_a_client_that_ignores_on_page(tmp_path):
    # Back-compat: a fetch_fn that returns everything at once (older client, or a test
    # double) must not have its results silently dropped.
    conn = nvd_cache.get_connection(tmp_path / "t.db")
    legacy_fetch = MagicMock(return_value=([_cve("CVE-2024-0003")], 1))
    assert nvd_cache.sync_full(conn=conn, fetch_fn=legacy_fetch) == 1
    assert conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0] == 1

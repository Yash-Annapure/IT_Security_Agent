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

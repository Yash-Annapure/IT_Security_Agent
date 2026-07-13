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

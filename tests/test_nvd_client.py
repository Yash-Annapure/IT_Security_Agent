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

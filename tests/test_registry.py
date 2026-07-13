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
    assert "git+https://github.com/lodash/lodash.git" in result["urls"]


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

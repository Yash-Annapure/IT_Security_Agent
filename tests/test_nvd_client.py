import threading
import time
from unittest.mock import MagicMock

import pytest
import requests

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


def test_fetch_all_pages_streams_to_on_page_without_accumulating():
    # Streaming mode exists so a full-catalog sync (~370k CVEs) never has to hold the
    # whole result set in memory before any of it is written.
    page1 = _response(200, {"totalResults": 3, "vulnerabilities": [1, 2]})
    page2 = _response(200, {"totalResults": 3, "vulnerabilities": [3]})
    get_fn = MagicMock(side_effect=[page1, page2])
    seen = []
    vulns, total = nvd_client.fetch_all_pages(
        {}, page_size=2, get_fn=get_fn, sleep_fn=MagicMock(), on_page=lambda v, f, t: seen.append((v, f, t))
    )
    assert vulns == []  # nothing accumulated - the callback owns the data
    assert total == 3
    assert seen == [([1, 2], 2, 3), ([3], 3, 3)]  # per-page data plus running progress


def _paged_get_fn(total, page_size, delay=0.0):
    """A get_fn that serves `total` items in pages, keyed off the requested startIndex.

    Indexed rather than side_effect-ordered because the parallel fetcher issues requests
    concurrently: a fixed sequence of responses would assume an ordering it doesn't have.
    """
    lock = threading.Lock()
    calls = []

    def get_fn(url, params=None, headers=None, timeout=None):
        with lock:
            calls.append(params["startIndex"])
        if delay:
            time.sleep(delay)
        start = params["startIndex"]
        items = list(range(start, min(start + page_size, total)))
        return _response(200, {"totalResults": total, "vulnerabilities": items})

    return get_fn, calls


def test_fetch_all_pages_parallel_fetches_every_page_exactly_once():
    get_fn, calls = _paged_get_fn(total=7, page_size=2)
    vulns, total = nvd_client.fetch_all_pages_parallel(
        {}, page_size=2, workers=3, get_fn=get_fn, sleep_fn=MagicMock()
    )
    assert total == 7
    assert sorted(vulns) == list(range(7))  # sorted: pages land out of order by design
    assert sorted(calls) == [0, 2, 4, 6]


def test_fetch_all_pages_parallel_streams_progress_monotonically():
    get_fn, _ = _paged_get_fn(total=7, page_size=2, delay=0.01)
    seen = []
    vulns, total = nvd_client.fetch_all_pages_parallel(
        {}, page_size=2, workers=3, get_fn=get_fn, sleep_fn=MagicMock(),
        on_page=lambda v, f, t: seen.append((f, t)),
    )
    assert vulns == []  # streaming mode still accumulates nothing
    fetched = [f for f, _ in seen]
    # Pages are fetched concurrently and land out of order (see the test above), so the
    # *intermediate* running totals depend on which worker finishes first - asserting an
    # exact sequence here made this test fail roughly half the time. What the counter
    # actually promises is that it only ever moves forward, never overshoots the total,
    # and ends exactly on it.
    assert len(fetched) == 4  # one callback per page: 2 + 2 + 2 + 1
    assert fetched == sorted(fetched)
    assert fetched[-1] == 7
    assert all(0 < f <= 7 for f in fetched)
    assert {t for _, t in seen} == {7}


def test_fetch_all_pages_parallel_propagates_worker_failure():
    # A page that fails every retry has to surface, not leave a silently short cache.
    def get_fn(url, params=None, headers=None, timeout=None):
        if params["startIndex"] == 0:
            return _response(200, {"totalResults": 6, "vulnerabilities": [0, 1]})
        raise requests.exceptions.ConnectionError("boom")

    with pytest.raises(requests.exceptions.ConnectionError):
        nvd_client.fetch_all_pages_parallel(
            {}, page_size=2, workers=2, get_fn=get_fn, sleep_fn=MagicMock()
        )


def test_rate_limiter_blocks_once_window_is_full():
    limiter = nvd_client.RateLimiter(limit=2, window=0.2)
    started = time.monotonic()
    for _ in range(3):  # third acquisition can't proceed until the window rolls
        limiter.acquire()
    assert time.monotonic() - started >= 0.2

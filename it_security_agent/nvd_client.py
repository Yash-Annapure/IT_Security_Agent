import collections
import os
import random
import threading
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait

import requests
from dotenv import load_dotenv

load_dotenv()

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY")
REQUEST_SPACING_SECONDS = 1 if NVD_API_KEY else 6
# NVD's published ceiling is 50 requests per rolling 30s with an API key, 5 without.
# Sit a few under it: the window is enforced on their side, and a burst that trips it
# costs a 403 plus backoff - slower than simply having waited.
RATE_LIMIT_REQUESTS = 40 if NVD_API_KEY else 4
RATE_LIMIT_WINDOW_SECONDS = 30
# Deliberately far below what the rate limit alone would permit. Sequential paging
# measures at ~1 request per 17s (~2 per 30s) against a budget of 50, so even a handful
# of workers is most of the available speedup, and NVD gets flaky well before its
# documented ceiling. Raise via warm_cache.py --workers if you want to push it.
DEFAULT_WORKERS = 4 if NVD_API_KEY else 2


class RateLimiter:
    """Thread-safe rolling-window limiter: at most `limit` acquisitions per `window`.

    The per-page `sleep` in fetch_all_pages can only pace a single caller. Once several
    workers share NVD's budget the spacing has to be enforced against one shared clock,
    or each thread independently believes it is within limits while the total is not.
    """

    def __init__(self, limit=RATE_LIMIT_REQUESTS, window=RATE_LIMIT_WINDOW_SECONDS):
        self.limit = limit
        self.window = window
        self._times = collections.deque()
        self._lock = threading.Lock()

    def acquire(self):
        while True:
            with self._lock:
                now = time.monotonic()
                while self._times and now - self._times[0] >= self.window:
                    self._times.popleft()
                if len(self._times) < self.limit:
                    self._times.append(now)
                    return
                wait_for = self.window - (now - self._times[0])
            time.sleep(wait_for)  # outside the lock, so other threads can still drain


def _backoff_seconds(attempt):
    """Exponential backoff with jitter, capped at a minute.

    A flat retry delay was fine for one sequential caller. With several workers sharing
    the budget a 403 tends to hit all of them at once, and retrying in lockstep just
    recreates the burst that caused it - the jitter is what breaks up the convoy.
    """
    return min(REQUEST_SPACING_SECONDS * 2 * (2 ** attempt), 60) + random.uniform(0, 1)


def nvd_get(params, retries=5, get_fn=requests.get, sleep_fn=time.sleep, limiter=None):
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    for attempt in range(retries):
        if limiter is not None:
            # Inside the retry loop, so retries are charged against the budget too -
            # otherwise a run of failures quietly doubles the real request rate.
            limiter.acquire()
        try:
            resp = get_fn(NVD_BASE, params=params, headers=headers, timeout=90)
        except requests.exceptions.RequestException:
            if attempt < retries - 1:
                sleep_fn(_backoff_seconds(attempt))
                continue
            raise
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code in (403, 429, 503) and attempt < retries - 1:
            sleep_fn(_backoff_seconds(attempt))
            continue
        resp.raise_for_status()
    raise RuntimeError("NVD request failed after retries")


def fetch_all_pages(params, page_size=2000, get_fn=requests.get, sleep_fn=time.sleep, on_page=None):
    """Page through an NVD query, returning (vulnerabilities, total_results).

    `on_page(vulns, fetched_so_far, total_results)` is an optional callback invoked once
    per page. Supplying it switches this into streaming mode: pages are handed to the
    callback and NOT accumulated, so the returned list is empty. That matters for large
    queries - NVD's full catalog is ~370k CVEs, which is gigabytes of parsed JSON if you
    hold it all in memory before writing any of it. It also gives callers something to
    report progress with, since an unfiltered sync is ~185 sequential requests and would
    otherwise sit silent for tens of minutes.
    """
    all_vulns = []
    start_index = 0
    total_results = None
    while True:
        page = nvd_get(
            {**params, "resultsPerPage": page_size, "startIndex": start_index},
            get_fn=get_fn, sleep_fn=sleep_fn,
        )
        vulns = page["vulnerabilities"]
        total_results = page["totalResults"]
        start_index += page_size
        if on_page is not None:
            on_page(vulns, min(start_index, total_results), total_results)
        else:
            all_vulns.extend(vulns)
        if start_index >= total_results:
            break
        sleep_fn(REQUEST_SPACING_SECONDS)
    return all_vulns, total_results


def fetch_all_pages_parallel(params, page_size=2000, workers=None, get_fn=requests.get,
                             sleep_fn=time.sleep, on_page=None, limiter=None):
    """Same contract as fetch_all_pages, but fetches pages concurrently.

    Sequential paging spends almost all of its time waiting: a page measures ~17s
    end to end, of which the deliberate spacing is ~1s. That leaves the request rate
    at roughly 2 per 30s against a budget of 50, so the win here is idle time, not
    throughput per request.

    Kept separate from fetch_all_pages rather than replacing it: that one is on the
    server's per-scan path, where a single small query has nothing to parallelise and
    concurrency would only add ways to fail. This is for bulk warming.

    Two ordering details matter:

      * Page 0 is fetched by itself first, because `totalResults` is what says how many
        pages exist - there is nothing to fan out over until it comes back.
      * `on_page` is only ever called from the calling thread. The cache writes SQLite
        from that callback, and a single writer keeps the existing connection usable as
        is (sqlite3 connections are not shareable across threads by default).

    Completed pages arrive out of order. That is safe for the cache because rows are
    written with INSERT OR REPLACE keyed on CVE id, so order carries no meaning.
    """
    workers = workers or DEFAULT_WORKERS
    limiter = limiter or RateLimiter()

    def fetch_page(start_index):
        page = nvd_get(
            {**params, "resultsPerPage": page_size, "startIndex": start_index},
            get_fn=get_fn, sleep_fn=sleep_fn, limiter=limiter,
        )
        return page["vulnerabilities"], page["totalResults"]

    all_vulns = []
    fetched = 0

    def deliver(vulns):
        nonlocal fetched
        fetched += len(vulns)
        if on_page is not None:
            on_page(vulns, min(fetched, total_results), total_results)
        else:
            all_vulns.extend(vulns)

    first_vulns, total_results = fetch_page(0)
    deliver(first_vulns)

    remaining = iter(range(page_size, total_results, page_size))
    # Cap work in flight rather than submitting every page up front. Each result is a
    # fully parsed page of `page_size` CVEs held in memory until it is delivered, so an
    # unbounded queue would buffer the whole catalog - the thing streaming mode exists
    # to avoid. Two per worker keeps them fed without stockpiling.
    max_inflight = workers * 2
    pending = set()
    with ThreadPoolExecutor(max_workers=workers) as pool:
        try:
            while True:
                while len(pending) < max_inflight:
                    start_index = next(remaining, None)
                    if start_index is None:
                        break
                    pending.add(pool.submit(fetch_page, start_index))
                if not pending:
                    break
                done, pending = wait(pending, return_when=FIRST_COMPLETED)
                for future in done:
                    page_vulns, _ = future.result()  # re-raises whatever the worker hit
                    deliver(page_vulns)
        except BaseException:
            # Covers Ctrl-C as well as a failed page. Cancelling the queued futures caps
            # the shutdown wait at whatever is already in flight.
            for future in pending:
                future.cancel()
            raise
    return all_vulns, total_results

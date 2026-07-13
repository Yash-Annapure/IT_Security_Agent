import os
import time

import requests
from dotenv import load_dotenv

load_dotenv()

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY")
REQUEST_SPACING_SECONDS = 1 if NVD_API_KEY else 6


def nvd_get(params, retries=5, get_fn=requests.get, sleep_fn=time.sleep):
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    for attempt in range(retries):
        try:
            resp = get_fn(NVD_BASE, params=params, headers=headers, timeout=90)
        except requests.exceptions.RequestException:
            if attempt < retries - 1:
                sleep_fn(REQUEST_SPACING_SECONDS * 2)
                continue
            raise
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code in (403, 429, 503) and attempt < retries - 1:
            sleep_fn(REQUEST_SPACING_SECONDS * 2)
            continue
        resp.raise_for_status()
    raise RuntimeError("NVD request failed after retries")


def fetch_all_pages(params, page_size=2000, get_fn=requests.get, sleep_fn=time.sleep):
    all_vulns = []
    start_index = 0
    total_results = None
    while True:
        page = nvd_get(
            {**params, "resultsPerPage": page_size, "startIndex": start_index},
            get_fn=get_fn, sleep_fn=sleep_fn,
        )
        all_vulns.extend(page["vulnerabilities"])
        total_results = page["totalResults"]
        start_index += page_size
        if start_index >= total_results:
            break
        sleep_fn(REQUEST_SPACING_SECONDS)
    return all_vulns, total_results

"""Pre-populate the local NVD/KEV/CPE cache so scans don't fetch anything at scan time.

    uv run warm_cache.py                  # warm from this repo's uv.lock
    uv run warm_cache.py path/to/uv.lock path/to/package-lock.json
    uv run warm_cache.py --full           # also pull NVD's ENTIRE CVE catalog (slow, big)
    uv run warm_cache.py --days 90        # widen the incremental CVE window (default 14)

Everything lands in `nvd_cache.db` (SQLite, repo root - the same file the server reads),
so this is a one-time cost per machine rather than a per-scan one. Run it once after
cloning, and again occasionally to pick up newly published CVEs.

Why this exists: a scan's slowest step is CPE vendor lookups, which NVD rate-limits to
one request per 6s without an API key (1s with one). The server prewarms those inside
each scan under a 90s budget, so a large lockfile converges over several scans instead
of one. This script does the same fetching with no budget cap and no timeout pressure -
afterwards every name is a local cache hit and scans run in seconds.

Set NVD_API_KEY in .env first if you have one (free from https://nvd.nist.gov/developers
/request-an-api-key): it makes this ~6x faster.
"""
import datetime
import os
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

from it_security_agent import cpe_dictionary, kev, nvd_cache
from it_security_agent.mcp_server import parse_lockfile_components

load_dotenv()

NVD_API_KEY = os.environ.get("NVD_API_KEY")
REQUEST_SPACING_SECONDS = 1 if NVD_API_KEY else 6
DEFAULT_LOCKFILES = ["uv.lock", "package-lock.json", "requirements.txt"]


def _collect_names(paths: list[Path]) -> list[str]:
    names: set[str] = set()
    for path in paths:
        try:
            components = parse_lockfile_components(path.read_text(encoding="utf-8"))
        except Exception as exc:
            print(f"  ! skipping {path}: {exc}", flush=True)
            continue
        if not components:
            # Unrecognized text falls through to the requirements.txt parser, which
            # returns [] rather than raising - say so instead of silently ignoring it.
            print(f"  ! skipping {path}: no components parsed (unrecognized lockfile format?)", flush=True)
            continue
        print(f"  {path}: {len(components)} components", flush=True)
        names.update(c.name for c in components)
    return sorted(names)


def warm_cpe(names: list[str], conn) -> tuple[int, int]:
    """Fetch CPE vendor data for every name not already cached. Returns (fetched, failed)."""
    todo = [n for n in names if not cpe_dictionary.is_cached(n, conn=conn)]
    cached = len(names) - len(todo)
    print(f"\nCPE vendor data: {cached}/{len(names)} already cached, {len(todo)} to fetch", flush=True)
    if not todo:
        return 0, 0

    eta = len(todo) * REQUEST_SPACING_SECONDS
    print(f"Estimated ~{eta // 60}m {eta % 60}s at {REQUEST_SPACING_SECONDS}s/request"
          f"{'' if NVD_API_KEY else ' (no NVD_API_KEY - 6x slower than it needs to be)'}\n", flush=True)

    fetched = failed = 0
    for i, name in enumerate(todo, start=1):
        try:
            cpe_dictionary.search(name, conn=conn, api_key=NVD_API_KEY)
            fetched += 1
            status = "ok"
        except Exception as exc:
            failed += 1
            status = f"FAILED ({type(exc).__name__})"
        print(f"  [{i}/{len(todo)}] {name}: {status}", flush=True)
        if i < len(todo):
            time.sleep(REQUEST_SPACING_SECONDS)
    return fetched, failed


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = [a for a in sys.argv[1:] if a.startswith("--")]
    full = "--full" in flags
    days = 14
    for flag in flags:
        if flag.startswith("--days"):
            _, _, value = flag.partition("=")
            days = int(value) if value else 14

    paths = [Path(a) for a in args] or [Path(n) for n in DEFAULT_LOCKFILES if Path(n).exists()]
    if not paths:
        print("No lockfile found. Pass one explicitly, e.g.: uv run warm_cache.py path/to/uv.lock",
              file=sys.stderr)
        sys.exit(1)

    started = time.time()
    conn = nvd_cache.get_connection()
    print(f"Cache database: {nvd_cache.DB_PATH}\n")

    print("Reading lockfiles:", flush=True)
    names = _collect_names(paths)
    if not names:
        print("No components parsed from any lockfile - nothing to warm.", file=sys.stderr)
        sys.exit(1)
    print(f"  -> {len(names)} unique package names", flush=True)

    if full:
        print("\nSyncing NVD's ENTIRE CVE catalog (this takes a long time and is rarely "
              "needed - the incremental window covers active CVEs)...", flush=True)
        count = nvd_cache.sync_full(conn=conn)
    else:
        print(f"\nSyncing NVD CVEs modified in the last {days} days...", flush=True)
        since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
        count = nvd_cache.sync_incremental(since=since, conn=conn)
    print(f"  -> stored/updated {count} CVEs", flush=True)

    print("\nRefreshing CISA KEV (known exploited vulnerabilities) feed...", flush=True)
    kev.refresh(conn=conn)
    print("  -> done", flush=True)

    fetched, failed = warm_cpe(names, conn)

    elapsed = int(time.time() - started)
    print(f"\nCache warm in {elapsed // 60}m {elapsed % 60}s. "
          f"CVEs synced: {count}. CPE names fetched: {fetched}"
          f"{f', failed: {failed}' if failed else ''}.", flush=True)
    print("Scans against these lockfiles should now hit the local cache for every package.")
    if failed:
        print("Failed names just yield fewer vendor candidates when matching - re-run to retry them.")


if __name__ == "__main__":
    main()

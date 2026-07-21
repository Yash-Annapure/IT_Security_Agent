"""Pre-populate the local NVD/KEV/CPE cache so scans don't fetch anything at scan time.

    uv run warm_cache.py                  # quick warm (30-day CVE window, ~2 min)
    uv run warm_cache.py --days=45        # ~95% CVE coverage, ~35-45 min - do this once
    uv run warm_cache.py path/to/uv.lock path/to/package-lock.json
    uv run warm_cache.py --full           # all ~368k CVEs; --days=45 gets ~95% for less

Everything lands in `nvd_cache.db` (SQLite, repo root - the same file the server reads),
so this is a one-time cost per machine rather than a per-scan one. Run it once after
cloning, and again occasionally to pick up newly published CVEs.

Why this exists, and why the window size matters:

  * Matching can only find CVEs that are actually in the local cache. The cache is
    filled by an NVD query on `lastModified`, so a 14-day window holds only whatever
    NVD happened to touch in the last two weeks - a few percent of the catalog. Scans
    against that will look reassuringly clean while simply not knowing about most
    vulnerabilities. A wider window is a correctness setting, not a performance one.
  * CPE vendor lookups are the slowest per-scan step, and NVD rate-limits them (1
    request/sec with an API key, 6 without). The server prewarms them inside each scan
    under a 90s budget, so a large lockfile converges over several scans; this script
    does the same fetching with no budget cap, so afterwards every name is a local hit.

Set NVD_API_KEY in .env first if you have one (free from https://nvd.nist.gov/developers
/request-an-api-key): it makes everything here ~6x faster.
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
# 30 days is the largest window that stays quick. NVD bulk re-scores old records, and
# as of this writing a re-scoring event ~35-40 days back means the catalog size cliffs
# hard just past it - measured against the live API:
#     7d 5,447 | 14d 9,321 | 30d 14,672  <- cheap, seconds to a couple of minutes
#     45d 350,485 | 60d 350,507 | 90d 350,555  <- ~95% of all 368k CVEs, 35-45 minutes
# So --days 45 is the "near-complete coverage" setting and anything beyond it buys
# almost nothing extra. Re-measure with --coverage if these numbers look stale.
DEFAULT_DAYS = 30
DEFAULT_LOCKFILES = ["uv.lock", "package-lock.json", "requirements.txt"]


def _fmt_duration(seconds: float) -> str:
    seconds = int(seconds)
    return f"{seconds // 60}m {seconds % 60:02d}s" if seconds >= 60 else f"{seconds}s"


def _db_stats(conn) -> dict:
    """Row counts per table, tolerating tables that don't exist yet on a fresh DB."""
    stats = {}
    for table in ("cves", "kev", "cpe_dictionary"):
        try:
            stats[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        except Exception:
            stats[table] = 0
    try:
        stats["size_mb"] = nvd_cache.DB_PATH.stat().st_size / (1024 * 1024)
    except OSError:
        stats["size_mb"] = 0.0
    return stats


def _print_stats(label: str, stats: dict) -> None:
    print(f"  {label}: {stats['cves']:,} CVEs, {stats['kev']:,} known-exploited, "
          f"{stats['cpe_dictionary']:,} CPE names ({stats['size_mb']:.1f} MB)", flush=True)


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
        ecosystems = sorted({c.ecosystem for c in components})
        print(f"  {path}: {len(components)} components ({', '.join(ecosystems)})", flush=True)
        names.update(c.name for c in components)
    return sorted(names)


def _sync_reporter(started_at: float):
    """Progress callback for NVD paging: shows position, rate and a live ETA.

    NVD pages 2000 CVEs at a time, so even a 90-day window is dozens of sequential
    requests and a full sync is ~185. Without this the command looks hung.
    """
    state = {"last": 0.0, "page": 0}

    def report(fetched, total):
        state["page"] += 1
        now = time.time()
        if now - state["last"] < 2 and fetched < total:
            return  # don't spam a line per page on fast connections
        state["last"] = now
        elapsed = now - started_at
        pct = (fetched / total * 100) if total else 0
        eta = (elapsed / fetched * (total - fetched)) if fetched else 0
        print(f"  [page {state['page']:>3}] {fetched:,}/{total:,} CVEs ({pct:.0f}%)  "
              f"elapsed {_fmt_duration(elapsed)}  eta ~{_fmt_duration(eta)}", flush=True)

    return report


def warm_cpe(names: list[str], conn) -> tuple[int, int]:
    """Fetch CPE vendor data for every name not already cached. Returns (fetched, failed)."""
    todo = [n for n in names if not cpe_dictionary.is_cached(n, conn=conn)]
    cached = len(names) - len(todo)
    print(f"\nCPE vendor data: {cached}/{len(names)} already cached, {len(todo)} to fetch", flush=True)
    if not todo:
        return 0, 0

    eta = len(todo) * REQUEST_SPACING_SECONDS
    print(f"  ~{_fmt_duration(eta)} at {REQUEST_SPACING_SECONDS}s/request"
          f"{'' if NVD_API_KEY else ' (no NVD_API_KEY - 6x slower than it needs to be)'}\n", flush=True)

    started = time.time()
    fetched = failed = 0
    for i, name in enumerate(todo, start=1):
        try:
            products = cpe_dictionary.search(name, conn=conn, api_key=NVD_API_KEY)
            fetched += 1
            status = f"ok ({len(products)} CPE entries)" if products else "ok (no CPE entries - unknown to NVD)"
        except Exception as exc:
            failed += 1
            status = f"FAILED ({type(exc).__name__}: {exc})"
        remaining = (len(todo) - i) * REQUEST_SPACING_SECONDS
        print(f"  [{i:>4}/{len(todo)}] {name:<32} {status}"
              f"{'' if not remaining else f'   (~{_fmt_duration(remaining)} left)'}", flush=True)
        if i < len(todo):
            time.sleep(REQUEST_SPACING_SECONDS)
    print(f"  CPE pass finished in {_fmt_duration(time.time() - started)}", flush=True)
    return fetched, failed


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = [a for a in sys.argv[1:] if a.startswith("--")]
    full = "--full" in flags
    days = DEFAULT_DAYS
    for flag in flags:
        if flag.startswith("--days"):
            _, _, value = flag.partition("=")
            days = int(value) if value else DEFAULT_DAYS

    paths = [Path(a) for a in args] or [Path(n) for n in DEFAULT_LOCKFILES if Path(n).exists()]
    if not paths:
        print("No lockfile found. Pass one explicitly, e.g.: uv run warm_cache.py path/to/uv.lock",
              file=sys.stderr)
        sys.exit(1)

    started = time.time()
    conn = nvd_cache.get_connection()
    print(f"Cache database: {nvd_cache.DB_PATH}", flush=True)
    before = _db_stats(conn)
    _print_stats("before", before)

    print("\nReading lockfiles:", flush=True)
    names = _collect_names(paths)
    if not names:
        print("No components parsed from any lockfile - nothing to warm.", file=sys.stderr)
        sys.exit(1)
    print(f"  -> {len(names)} unique package names to look up", flush=True)

    if full:
        print("\nSyncing NVD's ENTIRE CVE catalog...", flush=True)
        print("  NOTE: ~370,000 CVEs over ~185 sequential requests - expect "
              f"{'10-20' if NVD_API_KEY else '30-45'} minutes"
              f"{'' if NVD_API_KEY else ' (no NVD_API_KEY - set one to cut this ~6x)'}.",
              flush=True)
        print("  Ctrl-C and re-run without --full if you'd rather not wait; --days covers "
              "recently-changed CVEs, which is what matching mostly relies on.\n", flush=True)
        count = nvd_cache.sync_full(conn=conn, on_progress=_sync_reporter(time.time()))
    else:
        print(f"\nSyncing NVD CVEs modified in the last {days} days...", flush=True)
        print("  (this is a coverage setting: matching can only find CVEs that are in "
              "this cache - widen it with --days if scans look suspiciously clean)\n", flush=True)
        since = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
        count = nvd_cache.sync_incremental(since=since, conn=conn, on_progress=_sync_reporter(time.time()))
    print(f"  -> stored/updated {count:,} CVEs", flush=True)
    if not full and days < 45:
        print("  Coverage note: NVD holds ~368,000 CVEs in total. A window this small "
              "keeps the sync quick but leaves the cache thin, and matching can only "
              "find what's cached. `--days 45` pulls ~350,000 (~95%) in one ~35-45 "
              "minute pass - worth doing once.", flush=True)

    print("\nRefreshing CISA KEV (actively-exploited vulnerabilities) feed...", flush=True)
    kev_count = kev.refresh(conn=conn)
    print(f"  -> {kev_count:,} known-exploited CVEs", flush=True)

    fetched, failed = warm_cpe(names, conn)

    after = _db_stats(conn)
    print(f"\nCache warm in {_fmt_duration(time.time() - started)}.", flush=True)
    _print_stats("before", before)
    _print_stats(" after", after)
    if failed:
        print(f"  {failed} CPE lookup(s) failed - those names just yield fewer vendor "
              f"candidates when matching. Re-run to retry them.", flush=True)
    print("\nScans against these lockfiles should now hit the local cache for every package.")


if __name__ == "__main__":
    main()

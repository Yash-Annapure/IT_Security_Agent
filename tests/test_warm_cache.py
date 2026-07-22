import datetime
import sys
from unittest.mock import patch

import warm_cache


def test_main_runs_incremental_sync_and_kev_refresh(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["warm_cache.py"])
    with patch.object(warm_cache.nvd_cache, "get_connection", return_value="conn"), \
         patch.object(warm_cache.nvd_cache, "sync_incremental", return_value=7) as mock_inc, \
         patch.object(warm_cache.nvd_cache, "sync_full") as mock_full, \
         patch.object(warm_cache.kev, "refresh", return_value=1283) as mock_kev:
        warm_cache.main()
    mock_inc.assert_called_once()
    mock_full.assert_not_called()  # incremental unless --full
    mock_kev.assert_called_once()
    assert "stored/updated 7 CVEs" in capsys.readouterr().out


def test_main_needs_no_lockfile(tmp_path, monkeypatch):
    # Warming is per-machine, not per-repo: it fills the CVE catalog, and vendors are
    # read out of those records at scan time. An empty directory must warm fine - this
    # used to exit(1) because the CPE pass needed package names to look up.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["warm_cache.py"])
    with patch.object(warm_cache.nvd_cache, "get_connection", return_value="conn"), \
         patch.object(warm_cache.nvd_cache, "sync_incremental", return_value=1), \
         patch.object(warm_cache.kev, "refresh", return_value=1283):
        warm_cache.main()  # must not raise SystemExit


def test_main_full_flag_pulls_entire_catalog(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["warm_cache.py", "--full"])
    with patch.object(warm_cache.nvd_cache, "get_connection", return_value="conn"), \
         patch.object(warm_cache.nvd_cache, "sync_incremental") as mock_inc, \
         patch.object(warm_cache.nvd_cache, "sync_full", return_value=99) as mock_full, \
         patch.object(warm_cache.kev, "refresh", return_value=1283):
        warm_cache.main()
    mock_full.assert_called_once()
    mock_inc.assert_not_called()


def test_default_window_is_wider_than_the_two_week_sliver(tmp_path, monkeypatch, capsys):
    # Coverage matters: matching can only find CVEs present in the cache, and a 14-day
    # window holds ~9k of NVD's ~368k. 30 days is the widest window that still syncs in
    # ~2 minutes (past ~45 days the catalog cliffs to ~350k and takes 35-45 min), so the
    # default stays quick but the run must tell the user to widen it.
    assert warm_cache.DEFAULT_DAYS >= 30
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["warm_cache.py"])
    with patch.object(warm_cache.nvd_cache, "get_connection", return_value="conn"), \
         patch.object(warm_cache.nvd_cache, "sync_incremental", return_value=1) as mock_inc, \
         patch.object(warm_cache.kev, "refresh", return_value=1283):
        warm_cache.main()
    since = mock_inc.call_args.kwargs["since"]
    window_days = (datetime.datetime.now(datetime.timezone.utc) - since).days
    assert window_days >= 29  # ~30-day window, allowing for clock rounding
    assert "Coverage note" in capsys.readouterr().out  # nudges the user toward --days=45


def test_wide_window_skips_the_coverage_nag(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["warm_cache.py", "--days=45"])
    with patch.object(warm_cache.nvd_cache, "get_connection", return_value="conn"), \
         patch.object(warm_cache.nvd_cache, "sync_incremental", return_value=1), \
         patch.object(warm_cache.kev, "refresh", return_value=1283):
        warm_cache.main()
    assert "Coverage note" not in capsys.readouterr().out


def test_days_flag_overrides_the_default(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["warm_cache.py", "--days=365"])
    with patch.object(warm_cache.nvd_cache, "get_connection", return_value="conn"), \
         patch.object(warm_cache.nvd_cache, "sync_incremental", return_value=1) as mock_inc, \
         patch.object(warm_cache.kev, "refresh", return_value=1283):
        warm_cache.main()
    since = mock_inc.call_args.kwargs["since"]
    assert (datetime.datetime.now(datetime.timezone.utc) - since).days >= 364

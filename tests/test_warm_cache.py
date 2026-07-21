import datetime
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

import warm_cache

UV_LOCK_TEXT = (
    '[[package]]\nname = "django"\nversion = "2.2.0"\n'
    'source = { registry = "https://pypi.org/simple" }\n\n'
    '[[package]]\nname = "flask"\nversion = "3.0.0"\n'
    'source = { registry = "https://pypi.org/simple" }\n'
)


def test_collect_names_dedupes_across_lockfiles(tmp_path, capsys):
    a = tmp_path / "uv.lock"
    a.write_text(UV_LOCK_TEXT)
    b = tmp_path / "other.lock"
    b.write_text(UV_LOCK_TEXT)  # same packages - must not double up
    assert warm_cache._collect_names([a, b]) == ["django", "flask"]


def test_collect_names_skips_unparseable_files_without_crashing(tmp_path, capsys):
    good = tmp_path / "uv.lock"
    good.write_text(UV_LOCK_TEXT)
    bad = tmp_path / "broken.lock"
    bad.write_text("this is not a lockfile {{{")
    assert warm_cache._collect_names([bad, good]) == ["django", "flask"]
    assert "skipping" in capsys.readouterr().out


def test_warm_cpe_skips_names_already_cached():
    with patch.object(warm_cache.cpe_dictionary, "is_cached", return_value=True), \
         patch.object(warm_cache.cpe_dictionary, "search") as mock_search, \
         patch.object(warm_cache.time, "sleep") as mock_sleep:
        fetched, failed = warm_cache.warm_cpe(["django", "flask"], conn="conn")
    assert (fetched, failed) == (0, 0)
    mock_search.assert_not_called()
    mock_sleep.assert_not_called()


def test_warm_cpe_fetches_uncached_names_with_rate_limit_spacing():
    with patch.object(warm_cache.cpe_dictionary, "is_cached", return_value=False), \
         patch.object(warm_cache.cpe_dictionary, "search") as mock_search, \
         patch.object(warm_cache.time, "sleep") as mock_sleep:
        fetched, failed = warm_cache.warm_cpe(["django", "flask"], conn="conn")
    assert (fetched, failed) == (2, 0)
    assert mock_search.call_count == 2
    # Spacing between requests, but not after the last one.
    assert mock_sleep.call_count == 1


def test_warm_cpe_keeps_going_when_one_name_fails():
    with patch.object(warm_cache.cpe_dictionary, "is_cached", return_value=False), \
         patch.object(warm_cache.cpe_dictionary, "search",
                      side_effect=[Exception("boom"), None]) as mock_search, \
         patch.object(warm_cache.time, "sleep"):
        fetched, failed = warm_cache.warm_cpe(["django", "flask"], conn="conn")
    assert (fetched, failed) == (1, 1)
    assert mock_search.call_count == 2  # the failure didn't abort the run


def test_main_exits_when_no_lockfile_found(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["warm_cache.py"])
    with pytest.raises(SystemExit) as exc_info:
        warm_cache.main()
    assert exc_info.value.code == 1


def test_main_runs_incremental_sync_kev_refresh_and_cpe_warm(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "uv.lock").write_text(UV_LOCK_TEXT)
    monkeypatch.setattr(sys, "argv", ["warm_cache.py"])
    with patch.object(warm_cache.nvd_cache, "get_connection", return_value="conn"), \
         patch.object(warm_cache.nvd_cache, "sync_incremental", return_value=7) as mock_inc, \
         patch.object(warm_cache.nvd_cache, "sync_full") as mock_full, \
         patch.object(warm_cache.kev, "refresh", return_value=1283) as mock_kev, \
         patch.object(warm_cache, "warm_cpe", return_value=(2, 0)) as mock_warm:
        warm_cache.main()
    mock_inc.assert_called_once()
    mock_full.assert_not_called()  # incremental unless --full
    mock_kev.assert_called_once()
    assert mock_warm.call_args[0][0] == ["django", "flask"]
    assert "stored/updated 7 CVEs" in capsys.readouterr().out


def test_main_full_flag_pulls_entire_catalog(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "uv.lock").write_text(UV_LOCK_TEXT)
    monkeypatch.setattr(sys, "argv", ["warm_cache.py", "--full"])
    with patch.object(warm_cache.nvd_cache, "get_connection", return_value="conn"), \
         patch.object(warm_cache.nvd_cache, "sync_incremental") as mock_inc, \
         patch.object(warm_cache.nvd_cache, "sync_full", return_value=99) as mock_full, \
         patch.object(warm_cache.kev, "refresh", return_value=1283), \
         patch.object(warm_cache, "warm_cpe", return_value=(0, 0)):
        warm_cache.main()
    mock_full.assert_called_once()
    mock_inc.assert_not_called()


def test_main_accepts_explicit_lockfile_paths(tmp_path, monkeypatch):
    lockfile = tmp_path / "nested" / "uv.lock"
    lockfile.parent.mkdir()
    lockfile.write_text(UV_LOCK_TEXT)
    monkeypatch.setattr(sys, "argv", ["warm_cache.py", str(lockfile)])
    with patch.object(warm_cache.nvd_cache, "get_connection", return_value="conn"), \
         patch.object(warm_cache.nvd_cache, "sync_incremental", return_value=1), \
         patch.object(warm_cache.kev, "refresh", return_value=1283), \
         patch.object(warm_cache, "warm_cpe", return_value=(2, 0)) as mock_warm:
        warm_cache.main()
    assert mock_warm.call_args[0][0] == ["django", "flask"]


def test_default_window_is_wider_than_the_two_week_sliver(tmp_path, monkeypatch, capsys):
    # Coverage matters: matching can only find CVEs present in the cache, and a 14-day
    # window holds ~9k of NVD's ~368k. 30 days is the widest window that still syncs in
    # ~2 minutes (past ~45 days the catalog cliffs to ~350k and takes 35-45 min), so the
    # default stays quick but the run must tell the user to widen it.
    assert warm_cache.DEFAULT_DAYS >= 30
    monkeypatch.chdir(tmp_path)
    (tmp_path / "uv.lock").write_text(UV_LOCK_TEXT)
    monkeypatch.setattr(sys, "argv", ["warm_cache.py"])
    with patch.object(warm_cache.nvd_cache, "get_connection", return_value="conn"), \
         patch.object(warm_cache.nvd_cache, "sync_incremental", return_value=1) as mock_inc, \
         patch.object(warm_cache.kev, "refresh", return_value=1283), \
         patch.object(warm_cache, "warm_cpe", return_value=(0, 0)):
        warm_cache.main()
    since = mock_inc.call_args.kwargs["since"]
    window_days = (datetime.datetime.now(datetime.timezone.utc) - since).days
    assert window_days >= 29  # ~30-day window, allowing for clock rounding
    assert "Coverage note" in capsys.readouterr().out  # nudges the user toward --days=45


def test_wide_window_skips_the_coverage_nag(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "uv.lock").write_text(UV_LOCK_TEXT)
    monkeypatch.setattr(sys, "argv", ["warm_cache.py", "--days=45"])
    with patch.object(warm_cache.nvd_cache, "get_connection", return_value="conn"), \
         patch.object(warm_cache.nvd_cache, "sync_incremental", return_value=1), \
         patch.object(warm_cache.kev, "refresh", return_value=1283), \
         patch.object(warm_cache, "warm_cpe", return_value=(0, 0)):
        warm_cache.main()
    assert "Coverage note" not in capsys.readouterr().out


def test_days_flag_overrides_the_default(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "uv.lock").write_text(UV_LOCK_TEXT)
    monkeypatch.setattr(sys, "argv", ["warm_cache.py", "--days=365"])
    with patch.object(warm_cache.nvd_cache, "get_connection", return_value="conn"), \
         patch.object(warm_cache.nvd_cache, "sync_incremental", return_value=1) as mock_inc, \
         patch.object(warm_cache.kev, "refresh", return_value=1283), \
         patch.object(warm_cache, "warm_cpe", return_value=(0, 0)):
        warm_cache.main()
    since = mock_inc.call_args.kwargs["since"]
    assert (datetime.datetime.now(datetime.timezone.utc) - since).days >= 364

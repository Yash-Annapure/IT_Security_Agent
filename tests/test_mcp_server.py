import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

from it_security_agent import mcp_server
from it_security_agent.agent import Finding, ScanResult
from it_security_agent.schema import Component

UV_LOCK_TEXT = """
[[package]]
name = "django"
version = "2.2.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "our-own-project"
version = "0.1.0"
source = { virtual = "." }
"""

PACKAGE_LOCK_TEXT = json.dumps({
    "packages": {
        "": {"name": "root-project"},
        "node_modules/lodash": {"version": "4.17.15"},
    }
})

def test_parse_lockfile_components_detects_uv_lock_by_content():
    components = mcp_server.parse_lockfile_components(UV_LOCK_TEXT)
    assert [c.name for c in components] == ["django"]
    assert components[0].ecosystem == "PyPI"


def test_parse_lockfile_components_detects_requirements_txt_by_content():
    # No "{" (not JSON) and no "[[package]]" (not uv.lock TOML) - falls back to
    # requirements.txt, the only remaining plain-text lockfile format supported.
    components = mcp_server.parse_lockfile_components("django==2.2.0\nflask>=1.0\n")
    assert [c.name for c in components] == ["django"]


def test_parse_lockfile_components_detects_package_lock_by_content():
    components = mcp_server.parse_lockfile_components(PACKAGE_LOCK_TEXT)
    assert [c.name for c in components] == ["lodash"]
    assert components[0].ecosystem == "npm"


def test_parse_lockfile_components_rejects_unknown_lockfile_type():
    with pytest.raises(ValueError):
        mcp_server.parse_lockfile_components(UV_LOCK_TEXT, lockfile_type="Pipfile.lock")


def test_bounded_get_sets_a_20s_timeout():
    with patch.object(mcp_server.requests, "get", return_value="response") as mock_get:
        result = mcp_server._bounded_get("http://example.test", headers={})
    assert result == "response"
    assert mock_get.call_args.kwargs["timeout"] == 20


def test_get_setup_rules_returns_the_bundled_clinerules_file_verbatim():
    on_disk = mcp_server.CLINERULES_PATH.read_text(encoding="utf-8")
    assert mcp_server.get_setup_rules() == on_disk
    assert "scan_repo" in on_disk  # sanity: it's actually the rules file, not something else


def test_get_setup_rules_raises_clearly_if_bundled_file_is_missing():
    with patch.object(mcp_server, "CLINERULES_PATH", Path("nonexistent") / "scan-repo.md"):
        with pytest.raises(FileNotFoundError):
            mcp_server.get_setup_rules()


def test_scan_repo_rejects_unexpanded_shell_substitution_with_clear_error():
    with pytest.raises(ValueError, match="unexpanded shell command substitution"):
        mcp_server.scan_repo(lockfile_content="$(type uv.lock)", lockfile_type="uv.lock")


def test_scan_repo_rejects_ellipsis_placeholder_with_clear_error():
    with pytest.raises(ValueError, match="placeholder/ellipsis stub"):
        mcp_server.scan_repo(lockfile_content="{ ... (lockfile content) ... }")


def test_scan_repo_rejects_output_location_description_with_clear_error():
    # The exact real case this covers: Cline auto-truncates large terminal output to a
    # log file and shows a summary line in its place - a model paraphrased that summary
    # ("... (3418 lines written to null) ...") as if it were the lockfile content itself.
    with pytest.raises(ValueError, match="description of where output was saved"):
        mcp_server.scan_repo(lockfile_content="... (3418 lines written to null) ...")


def test_scan_repo_rejects_bare_file_path_with_clear_error():
    with pytest.raises(ValueError, match="bare file path"):
        mcp_server.scan_repo(lockfile_content="reports/condensed_lockfile.txt")


def test_condense_lockfile_uv_lock_round_trips_to_the_same_components():
    condensed = mcp_server.condense_lockfile(lockfile_content=UV_LOCK_TEXT)
    assert condensed == "django==2.2.0"
    components = mcp_server.parse_lockfile_components(condensed)
    assert [(c.name, c.version, c.ecosystem) for c in components] == [("django", "2.2.0", "PyPI")]


def test_condense_lockfile_package_lock_round_trips_to_the_same_components():
    condensed = mcp_server.condense_lockfile(lockfile_content=PACKAGE_LOCK_TEXT)
    original = mcp_server.parse_lockfile_components(PACKAGE_LOCK_TEXT)
    round_tripped = mcp_server.parse_lockfile_components(condensed)
    assert {(c.name, c.version, c.ecosystem) for c in round_tripped} == \
        {(c.name, c.version, c.ecosystem) for c in original}


def test_condense_npm_stays_json_so_the_ecosystem_survives_the_round_trip():
    # A flat "react==18.2.0" list would be re-detected as requirements.txt and the
    # packages scanned as PyPI - silently matching npm names against Python CVEs.
    condensed = mcp_server.condense_lockfile(lockfile_content=json.dumps({
        "lockfileVersion": 3, "packages": {
            "": {"name": "app"},
            "node_modules/react": {"version": "18.2.0"},
            "node_modules/@babel/core": {"version": "7.0.0"}}}))
    components = mcp_server.parse_lockfile_components(condensed)
    assert {(c.name, c.version, c.ecosystem) for c in components} == {
        ("react", "18.2.0", "npm"), ("@babel/core", "7.0.0", "npm")}


def test_condense_npm_drops_the_node_modules_prefix_and_whitespace():
    # Both are re-derived on parse, so carrying them costs a small model context for
    # nothing - parse_package_lock_text splits on "node_modules/" and takes the last part.
    condensed = mcp_server.condense_lockfile(lockfile_content=json.dumps({
        "lockfileVersion": 3, "packages": {
            "": {"name": "app"}, "node_modules/react": {"version": "18.2.0"}}}))
    assert "node_modules/" not in condensed
    assert ", " not in condensed and '": ' not in condensed  # compact separators
    assert condensed == '{"packages":{"react":{"version":"18.2.0"}}}'


def test_condense_lockfile_is_dramatically_smaller_than_the_original():
    condensed = mcp_server.condense_lockfile(lockfile_content=UV_LOCK_TEXT)
    assert len(condensed) < len(UV_LOCK_TEXT)


def test_condense_lockfile_requires_lockfile_content():
    with pytest.raises(ValueError, match="No lockfile content provided"):
        mcp_server.condense_lockfile()


def test_condense_lockfile_raises_clearly_when_nothing_parses():
    with pytest.raises(ValueError, match="No components could be parsed"):
        mcp_server.condense_lockfile(lockfile_content='{"packages": {"": {}}}')


def test_condense_lockfile_rejects_unexpanded_shell_substitution_with_clear_error():
    with pytest.raises(ValueError, match="unexpanded shell command substitution"):
        mcp_server.condense_lockfile(lockfile_content="$(cat uv.lock)")


def _fake_ctx(headers):
    from types import SimpleNamespace
    request = None if headers is None else SimpleNamespace(headers=headers)
    return SimpleNamespace(request_context=SimpleNamespace(request=request))


def test_get_scan_command_derives_https_url_from_forwarded_headers():
    # The tunnel (cloudflared) terminates TLS and forwards plain HTTP, so the original
    # scheme arrives in x-forwarded-proto and the public hostname in host.
    ctx = _fake_ctx({"host": "example.trycloudflare.com", "x-forwarded-proto": "https"})
    text = mcp_server.get_scan_command(ctx)
    assert "https://example.trycloudflare.com/scan" in text
    assert "--data-binary" in text
    assert "curl.exe" in text  # PowerShell variant included
    assert "don't retry or cancel" in text  # warns about first-call duration so the model waits


def test_get_scan_command_tees_instead_of_redirecting():
    # A `>` redirect swallows the streamed pipeline progress, so the scan looks frozen
    # for its whole duration. The command must save the report AND stay on screen.
    ctx = _fake_ctx({"host": "example.test", "x-forwarded-proto": "https"})
    text = mcp_server.get_scan_command(ctx)
    assert "Tee-Object -Variable report" in text      # PowerShell: stream + capture
    assert "[IO.File]::WriteAllLines" in text          # ...saved as plain UTF-8, not UTF-16
    assert "| tee reports/" in text                    # bash/zsh
    assert "-sN" in text                               # unbuffered: stages appear live
    assert "DO NOT redirect this with `>`" in text


def test_get_scan_command_falls_back_to_http_without_proto_header():
    ctx = _fake_ctx({"host": "192.168.1.42:8765"})
    text = mcp_server.get_scan_command(ctx)
    assert "http://192.168.1.42:8765/scan" in text


def test_get_scan_command_asks_the_user_when_no_request_is_available():
    text = mcp_server.get_scan_command(_fake_ctx(None))
    assert "Ask the user" in text
    assert "/scan" in text  # still explains the command shape


def test_scan_http_endpoint_returns_the_finished_report():
    with patch.object(mcp_server, "get_connection", return_value="conn"), \
         patch.object(mcp_server, "_ensure_synced"), \
         patch.object(mcp_server, "prewarm"), \
         patch.object(mcp_server, "run_pipeline", return_value=None), \
         patch.object(mcp_server, "raw_matches", return_value=[]):
        resp = _http_client().post("/scan", content=UV_LOCK_TEXT.encode("utf-8"))
    assert resp.status_code == 200
    assert "Vulnerability scan result" in resp.text
    assert "Generated SBOM" not in resp.text  # SBOM off by default


def test_scan_http_endpoint_includes_sbom_only_when_requested():
    with patch.object(mcp_server, "get_connection", return_value="conn"), \
         patch.object(mcp_server, "_ensure_synced"), \
         patch.object(mcp_server, "prewarm"), \
         patch.object(mcp_server, "run_pipeline", return_value=None), \
         patch.object(mcp_server, "raw_matches", return_value=[]):
        resp = _http_client().post("/scan?include_sbom=true", content=UV_LOCK_TEXT.encode("utf-8"))
    assert resp.status_code == 200
    assert "Generated SBOM" in resp.text


def test_scan_http_endpoint_rejects_empty_body_with_usage_hint():
    resp = _http_client().post("/scan", content=b"")
    assert resp.status_code == 400
    assert "--data-binary" in resp.text


def test_scan_http_endpoint_rejects_unparseable_content_before_streaming():
    # Garbage must fail with a real 400 up front - once the streamed 200 begins,
    # the status can't be changed, so validation has to happen before the stream.
    resp = _http_client().post("/scan", content=b'{"packages": {"": {}}}')
    assert resp.status_code == 400
    assert "No components could be parsed" in resp.text


def test_scan_http_endpoint_streams_keepalive_header_before_the_report():
    with patch.object(mcp_server, "get_connection", return_value="conn"), \
         patch.object(mcp_server, "_ensure_synced"), \
         patch.object(mcp_server, "prewarm"), \
         patch.object(mcp_server, "run_pipeline", return_value=None), \
         patch.object(mcp_server, "raw_matches", return_value=[]):
        resp = _http_client().post("/scan", content=UV_LOCK_TEXT.encode("utf-8"))
    assert resp.status_code == 200
    # The keepalive preamble (what defeats Cloudflare's ~100s proxy timeout) comes
    # first, then the report.
    assert resp.text.index("Scanning") < resp.text.index("Vulnerability scan result")
    # Trailing newline: without it, terminal integrations glue their shell-prompt
    # artifacts onto the report's last line (seen in practice).
    assert resp.text.endswith("\n")


def test_scan_http_endpoint_scans_every_component_with_no_cap():
    # 45 components - more than scan_repo's MCP-tool default cap of 40. /scan is the
    # primary path and must test every single package in the lockfile.
    lock = "\n".join(
        f'[[package]]\nname = "pkg{i}"\nversion = "1.0.0"\nsource = {{ registry = "https://pypi.org/simple" }}\n'
        for i in range(45)
    )
    with patch.object(mcp_server, "get_connection", return_value="conn"), \
         patch.object(mcp_server, "_ensure_synced"), \
         patch.object(mcp_server, "prewarm"), \
         patch.object(mcp_server, "run_pipeline", return_value=None), \
         patch.object(mcp_server, "raw_matches", return_value=[]) as mock_raw:
        resp = _http_client().post("/scan", content=lock.encode("utf-8"))
    assert resp.status_code == 200
    scanned = mock_raw.call_args[0][0]
    assert len(scanned) == 45  # all of them, not the first 40
    assert "capped by max_components" not in resp.text


def test_scan_http_endpoint_streams_live_pipeline_progress():
    # Transparency: the user should see the real stages (SBOM generation, sync state,
    # CPE cache state, matching, triage) as they happen - not an opaque wait.
    with patch.object(mcp_server, "get_connection", return_value="conn"), \
         patch.object(mcp_server, "_ensure_synced"), \
         patch.object(mcp_server, "prewarm"), \
         patch.object(mcp_server, "run_pipeline", return_value=None), \
         patch.object(mcp_server, "raw_matches", return_value=[]):
        resp = _http_client().post("/scan", content=UV_LOCK_TEXT.encode("utf-8"))
    assert resp.status_code == 200
    for expected in ("Parsed 1 components", "Generated CycloneDX", "SBOM",
                     "Matching components against NVD", "## Pipeline"):
        assert expected in resp.text, f"missing progress detail: {expected}"


def test_run_pipeline_reports_model_training_details_through_step():
    two_class_df = pd.DataFrame([
        {**{f: 0.0 for f in mcp_server.labeling.FEATURES}, "label_real_match": True},
        {**{f: 1.0 for f in mcp_server.labeling.FEATURES}, "label_real_match": False},
    ])
    seen = []
    with patch.object(mcp_server.labeling, "build_dataset", return_value=two_class_df), \
         patch.object(mcp_server.model, "train_and_compare"), \
         patch.object(mcp_server.model, "load_winning_model", return_value=("RandomForest", object(), 0.42)), \
         patch.object(mcp_server.explain, "make_explainer", return_value=object()), \
         patch.object(mcp_server.agent, "scan", return_value="result"):
        mcp_server.run_pipeline([], conn=None, step=seen.append)
    joined = "\n".join(seen)
    assert "LogisticRegression vs RandomForest" in joined  # the model comparison is visible
    assert "RandomForest (decision threshold 0.42)" in joined  # and which one won
    assert "SHAP" in joined


def _http_client():
    # The /condense custom route is registered on the same ASGI app the real server
    # runs (streamable-http transport), so testing through that app exercises the
    # actual wiring, not a lookalike.
    from starlette.testclient import TestClient
    return TestClient(mcp_server.mcp.streamable_http_app())


def test_condense_http_endpoint_returns_condensed_lockfile():
    resp = _http_client().post("/condense", content=UV_LOCK_TEXT.encode("utf-8"))
    assert resp.status_code == 200
    assert resp.text == "django==2.2.0"


def test_condense_http_endpoint_rejects_empty_body_with_usage_hint():
    resp = _http_client().post("/condense", content=b"")
    assert resp.status_code == 400
    assert "--data-binary" in resp.text


def test_condense_http_endpoint_rejects_unparseable_content():
    resp = _http_client().post("/condense", content=b'{"packages": {"": {}}}')
    assert resp.status_code == 400
    assert "No components could be parsed" in resp.text


def test_get_connection_caches_across_calls():
    mcp_server._conn = None
    try:
        with patch.object(mcp_server.nvd_cache, "get_connection", return_value="a-connection") as mock_new:
            first = mcp_server.get_connection()
            second = mcp_server.get_connection()
        assert first == "a-connection"
        assert second is first
        mock_new.assert_called_once()
    finally:
        mcp_server._conn = None


def test_ensure_synced_skips_when_recent():
    mcp_server._last_synced = time.time()
    try:
        with patch.object(mcp_server.nvd_cache, "sync_incremental") as mock_sync:
            mcp_server._ensure_synced(conn="conn")
        mock_sync.assert_not_called()
    finally:
        mcp_server._last_synced = 0.0


def test_a_complete_cache_scans_offline_without_syncing():
    # A warmed cache is the whole point of warm_cache.py: if the catalog is already
    # local, a scan must not reach for the network at all.
    with patch.object(mcp_server, "get_connection", return_value="conn"), \
         patch.object(mcp_server, "_cache_coverage", return_value=dict(FULL_CACHE)), \
         patch.object(mcp_server, "_ensure_synced") as mock_sync, \
         patch.object(mcp_server, "prewarm"), \
         patch.object(mcp_server, "run_pipeline", return_value=ScanResult()):
        text = mcp_server.scan_repo(lockfile_content=UV_LOCK_TEXT, include_sbom=False)
    mock_sync.assert_not_called()
    assert "scanning offline, no NVD sync needed" in text


def test_ensure_synced_syncs_when_stale():
    mcp_server._last_synced = 0.0
    try:
        with patch.object(mcp_server.nvd_cache, "sync_incremental") as mock_sync, \
             patch.object(mcp_server.kev, "refresh") as mock_kev:
            mcp_server._ensure_synced(conn="conn")
        mock_sync.assert_called_once_with(since=mock_sync.call_args.kwargs["since"], conn="conn")
        mock_kev.assert_called_once_with(conn="conn")
        assert mcp_server._last_synced > 0
    finally:
        mcp_server._last_synced = 0.0


def test_prewarm_calls_cpe_search_per_unique_name():
    components = [
        Component(name="django", version="1.0", ecosystem="PyPI", source="t"),
        Component(name="django", version="2.0", ecosystem="PyPI", source="t"),  # duplicate name
        Component(name="flask", version="1.0", ecosystem="PyPI", source="t"),
    ]
    with patch.object(mcp_server.cpe_dictionary, "is_cached", return_value=False), \
         patch.object(mcp_server.cpe_dictionary, "search") as mock_search, \
         patch.object(mcp_server.time, "sleep"):
        mcp_server.prewarm(components, conn="conn")
    assert {call.args[0] for call in mock_search.call_args_list} == {"django", "flask"}


def test_prewarm_swallows_search_failures():
    components = [Component(name="broken", version="1.0", ecosystem="PyPI", source="t")]
    with patch.object(mcp_server.cpe_dictionary, "is_cached", return_value=False), \
         patch.object(mcp_server.cpe_dictionary, "search", side_effect=Exception("boom")), \
         patch.object(mcp_server.time, "sleep"):
        mcp_server.prewarm(components, conn="conn")  # must not raise


def test_prewarm_stops_at_time_budget():
    components = [
        Component(name="a", version="1.0", ecosystem="PyPI", source="t"),
        Component(name="b", version="1.0", ecosystem="PyPI", source="t"),
    ]
    with patch.object(mcp_server.cpe_dictionary, "is_cached", return_value=False), \
         patch.object(mcp_server.cpe_dictionary, "search") as mock_search, \
         patch.object(mcp_server.time, "sleep"):
        mcp_server.prewarm(components, conn="conn", budget_seconds=-1)  # already "expired"
    mock_search.assert_not_called()


def test_run_pipeline_trains_and_scans_when_dataset_has_both_classes():
    two_class_df = pd.DataFrame([
        {**{f: 0.0 for f in mcp_server.labeling.FEATURES}, "label_real_match": True},
        {**{f: 1.0 for f in mcp_server.labeling.FEATURES}, "label_real_match": False},
    ])
    components = [Component(name="django", version="2.2.0", ecosystem="PyPI", source="t")]
    sentinel_result = ScanResult()
    with patch.object(mcp_server.labeling, "build_dataset", return_value=two_class_df), \
         patch.object(mcp_server.model, "train_and_compare"), \
         patch.object(mcp_server.model, "load_winning_model", return_value=("random_forest", MagicMock(), 0.5)), \
         patch.object(mcp_server.explain, "make_explainer", return_value=MagicMock()), \
         patch.object(mcp_server.agent, "scan", return_value=sentinel_result) as mock_scan:
        result = mcp_server.run_pipeline(components, conn="conn")
    assert result is sentinel_result
    mock_scan.assert_called_once()


def test_raw_matches_only_includes_components_with_hits():
    hit = Component(name="babel", version="2.18.0", ecosystem="PyPI", source="t")
    miss = Component(name="quiet-package", version="1.0.0", ecosystem="PyPI", source="t")
    match = {"cve": "CVE-X", "severity": "HIGH", "cvss_score": 7.5, "vendor": "babel"}

    def fake_find(component, conn=None):
        return ([match], []) if component is hit else ([], [])

    with patch.object(mcp_server.matching, "find_candidates", side_effect=fake_find):
        found = mcp_server.raw_matches([hit, miss], conn="conn")
    assert found == [(hit, [match])]


def test_scan_repo_returns_triaged_summary_when_pipeline_succeeds():
    sentinel_result = ScanResult(confirmed=[_finding()])
    with patch.object(mcp_server, "get_connection", return_value="conn"), \
         patch.object(mcp_server, "_ensure_synced"), \
         patch.object(mcp_server, "prewarm"), \
         patch.object(mcp_server, "run_pipeline", return_value=sentinel_result):
        text = mcp_server.scan_repo(lockfile_content=UV_LOCK_TEXT, include_sbom=False)
    assert text.startswith(mcp_server.format_summary(sentinel_result, {
        "scanned": 1, "total": 1, "truncated": False, "max_components": 40,
    }))
    # Every report also records which pipeline stages actually ran, for transparency.
    assert "## Pipeline (what this scan actually ran)" in text


def test_scan_repo_omits_generated_sbom_by_default():
    # Default is False: the SBOM is a full CycloneDX document (one entry per
    # component, tens of KB on a real dependency tree) - not worth the cost on
    # every routine vulnerability check when nobody asked for it.
    with patch.object(mcp_server, "get_connection", return_value="conn"), \
         patch.object(mcp_server, "_ensure_synced"), \
         patch.object(mcp_server, "prewarm"), \
         patch.object(mcp_server, "run_pipeline", return_value=None), \
         patch.object(mcp_server, "raw_matches", return_value=[]):
        text = mcp_server.scan_repo(lockfile_content=UV_LOCK_TEXT)
    assert "Generated SBOM" not in text


def test_scan_repo_includes_generated_sbom_when_requested():
    with patch.object(mcp_server, "get_connection", return_value="conn"), \
         patch.object(mcp_server, "_ensure_synced"), \
         patch.object(mcp_server, "prewarm"), \
         patch.object(mcp_server, "run_pipeline", return_value=None), \
         patch.object(mcp_server, "raw_matches", return_value=[]):
        text = mcp_server.scan_repo(lockfile_content=UV_LOCK_TEXT, include_sbom=True)
    assert "Generated SBOM" in text
    assert '"bomFormat": "CycloneDX"' in text
    assert '"name": "django"' in text


def test_scan_repo_generated_sbom_covers_full_list_not_just_scanned_subset():
    # The SBOM is a bill of materials - it should reflect everything found, even
    # if the vulnerability scan itself is capped by max_components for latency.
    lock = "\n".join(
        f'[[package]]\nname = "pkg{i}"\nversion = "1.0.0"\nsource = {{ registry = "https://pypi.org/simple" }}\n'
        for i in range(5)
    )
    with patch.object(mcp_server, "get_connection", return_value="conn"), \
         patch.object(mcp_server, "_ensure_synced"), \
         patch.object(mcp_server, "prewarm"), \
         patch.object(mcp_server, "run_pipeline", return_value=None), \
         patch.object(mcp_server, "raw_matches", return_value=[]):
        text = mcp_server.scan_repo(lockfile_content=lock, max_components=2, include_sbom=True)
    assert "5 components" in text  # SBOM section header
    for i in range(5):
        assert f'"name": "pkg{i}"' in text


def test_main_runs_streamable_http_transport():
    with patch.object(mcp_server.mcp, "run") as mock_run, \
         patch.object(mcp_server, "startup_banner", return_value="banner"), \
         patch.object(mcp_server, "_start_background_sync") as mock_sync:
        mcp_server.main()
    mock_run.assert_called_once_with(transport="streamable-http")
    mock_sync.assert_called_once()  # NVD/KEV sync kicks off at startup, not on first scan


def test_prewarm_skips_sleep_and_network_for_cached_names():
    components = [Component(name="django", version="2.2.0", ecosystem="PyPI", source="t")]
    with patch.object(mcp_server.cpe_dictionary, "is_cached", return_value=True), \
         patch.object(mcp_server.cpe_dictionary, "search") as mock_search, \
         patch.object(mcp_server.time, "sleep") as mock_sleep:
        mcp_server.prewarm(components, conn="conn")
    mock_search.assert_not_called()
    mock_sleep.assert_not_called()


def test_prewarm_fetches_and_spaces_requests_for_uncached_names():
    components = [Component(name="django", version="2.2.0", ecosystem="PyPI", source="t")]
    with patch.object(mcp_server.cpe_dictionary, "is_cached", return_value=False), \
         patch.object(mcp_server.cpe_dictionary, "search") as mock_search, \
         patch.object(mcp_server.time, "sleep") as mock_sleep:
        mcp_server.prewarm(components, conn="conn")
    mock_search.assert_called_once()
    mock_sleep.assert_called_once()


def test_detect_reachable_host_returns_an_ip_on_success():
    with patch.object(mcp_server.socket, "socket") as mock_socket_cls:
        mock_sock = mock_socket_cls.return_value
        mock_sock.getsockname.return_value = ("192.168.1.42", 54321)
        host = mcp_server._detect_reachable_host()
    assert host == "192.168.1.42"
    mock_sock.close.assert_called_once()


def test_detect_reachable_host_returns_none_on_failure():
    with patch.object(mcp_server.socket, "socket", side_effect=OSError("no network")):
        assert mcp_server._detect_reachable_host() is None


def test_startup_banner_prefers_explicit_public_host_override():
    with patch.dict("os.environ", {"MCP_PUBLIC_HOST": "scan.mylab.internal"}), \
         patch.object(mcp_server, "_detect_reachable_host", return_value="10.0.0.5"):
        banner = mcp_server.startup_banner("0.0.0.0", 8765)
    assert "http://scan.mylab.internal:8765/mcp" in banner
    assert "10.0.0.5" not in banner


def test_startup_banner_auto_detects_when_host_is_wildcard():
    with patch.dict("os.environ", {}, clear=True), \
         patch.object(mcp_server, "_detect_reachable_host", return_value="10.0.0.5"):
        banner = mcp_server.startup_banner("0.0.0.0", 8765)
    assert "http://10.0.0.5:8765/mcp" in banner
    assert '"type": "streamableHttp"' in banner


def test_startup_banner_includes_auto_approve_for_scan_repo():
    with patch.dict("os.environ", {}, clear=True), \
         patch.object(mcp_server, "_detect_reachable_host", return_value="10.0.0.5"):
        banner = mcp_server.startup_banner("0.0.0.0", 8765)
    expected_config = json.dumps(
        {"mcpServers": {"it-security-agent": {
            "type": "streamableHttp", "url": "http://10.0.0.5:8765/mcp",
            "timeout": 300,
            "autoApprove": ["get_scan_command", "condense_lockfile", "scan_repo"],
        }}},
        indent=2,
    )
    assert expected_config in banner
    assert '"timeout": 300' in banner


def test_startup_banner_uses_explicit_host_directly_when_not_wildcard():
    with patch.dict("os.environ", {}, clear=True), \
         patch.object(mcp_server, "_detect_reachable_host") as mock_detect:
        banner = mcp_server.startup_banner("192.168.1.9", 8765)
    assert "http://192.168.1.9:8765/mcp" in banner
    mock_detect.assert_not_called()  # host is already a real address - no need to guess


def test_startup_banner_warns_when_detection_fails():
    with patch.dict("os.environ", {}, clear=True), \
         patch.object(mcp_server, "_detect_reachable_host", return_value=None):
        banner = mcp_server.startup_banner("0.0.0.0", 8765)
    assert "MCP_PUBLIC_HOST" in banner
    assert "http://" not in banner


def test_scan_repo_requires_lockfile_content():
    with pytest.raises(ValueError, match="No lockfile content"):
        mcp_server.scan_repo()


def test_scan_repo_rejects_sbom_content_as_an_unknown_argument():
    # This is the tamper-proofing guarantee: there is no code path that lets a
    # caller hand over a pre-made SBOM and have it trusted directly - the
    # parameter doesn't exist. This would fail with TypeError, not silently
    # accept a spoofable input.
    with pytest.raises(TypeError):
        mcp_server.scan_repo(sbom_content="{}")


def test_scan_repo_reports_when_nothing_parses():
    # Well-formed but empty package-lock.json - a real "nothing to scan" case, not an error.
    result = mcp_server.scan_repo(lockfile_content=json.dumps({"packages": {"": {}}}))
    assert "No components could be parsed" in result


def test_scan_repo_truncates_to_max_components():
    lock = "\n".join(
        f'[[package]]\nname = "pkg{i}"\nversion = "1.0.0"\nsource = {{ registry = "https://pypi.org/simple" }}\n'
        for i in range(5)
    )
    with patch.object(mcp_server, "get_connection", return_value="conn"), \
         patch.object(mcp_server, "_ensure_synced"), \
         patch.object(mcp_server, "prewarm"), \
         patch.object(mcp_server, "run_pipeline", return_value=None), \
         patch.object(mcp_server, "raw_matches", return_value=[]) as mock_raw:
        mcp_server.scan_repo(lockfile_content=lock, max_components=2)
    scanned_components = mock_raw.call_args[0][0]
    assert len(scanned_components) == 2


def test_run_pipeline_returns_none_when_dataset_has_a_single_class():
    import pandas as pd
    single_class_df = pd.DataFrame([{**{f: 0.0 for f in mcp_server.labeling.FEATURES}, "label_real_match": True}])
    with patch.object(mcp_server.labeling, "build_dataset", return_value=single_class_df):
        result = mcp_server.run_pipeline([Component(name="x", version="1.0", ecosystem="PyPI", source="t")], conn=None)
    assert result is None


def _finding(cve="CVE-2024-0001", confidence=0.9, explanation=None):
    component = Component(name="django", version="2.2.0", ecosystem="PyPI", source="test")
    return Finding(component=component, cve=cve, severity="HIGH", cvss_score=7.5,
                    confidence=confidence, corroboration="osv_disagrees", explanation=explanation)


FULL_CACHE = {"cves": 365_000, "kev": 1_600, "fraction": 0.99, "thin": False}
THIN_CACHE = {"cves": 42_055, "kev": 1_600, "fraction": 0.11, "thin": True}


def _meta(cache=None, **over):
    meta = {"scanned": 1, "total": 1, "truncated": False, "max_components": 40}
    if cache is not None:
        meta["cache"] = cache
    return {**meta, **over}


def test_format_summary_leads_with_a_yes_or_no_verdict():
    found = mcp_server.format_summary(ScanResult(confirmed=[_finding()]), _meta(FULL_CACHE))
    assert "VULNERABILITIES FOUND: 1" in found

    clean = mcp_server.format_summary(ScanResult(), _meta(FULL_CACHE))
    assert "NO VULNERABILITIES FOUND" in clean


def test_format_summary_distinguishes_clean_from_undecided():
    # "nothing confirmed" and "nothing found" are different answers - a review queue
    # means the scan reached no conclusion, not that the components are clean.
    text = mcp_server.format_summary(ScanResult(review_queue=[_finding()]), _meta(FULL_CACHE))
    assert "NO CONFIRMED VULNERABILITIES" in text
    assert "need human review" in text
    assert "NO VULNERABILITIES FOUND" not in text


def test_clean_result_on_a_thin_cache_is_not_reported_as_clean():
    # The dangerous failure mode: a partial NVD sync produces an empty report rather
    # than an error. The report must say so instead of implying a clean bill of health.
    text = mcp_server.format_summary(ScanResult(), _meta(THIN_CACHE))
    assert "not a clean bill of health" in text
    assert "11%" in text
    assert "warm_cache.py --full" in text


def test_clean_result_on_a_full_cache_carries_no_coverage_warning():
    text = mcp_server.format_summary(ScanResult(), _meta(FULL_CACHE))
    assert "not a clean bill of health" not in text
    assert "365,000 cached CVEs" in text


def test_findings_on_a_thin_cache_are_marked_a_lower_bound():
    text = mcp_server.format_summary(ScanResult(confirmed=[_finding()]), _meta(THIN_CACHE))
    assert "lower bound" in text
    assert "not a clean bill of health" not in text  # findings exist; the caveat differs


def test_a_suspected_collision_does_not_get_remediation_advice():
    # "upgrade click past 8.4.2" to fix an Ubuntu-phone CVE points at the wrong software.
    f = _finding(cve="CVE-2015-8768")
    f.vendor_conflict = True
    text = mcp_server.format_summary(ScanResult(review_queue=[f]), _meta(FULL_CACHE))
    assert "check first whether this CVE is about" in text
    assert "**Fix:** upgrade" not in text


def test_a_gate_demoted_finding_is_not_described_as_hesitation():
    # The vendor gate demotes findings the model scored *above* threshold, so labelling
    # their SHAP values "why the model hesitated" would misdescribe the decision.
    f = _finding(cve="CVE-X", explanation={"name_similarity": 0.46})
    f.model_confident, f.vendor_conflict = True, True
    text = mcp_server.format_summary(ScanResult(review_queue=[f]), _meta(FULL_CACHE))
    assert "What drove the model's score" in text
    assert "Why the model hesitated" not in text

    unsure = _finding(cve="CVE-Y", explanation={"name_similarity": 0.1})
    unsure.model_confident = False
    text = mcp_server.format_summary(ScanResult(review_queue=[unsure]), _meta(FULL_CACHE))
    assert "Why the model hesitated" in text


def test_review_queue_blurb_covers_both_reasons_a_finding_lands_there():
    text = mcp_server.format_summary(ScanResult(review_queue=[_finding()]), _meta(FULL_CACHE))
    assert "wasn't confident enough" in text
    assert "likely name collision" in text


def test_format_summary_states_the_flagging_policy():
    text = mcp_server.format_summary(ScanResult(confirmed=[_finding()]), _meta(
        FULL_CACHE, model={"name": "random_forest", "threshold": 0.15,
                           "training_rows": 26856, "features": 7}))
    assert "## How these were flagged" in text
    assert "random_forest" in text and "0.15" in text
    assert "26,856" in text
    assert f"{mcp_server.model.FN_WEIGHT}x a false alarm" in text
    for bucket in ("escalated", "confirmed", "review_queue", "rejected"):
        assert f"**{bucket}**" in text


def test_format_summary_without_cache_metadata_makes_no_coverage_claim():
    # Callers that don't supply coverage (older callers, tests) must get a report that
    # simply omits the claim rather than one that implies full coverage.
    text = mcp_server.format_summary(ScanResult(), _meta())
    assert "Searched a local NVD cache" not in text
    assert "NO VULNERABILITIES FOUND" in text


def test_format_summary_includes_escalated_and_review_queue_sections():
    result = ScanResult(
        escalated=[_finding(cve="CVE-ESCALATED")],
        confirmed=[_finding(cve="CVE-CONFIRMED")],
        review_queue=[_finding(cve="CVE-REVIEW", explanation={"name_similarity": 0.9, "keyword_alignment": -0.5})],
        rejected=[],
    )
    meta = {"scanned": 3, "total": 3, "truncated": False, "max_components": 40}
    text = mcp_server.format_summary(result, meta)
    assert "CVE-ESCALATED" in text
    assert "CVE-CONFIRMED" in text
    assert "CVE-REVIEW" in text
    assert "top SHAP factors" in text
    assert "Scanned" not in text  # not truncated, so no truncation note


def test_format_summary_explains_findings_in_both_plain_and_technical_terms():
    f = _finding(cve="CVE-2019-19844")
    f.severity = "CRITICAL"
    f.cvss_score = 9.8
    f.kev_hit = True
    f.cwe_ids = ["CWE-640", "CWE-79"]
    f.vendor = "djangoproject"
    f.description = "Django before 1.11.27 allows account takeover via a crafted password reset."
    text = mcp_server.format_summary(ScanResult(escalated=[f]), {
        "scanned": 1, "total": 1, "truncated": False, "max_components": 40,
    })

    # Layman's layer: what it means and what to do, without jargon.
    assert "**What this means:**" in text
    assert "exploiting this right now" in text  # KEV status in plain words
    assert "as severe as vulnerabilities get" in text  # 9.8 explained, not just printed
    # The plain-English line explains the primary (first) weakness; all of them still
    # appear in the technical "Weakness type" line below.
    assert "'forgot password' flow can be abused" in text  # CWE-640 in plain words
    assert "**Fix:**" in text

    # Technical layer: the specifics a practitioner needs.
    assert "CVSS 9.8/10" in text
    assert "Cross-site Scripting (XSS)" in text  # CWE technical name
    assert "cwe.mitre.org/data/definitions/79.html" in text  # and a link to the definition
    assert "djangoproject" in text  # which NVD vendor matched
    assert "Django before 1.11.27" in text  # verbatim NVD description
    assert "https://nvd.nist.gov/vuln/detail/CVE-2019-19844" in text


def test_format_summary_handles_findings_with_no_enrichment_data():
    # Older/rejected findings can lack description, CWEs and score entirely - the
    # report must still render rather than blowing up on a missing field.
    f = _finding(cve="CVE-BARE")
    f.cvss_score = None
    f.cwe_ids = []
    f.description = ""
    f.vendor = ""
    text = mcp_server.format_summary(ScanResult(confirmed=[f]), {
        "scanned": 1, "total": 1, "truncated": False, "max_components": 40,
    })
    assert "CVE-BARE" in text
    assert "hasn't published a severity score" in text


def test_format_summary_truncates_very_long_nvd_descriptions():
    f = _finding(cve="CVE-LONG")
    f.description = "x" * 2000
    text = mcp_server.format_summary(ScanResult(confirmed=[f]), {
        "scanned": 1, "total": 1, "truncated": False, "max_components": 40,
    })
    assert "truncated - see the NVD link" in text
    # Assert against the description itself rather than the report's total length: the
    # report carries fixed explanatory sections (verdict, flagging policy) whose size is
    # unrelated to whether this field was cut.
    assert "x" * 900 in text
    assert "x" * 901 not in text


def test_format_summary_notes_truncation():
    result = ScanResult()
    meta = {"scanned": 2, "total": 10, "truncated": True, "max_components": 2}
    text = mcp_server.format_summary(result, meta)
    assert "Scanned 2 of 10" in text


def test_format_raw_matches_warns_it_is_untriaged():
    component = Component(name="babel", version="2.18.0", ecosystem="PyPI", source="test")
    found = [(component, [{"cve": "CVE-X", "severity": "HIGH", "cvss_score": 7.5, "vendor": "babel"}])]
    meta = {"scanned": 1, "total": 1, "truncated": False, "max_components": 40}
    text = mcp_server.format_raw_matches(found, meta)
    assert "Not enough labeled data" in text
    assert "CVE-X" in text


def test_format_raw_matches_empty_on_a_thin_cache_is_not_reported_as_clean():
    # The untriaged fallback reports emptiness for the same reason the triaged path can -
    # an incomplete cache - so it must carry the same caveat rather than reading clean.
    text = mcp_server.format_raw_matches([], _meta(THIN_CACHE))
    assert "not a clean bill of health" in text
    assert "No name+version matches found" in text

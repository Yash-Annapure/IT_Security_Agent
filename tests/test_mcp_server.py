import json
import time
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

from it_security_agent import mcp_server
from it_security_agent.agent import Finding, ScanResult
from it_security_agent.schema import Component

SPDX_TEXT = json.dumps({
    "spdxVersion": "SPDX-2.3",
    "packages": [
        {"name": "requests", "versionInfo": "2.31.0",
         "externalRefs": [{"referenceType": "purl", "referenceLocator": "pkg:pypi/requests@2.31.0"}]},
        {"name": "unresolvable-package", "versionInfo": "1.0.0", "externalRefs": []},
    ],
})

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

CYCLONEDX_TEXT = json.dumps({
    "bomFormat": "CycloneDX",
    "components": [{"name": "axios", "version": "0.21.0", "purl": "pkg:npm/axios@0.21.0"}],
})


def test_parse_components_detects_uv_lock_by_content():
    components = mcp_server.parse_components(lockfile_content=UV_LOCK_TEXT)
    assert [c.name for c in components] == ["django"]
    assert components[0].ecosystem == "PyPI"


def test_parse_components_detects_requirements_txt_by_content():
    # No "{" (not JSON) and no "[[package]]" (not uv.lock TOML) - falls back to
    # requirements.txt, the only remaining plain-text lockfile format supported.
    components = mcp_server.parse_components(lockfile_content="django==2.2.0\nflask>=1.0\n")
    assert [c.name for c in components] == ["django"]


def test_parse_components_detects_package_lock_by_content():
    components = mcp_server.parse_components(lockfile_content=PACKAGE_LOCK_TEXT)
    assert [c.name for c in components] == ["lodash"]
    assert components[0].ecosystem == "npm"


def test_parse_components_detects_cyclonedx_sbom():
    components = mcp_server.parse_components(sbom_content=CYCLONEDX_TEXT)
    assert [c.name for c in components] == ["axios"]


def test_parse_components_combines_lockfile_and_sbom():
    components = mcp_server.parse_components(lockfile_content=UV_LOCK_TEXT, sbom_content=CYCLONEDX_TEXT)
    assert {c.name for c in components} == {"django", "axios"}


def test_parse_components_rejects_unknown_lockfile_type():
    with pytest.raises(ValueError):
        mcp_server.parse_components(lockfile_content=UV_LOCK_TEXT, lockfile_type="Pipfile.lock")


def test_parse_components_detects_spdx_sbom():
    # SPDX has no "bomFormat" key - that's what parse_components uses to tell it apart
    # from CycloneDX. Only the package with a purl should come through.
    components = mcp_server.parse_components(sbom_content=SPDX_TEXT)
    assert [c.name for c in components] == ["requests"]


def test_parse_components_rejects_unknown_sbom_format():
    with pytest.raises(ValueError):
        mcp_server.parse_components(sbom_content=CYCLONEDX_TEXT, sbom_format="cdx-json")


def test_bounded_get_sets_a_20s_timeout():
    with patch.object(mcp_server.requests, "get", return_value="response") as mock_get:
        result = mcp_server._bounded_get("http://example.test", headers={})
    assert result == "response"
    assert mock_get.call_args.kwargs["timeout"] == 20


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
    with patch.object(mcp_server.cpe_dictionary, "search") as mock_search, \
         patch.object(mcp_server.time, "sleep"):
        mcp_server.prewarm(components, conn="conn")
    assert {call.args[0] for call in mock_search.call_args_list} == {"django", "flask"}


def test_prewarm_swallows_search_failures():
    components = [Component(name="broken", version="1.0", ecosystem="PyPI", source="t")]
    with patch.object(mcp_server.cpe_dictionary, "search", side_effect=Exception("boom")), \
         patch.object(mcp_server.time, "sleep"):
        mcp_server.prewarm(components, conn="conn")  # must not raise


def test_prewarm_stops_at_time_budget():
    components = [
        Component(name="a", version="1.0", ecosystem="PyPI", source="t"),
        Component(name="b", version="1.0", ecosystem="PyPI", source="t"),
    ]
    with patch.object(mcp_server.cpe_dictionary, "search") as mock_search, \
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
    assert text == mcp_server.format_summary(sentinel_result, {
        "scanned": 1, "total": 1, "truncated": False, "max_components": 40,
    })


def test_scan_repo_includes_generated_sbom_by_default():
    with patch.object(mcp_server, "get_connection", return_value="conn"), \
         patch.object(mcp_server, "_ensure_synced"), \
         patch.object(mcp_server, "prewarm"), \
         patch.object(mcp_server, "run_pipeline", return_value=None), \
         patch.object(mcp_server, "raw_matches", return_value=[]):
        text = mcp_server.scan_repo(lockfile_content=UV_LOCK_TEXT)
    assert "Generated SBOM" in text
    assert '"bomFormat": "CycloneDX"' in text
    assert '"name": "django"' in text


def test_scan_repo_can_omit_generated_sbom():
    with patch.object(mcp_server, "get_connection", return_value="conn"), \
         patch.object(mcp_server, "_ensure_synced"), \
         patch.object(mcp_server, "prewarm"), \
         patch.object(mcp_server, "run_pipeline", return_value=None), \
         patch.object(mcp_server, "raw_matches", return_value=[]):
        text = mcp_server.scan_repo(lockfile_content=UV_LOCK_TEXT, include_sbom=False)
    assert "Generated SBOM" not in text


def test_scan_repo_does_not_generate_sbom_from_existing_sbom_input():
    # sbom_content is already an SBOM - nothing to generate.
    with patch.object(mcp_server, "get_connection", return_value="conn"), \
         patch.object(mcp_server, "_ensure_synced"), \
         patch.object(mcp_server, "prewarm"), \
         patch.object(mcp_server, "run_pipeline", return_value=None), \
         patch.object(mcp_server, "raw_matches", return_value=[]):
        text = mcp_server.scan_repo(sbom_content=CYCLONEDX_TEXT)
    assert "Generated SBOM" not in text


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
        text = mcp_server.scan_repo(lockfile_content=lock, max_components=2)
    assert "5 components" in text  # SBOM section header
    for i in range(5):
        assert f'"name": "pkg{i}"' in text


def test_main_runs_streamable_http_transport():
    with patch.object(mcp_server.mcp, "run") as mock_run:
        mcp_server.main()
    mock_run.assert_called_once_with(transport="streamable-http")


def test_scan_repo_requires_at_least_one_input():
    with pytest.raises(ValueError):
        mcp_server.scan_repo()


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
    assert "top factors:" in text
    assert "Scanned" not in text  # not truncated, so no truncation note


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

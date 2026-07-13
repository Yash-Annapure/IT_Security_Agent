from pathlib import Path

from it_security_agent import repo_scan

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_uv_lock_excludes_virtual_project_package():
    components = repo_scan.parse_uv_lock(FIXTURES / "sample_uv.lock")
    names = {c.name for c in components}
    assert "it-security-agent" not in names
    assert names == {"requests", "urllib3"}


def test_parse_uv_lock_sets_exact_pinned_version():
    components = repo_scan.parse_uv_lock(FIXTURES / "sample_uv.lock")
    requests_component = next(c for c in components if c.name == "requests")
    assert requests_component.version == "2.31.0"
    assert requests_component.ecosystem == "PyPI"


def test_parse_package_lock_excludes_root_package():
    components = repo_scan.parse_package_lock(FIXTURES / "sample_package-lock.json")
    names = {c.name for c in components}
    assert "sample-project" not in names
    assert names == {"lodash", "axios"}


def test_parse_package_lock_sets_ecosystem_npm():
    components = repo_scan.parse_package_lock(FIXTURES / "sample_package-lock.json")
    lodash = next(c for c in components if c.name == "lodash")
    assert lodash.ecosystem == "npm"
    assert lodash.version == "4.17.21"

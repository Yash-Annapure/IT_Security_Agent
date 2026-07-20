import pytest

from it_security_agent import generate_sbom


def test_discover_components_reads_uv_lock(tmp_path):
    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname = "django"\nversion = "2.2.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
    )
    components = generate_sbom.discover_components(tmp_path)
    assert [c.name for c in components] == ["django"]


def test_discover_components_prefers_uv_lock_over_requirements_txt(tmp_path):
    # Order matters (DETECTORS): a repo with both should get the more precisely
    # pinned uv.lock's components, plus whatever requirements.txt adds - not
    # one replacing the other, since a repo can genuinely have both.
    (tmp_path / "uv.lock").write_text(
        '[[package]]\nname = "django"\nversion = "2.2.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
    )
    (tmp_path / "requirements.txt").write_text("flask==2.1.0\n")
    components = generate_sbom.discover_components(tmp_path)
    assert {c.name for c in components} == {"django", "flask"}


def test_discover_components_empty_dir_returns_nothing(tmp_path):
    assert generate_sbom.discover_components(tmp_path) == []


def test_generate_sbom_builds_cyclonedx_from_repo_files(tmp_path):
    (tmp_path / "requirements.txt").write_text("requests==2.31.0\n")
    bom = generate_sbom.generate_sbom(tmp_path, bom_version="9.9.9")
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["metadata"]["component"]["version"] == "9.9.9"
    assert [c["name"] for c in bom["components"]] == ["requests"]


def test_generate_sbom_defaults_bom_name_to_directory_name(tmp_path):
    repo_dir = tmp_path / "my-cool-repo"
    repo_dir.mkdir()
    (repo_dir / "requirements.txt").write_text("requests==2.31.0\n")
    bom = generate_sbom.generate_sbom(repo_dir)
    assert bom["metadata"]["component"]["name"] == "my-cool-repo"


def test_generate_sbom_raises_when_nothing_found(tmp_path):
    with pytest.raises(ValueError, match="no supported dependency files"):
        generate_sbom.generate_sbom(tmp_path)

import json
from pathlib import Path

from it_security_agent import sbom

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_cyclonedx_maps_components_with_purl():
    data = json.loads((FIXTURES / "sample_cyclonedx.json").read_text())
    components = sbom.parse_cyclonedx(data)
    names = {c.name for c in components}
    assert names == {"requests", "lodash"}
    requests_component = next(c for c in components if c.name == "requests")
    assert requests_component.ecosystem == "PyPI"
    assert requests_component.version == "2.31.0"


def test_parse_cyclonedx_skips_components_without_purl():
    data = json.loads((FIXTURES / "sample_cyclonedx.json").read_text())
    components = sbom.parse_cyclonedx(data)
    assert "no-purl-component" not in {c.name for c in components}


def test_parse_spdx_uses_external_ref_purl():
    data = json.loads((FIXTURES / "sample_spdx.json").read_text())
    components, unparsed = sbom.parse_spdx(data)
    assert len(components) == 1
    assert components[0].name == "requests"
    assert components[0].ecosystem == "PyPI"


def test_parse_spdx_counts_packages_without_purl_as_unparsed():
    data = json.loads((FIXTURES / "sample_spdx.json").read_text())
    _, unparsed = sbom.parse_spdx(data)
    assert unparsed == 1


def _sample_components():
    from it_security_agent.schema import Component
    return [
        Component(name="django", version="2.2.0", ecosystem="PyPI", source="test"),
        Component(name="lodash", version="4.17.21", ecosystem="npm", source="test"),
    ]


def test_to_cyclonedx_produces_a_valid_bom_shape():
    bom = sbom.to_cyclonedx(_sample_components(), bom_name="my-repo", bom_version="1.2.3")
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] == sbom.CYCLONEDX_SPEC_VERSION
    assert bom["metadata"]["component"] == {"type": "application", "name": "my-repo", "version": "1.2.3"}
    assert {c["name"] for c in bom["components"]} == {"django", "lodash"}
    assert all(c["purl"] for c in bom["components"])


def test_to_cyclonedx_round_trips_through_parse_cyclonedx():
    original = _sample_components()
    bom = sbom.to_cyclonedx(original)
    parsed = sbom.parse_cyclonedx(bom)
    assert {(c.name, c.version, c.ecosystem) for c in parsed} == \
        {(c.name, c.version, c.ecosystem) for c in original}


def test_write_cyclonedx_writes_valid_json_to_disk(tmp_path):
    out_path = tmp_path / "nested" / "sbom.json"
    bom = sbom.write_cyclonedx(_sample_components(), out_path, bom_name="my-repo")
    on_disk = json.loads(out_path.read_text())
    assert on_disk == bom
    assert on_disk["metadata"]["component"]["name"] == "my-repo"

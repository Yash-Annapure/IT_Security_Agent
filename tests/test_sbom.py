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

import json

import pytest

from condense_lockfile import condense
from it_security_agent.mcp_server import parse_lockfile_components

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
        "node_modules/express": {"version": "4.18.2"},
    }
})


def test_condense_uv_lock_round_trips_to_the_same_components():
    condensed = condense(UV_LOCK_TEXT)
    assert condensed == "django==2.2.0"
    components = parse_lockfile_components(condensed)
    assert [(c.name, c.version, c.ecosystem) for c in components] == [("django", "2.2.0", "PyPI")]


def test_condense_package_lock_round_trips_to_the_same_components():
    condensed = condense(PACKAGE_LOCK_TEXT)
    original = parse_lockfile_components(PACKAGE_LOCK_TEXT)
    round_tripped = parse_lockfile_components(condensed)
    assert {(c.name, c.version, c.ecosystem) for c in round_tripped} == \
        {(c.name, c.version, c.ecosystem) for c in original}


def test_condense_is_dramatically_smaller_than_the_original():
    condensed = condense(UV_LOCK_TEXT)
    assert len(condensed) < len(UV_LOCK_TEXT)


def test_condense_raises_clearly_when_nothing_parses():
    with pytest.raises(ValueError, match="No components parsed"):
        condense('{"packages": {"": {}}}')

from it_security_agent.schema import Component, build_purl


def test_build_purl_known_ecosystem():
    assert build_purl("PyPI", "requests", "2.31.0") == "pkg:pypi/requests@2.31.0"


def test_build_purl_unknown_ecosystem_falls_back_to_lowercase():
    assert build_purl("Nuget", "Foo", "1.0.0") == "pkg:nuget/Foo@1.0.0"


def test_component_auto_builds_purl():
    c = Component(name="requests", version="2.31.0", ecosystem="PyPI", source="test")
    assert c.purl == "pkg:pypi/requests@2.31.0"


def test_component_keeps_explicit_purl():
    c = Component(name="foo", version="1.0", ecosystem="Debian", source="test",
                   purl="pkg:deb/debian/foo@1.0")
    assert c.purl == "pkg:deb/debian/foo@1.0"

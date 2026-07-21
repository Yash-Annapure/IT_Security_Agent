from unittest.mock import patch

from it_security_agent import matching, nvd_cache
from it_security_agent.normalize import VendorCandidate
from it_security_agent.schema import Component


def _cve(cve_id, vendor, product, version_field="1.0.0", metrics=None):
    return {
        "cve": {
            "id": cve_id,
            "descriptions": [{"lang": "en", "value": "A test vulnerability"}],
            "metrics": metrics or {"cvssMetricV31": [{"baseSeverity": "HIGH", "cvssData": {"baseScore": 7.5}}]},
            "weaknesses": [],
            "configurations": [{"nodes": [{"cpeMatch": [
                {"criteria": f"cpe:2.3:a:{vendor}:{product}:{version_field}:*:*:*:*:*:*:*", "vulnerable": True}
            ]}]}],
        }
    }


def test_find_candidates_matches_version_and_attaches_vendor_candidate():
    conn = nvd_cache.get_connection(":memory:")
    component = Component(name="django", version="1.0.0", ecosystem="PyPI", source="test")
    candidate = VendorCandidate(vendor="djangoproject", product="django", signals={"vendor_equals_package": 0})
    with patch("it_security_agent.nvd_cache.query_by_product_name",
               return_value=[_cve("CVE-2024-0001", "djangoproject", "django")]), \
         patch("it_security_agent.normalize.resolve_vendor", return_value=[candidate]):
        matches, rejected = matching.find_candidates(component, conn=conn)
    assert len(matches) == 1
    assert matches[0]["cve"] == "CVE-2024-0001"
    assert matches[0]["vendor_candidate"] is candidate
    assert rejected == []


def test_find_candidates_reports_which_vendors_the_registry_backs():
    # A vendor can appear with several CPE entries, only some carrying registry_overlap.
    # The trusted set must be built from the full candidate list - deduplicating by vendor
    # first would drop the overlap whenever a non-overlapping entry happened to come last.
    conn = nvd_cache.get_connection(":memory:")
    component = Component(name="jupyter", version="1.0.0", ecosystem="PyPI", source="test")
    backed = VendorCandidate(vendor="jupyter", product="jupyter", signals={"registry_overlap": True})
    same_vendor_no_overlap = VendorCandidate(vendor="jupyter", product="jupyter",
                                             signals={"registry_overlap": False})
    other = VendorCandidate(vendor="microsoft", product="jupyter", signals={"registry_overlap": False})
    with patch("it_security_agent.nvd_cache.query_by_product_name",
               return_value=[_cve("CVE-2024-0001", "microsoft", "jupyter")]), \
         patch("it_security_agent.normalize.resolve_vendor",
               return_value=[backed, same_vendor_no_overlap, other]):
        matches, _ = matching.find_candidates(component, conn=conn)
    assert matches[0]["registry_trusted_vendors"] == frozenset({"jupyter"})
    assert matches[0]["vendor"] == "microsoft"  # the CVE matched a vendor the registry contradicts


def test_find_candidates_rejects_when_version_does_not_apply():
    conn = nvd_cache.get_connection(":memory:")
    component = Component(name="django", version="9.9.9", ecosystem="PyPI", source="test")
    with patch("it_security_agent.nvd_cache.query_by_product_name",
               return_value=[_cve("CVE-2024-0001", "djangoproject", "django", version_field="1.0.0")]), \
         patch("it_security_agent.normalize.resolve_vendor", return_value=[]):
        matches, rejected = matching.find_candidates(component, conn=conn)
    assert matches == []
    assert rejected == ["CVE-2024-0001"]


def test_known_collision_babel_stays_a_collision():
    # Regression case from Week 2: babel (PyPI, our package) collides with babeljs (npm).
    # normalize.resolve_vendor returning no candidate for the collision vendor means
    # find_candidates cannot attach a vendor_candidate, so it can never become "confirmed".
    conn = nvd_cache.get_connection(":memory:")
    component = Component(name="babel", version="2.18.0", ecosystem="PyPI", source="test")
    with patch("it_security_agent.nvd_cache.query_by_product_name",
               return_value=[_cve("CVE-2024-0002", "babeljs", "babel", version_field="2.18.0")]), \
         patch("it_security_agent.normalize.resolve_vendor", return_value=[]):
        matches, rejected = matching.find_candidates(component, conn=conn)
    assert len(matches) == 1
    assert matches[0]["vendor_candidate"] is None


def test_version_applies_exact_version():
    m = {"criteria": "cpe:2.3:a:vendor:product:1.0.0:*:*:*:*:*:*:*", "vulnerable": True}
    assert matching.version_applies(m, matching.parse_version("1.0.0")) is True
    assert matching.version_applies(m, matching.parse_version("2.0.0")) is False


def test_version_applies_range():
    m = {
        "criteria": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*", "vulnerable": True,
        "versionStartIncluding": "1.0.0", "versionEndExcluding": "2.0.0",
    }
    assert matching.version_applies(m, matching.parse_version("1.5.0")) is True
    assert matching.version_applies(m, matching.parse_version("2.0.0")) is False

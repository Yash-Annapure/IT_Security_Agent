from unittest.mock import MagicMock, patch

from it_security_agent import agent
from it_security_agent.normalize import VendorCandidate
from it_security_agent.schema import Component


def _match(cve="CVE-2024-0001", vendor_candidate=None):
    return {"cve": cve, "severity": "HIGH", "cvss_score": 7.5, "vendor": "vendor", "vendor_candidate": vendor_candidate}


def _run_scan(component, matches, rejected, osv_vulns, kev_entry, confidence):
    with patch("it_security_agent.matching.find_candidates", return_value=(matches, rejected)), \
         patch("it_security_agent.osv.query", return_value=osv_vulns), \
         patch("it_security_agent.kev.is_kev", return_value=kev_entry), \
         patch("it_security_agent.model.predict_confidence", return_value=confidence), \
         patch("it_security_agent.explain.explain_match", return_value={"name_similarity": 0.1}):
        return agent.scan([component], "random_forest", MagicMock(), 0.7, MagicMock())


def test_high_confidence_confirms_even_when_osv_disagrees():
    # High confidence alone is enough to confirm - but corroboration is still
    # computed and recorded (for the OSV agreement-rate report), not skipped.
    component = Component(name="django", version="2.2.0", ecosystem="PyPI", source="test")
    candidate = VendorCandidate(vendor="djangoproject", product="django", signals={})
    result = _run_scan(component, [_match(vendor_candidate=candidate)], [], osv_vulns=[], kev_entry=None, confidence=0.9)
    assert len(result.confirmed) == 1
    assert result.confirmed[0].corroboration == "osv_disagrees"


def test_high_confidence_non_osv_ecosystem_is_not_checked():
    component = Component(name="openssl", version="3.0.2", ecosystem="Debian", source="test")
    candidate = VendorCandidate(vendor="openssl", product="openssl", signals={})
    result = _run_scan(component, [_match(vendor_candidate=candidate)], [], osv_vulns=[], kev_entry=None, confidence=0.9)
    assert len(result.confirmed) == 1
    assert result.confirmed[0].corroboration == "not_checked"


def test_low_confidence_osv_agrees_confirms():
    component = Component(name="lodash", version="4.17.15", ecosystem="npm", source="test")
    candidate = VendorCandidate(vendor="lodash", product="lodash", signals={})
    result = _run_scan(component, [_match(vendor_candidate=candidate)], [], osv_vulns=[{"id": "GHSA-x"}], kev_entry=None, confidence=0.3)
    assert len(result.confirmed) == 1
    assert result.confirmed[0].corroboration == "osv_agrees"


def test_low_confidence_osv_disagrees_goes_to_review_queue():
    component = Component(name="lodash", version="4.17.15", ecosystem="npm", source="test")
    candidate = VendorCandidate(vendor="lodash", product="lodash", signals={})
    result = _run_scan(component, [_match(vendor_candidate=candidate)], [], osv_vulns=[], kev_entry=None, confidence=0.3)
    assert len(result.review_queue) == 1
    assert result.review_queue[0].corroboration == "osv_disagrees"
    assert result.review_queue[0].explanation is not None


def test_low_confidence_not_checked_goes_to_review_queue():
    component = Component(name="openssl", version="3.0.2", ecosystem="Debian", source="test")
    candidate = VendorCandidate(vendor="openssl", product="openssl", signals={})
    result = _run_scan(component, [_match(vendor_candidate=candidate)], [], osv_vulns=[], kev_entry=None, confidence=0.3)
    assert len(result.review_queue) == 1
    assert result.review_queue[0].corroboration == "not_checked"


def test_kev_hit_escalates_instead_of_confirms():
    component = Component(name="django", version="2.2.0", ecosystem="PyPI", source="test")
    candidate = VendorCandidate(vendor="djangoproject", product="django", signals={})
    result = _run_scan(component, [_match(vendor_candidate=candidate)], [], osv_vulns=[], kev_entry={"dueDate": "2024-01-01"}, confidence=0.9)
    assert result.confirmed == []
    assert len(result.escalated) == 1
    assert result.escalated[0].kev_hit is True


def test_rejected_findings_are_kept_not_dropped():
    component = Component(name="django", version="2.2.0", ecosystem="PyPI", source="test")
    result = _run_scan(component, [], ["CVE-2024-0002"], osv_vulns=[], kev_entry=None, confidence=0.9)
    assert len(result.rejected) == 1
    assert result.rejected[0].cve == "CVE-2024-0002"

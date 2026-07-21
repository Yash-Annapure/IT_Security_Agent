from unittest.mock import MagicMock, patch

import pandas as pd
from sklearn.ensemble import RandomForestClassifier

from it_security_agent import agent, explain, labeling
from it_security_agent.normalize import VendorCandidate
from it_security_agent.schema import Component


def _match(cve="CVE-2024-0001", vendor_candidate=None):
    return {"cve": cve, "severity": "HIGH", "cvss_score": 7.5, "vendor": "vendor", "vendor_candidate": vendor_candidate}


def _run_scan(component, matches, rejected, osv_vulns, kev_entry, confidence):
    kev_ids = {m["cve"] for m in matches} if kev_entry else set()
    with patch("it_security_agent.matching.find_candidates", return_value=(matches, rejected)), \
         patch("it_security_agent.osv.query", return_value=osv_vulns), \
         patch("it_security_agent.kev.load_kev_ids", return_value=kev_ids), \
         patch("it_security_agent.model.predict_confidence_batch",
               side_effect=lambda m, rows: [confidence] * len(rows)), \
         patch("it_security_agent.explain.explain_matches",
               side_effect=lambda e, rows: [{"name_similarity": 0.1}] * len(rows)):
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


def test_osv_is_queried_once_per_component_not_once_per_match():
    # OSV is keyed on (ecosystem, name, version) - the component - so every candidate CVE
    # for a component shares one answer. Querying per match meant a component whose OSV
    # entry wasn't cached yet made one network round trip per candidate.
    component = Component(name="django", version="2.2.0", ecosystem="PyPI", source="test")
    candidate = VendorCandidate(vendor="djangoproject", product="django", signals={})
    matches = [_match(cve=f"CVE-2024-000{i}", vendor_candidate=candidate) for i in range(5)]
    with patch("it_security_agent.matching.find_candidates", return_value=(matches, [])), \
         patch("it_security_agent.osv.query", return_value=[]) as osv_query, \
         patch("it_security_agent.kev.load_kev_ids", return_value=set()), \
         patch("it_security_agent.model.predict_confidence_batch",
               side_effect=lambda m, rows: [0.9] * len(rows)):
        agent.scan([component], "random_forest", MagicMock(), 0.7, MagicMock())
    assert osv_query.call_count == 1


def test_kev_catalog_is_read_once_per_scan_not_once_per_finding():
    components = [Component(name=f"pkg{i}", version="1.0", ecosystem="PyPI", source="test") for i in range(4)]
    candidate = VendorCandidate(vendor="v", product="p", signals={})
    with patch("it_security_agent.matching.find_candidates",
               return_value=([_match(vendor_candidate=candidate)], [])), \
         patch("it_security_agent.osv.query", return_value=[]), \
         patch("it_security_agent.kev.load_kev_ids", return_value=set()) as load_kev, \
         patch("it_security_agent.kev.is_kev") as is_kev, \
         patch("it_security_agent.model.predict_confidence_batch",
               side_effect=lambda m, rows: [0.9] * len(rows)):
        agent.scan(components, "random_forest", MagicMock(), 0.7, MagicMock())
    assert load_kev.call_count == 1
    assert is_kev.call_count == 0  # the preloaded set replaces per-CVE lookups entirely


def test_triage_component_still_works_standalone_without_a_preloaded_kev_set():
    # The notebook triages single components directly; that path must keep working and
    # must still detect KEV membership, falling back to per-CVE lookups.
    component = Component(name="django", version="2.2.0", ecosystem="PyPI", source="test")
    candidate = VendorCandidate(vendor="djangoproject", product="django", signals={})
    with patch("it_security_agent.matching.find_candidates",
               return_value=([_match(vendor_candidate=candidate)], [])), \
         patch("it_security_agent.osv.query", return_value=[]), \
         patch("it_security_agent.kev.is_kev", return_value={"dueDate": "2024-01-01"}), \
         patch("it_security_agent.model.predict_confidence_batch", side_effect=lambda m, rows: [0.9]):
        result = agent.triage_component(component, "random_forest", MagicMock(), 0.7, MagicMock())
    assert len(result.escalated) == 1
    assert result.escalated[0].kev_hit is True


def test_review_queue_uses_real_explainer_over_labeling_features():
    # Regression guard: the review-queue branch must feed predict_confidence and
    # explain_match a vector matching labeling.FEATURES exactly (no registry_overlap
    # leaking in, ecosystem_pypi/osv_corroborated present). Drive it with a real
    # fitted model + real SHAP explainer so a column mismatch would actually raise.
    X = pd.DataFrame([{f: i % 2 for f in labeling.FEATURES} for i in range(20)])
    y = pd.Series([i % 2 for i in range(20)])
    rf = RandomForestClassifier(n_estimators=10, random_state=0).fit(X, y)
    real_explainer = explain.make_explainer("random_forest", rf, X)

    component = Component(name="lodash", version="4.17.15", ecosystem="npm", source="test")
    # Candidate carries the normalize-side 6-key signals dict (includes registry_overlap).
    candidate = VendorCandidate(vendor="lodash", product="lodash", signals={
        "vendor_equals_package": 1, "name_similarity": 0.9, "registry_overlap": True,
        "py_keyword_score": 0, "js_keyword_score": 1, "keyword_alignment": 1,
    })

    # osv_vulns=[] -> osv_disagrees, and threshold above any probability -> review queue.
    with patch("it_security_agent.matching.find_candidates", return_value=([_match(vendor_candidate=candidate)], [])), \
         patch("it_security_agent.osv.query", return_value=[]), \
         patch("it_security_agent.kev.load_kev_ids", return_value=set()):
        result = agent.scan([component], "random_forest", rf, 2.0, real_explainer)

    assert len(result.review_queue) == 1
    finding = result.review_queue[0]
    assert finding.explanation is not None
    assert set(finding.explanation.keys()) == set(labeling.FEATURES)

from unittest.mock import patch

from it_security_agent import labeling
from it_security_agent.normalize import VendorCandidate
from it_security_agent.schema import Component


def test_features_never_includes_registry_overlap():
    assert "registry_overlap" not in labeling.FEATURES


def test_build_dataset_labels_true_when_registry_overlap_true():
    component = Component(name="django", version="2.2.0", ecosystem="PyPI", source="test")
    candidate = VendorCandidate(
        vendor="djangoproject", product="django",
        signals={"vendor_equals_package": 0, "name_similarity": 1.0, "registry_overlap": True,
                 "py_keyword_score": 5, "js_keyword_score": 0, "keyword_alignment": 5},
    )
    with patch("it_security_agent.normalize.resolve_vendor", return_value=[candidate]), \
         patch("it_security_agent.osv.query", return_value=[]):
        df = labeling.build_dataset([component])
    assert len(df) == 1
    assert df.iloc[0]["label_real_match"] == True


def test_build_dataset_skips_candidates_with_unknown_overlap():
    component = Component(name="foo", version="1.0.0", ecosystem="Debian", source="test")
    candidate = VendorCandidate(
        vendor="foo", product="foo",
        signals={"vendor_equals_package": 1, "name_similarity": 1.0, "registry_overlap": None,
                 "py_keyword_score": 0, "js_keyword_score": 0, "keyword_alignment": 0},
    )
    with patch("it_security_agent.normalize.resolve_vendor", return_value=[candidate]), \
         patch("it_security_agent.osv.query", return_value=[]):
        df = labeling.build_dataset([component])
    assert len(df) == 0


def test_build_dataset_includes_osv_corroborated_as_a_feature():
    component = Component(name="axios", version="0.21.0", ecosystem="npm", source="test")
    candidate = VendorCandidate(
        vendor="axios", product="axios",
        signals={"vendor_equals_package": 1, "name_similarity": 1.0, "registry_overlap": True,
                 "py_keyword_score": 0, "js_keyword_score": 3, "keyword_alignment": 3},
    )
    with patch("it_security_agent.normalize.resolve_vendor", return_value=[candidate]), \
         patch("it_security_agent.osv.query", return_value=[{"id": "GHSA-xxxx"}]):
        df = labeling.build_dataset([component])
    assert df.iloc[0]["osv_corroborated"] == 1

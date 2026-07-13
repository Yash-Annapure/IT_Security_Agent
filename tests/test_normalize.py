from unittest.mock import patch

from it_security_agent import normalize, nvd_cache


def _cpe_product(vendor, product, title, refs=None):
    return {
        "cpe": {
            "cpeName": f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*",
            "titles": [{"lang": "en", "title": title}],
            "refs": [{"ref": r} for r in (refs or [])],
        }
    }


def test_resolve_vendor_computes_name_similarity_and_vendor_equals_package():
    products = [_cpe_product("djangoproject", "django", "Django web framework")]
    with patch("it_security_agent.cpe_dictionary.search", return_value=products), \
         patch("it_security_agent.registry.cached_fetch_metadata", return_value=None):
        candidates = normalize.resolve_vendor("django", "PyPI")
    assert len(candidates) == 1
    c = candidates[0]
    assert c.vendor == "djangoproject"
    assert c.signals["vendor_equals_package"] == 0
    assert c.signals["name_similarity"] == 1.0


def test_resolve_vendor_registry_overlap_true_when_domains_match():
    products = [_cpe_product("djangoproject", "django", "Django", refs=["https://github.com/django/django"])]
    registry_meta = {"urls": ["https://github.com/django/django"]}
    with patch("it_security_agent.cpe_dictionary.search", return_value=products), \
         patch("it_security_agent.registry.cached_fetch_metadata", return_value=registry_meta):
        candidates = normalize.resolve_vendor("django", "PyPI")
    assert candidates[0].signals["registry_overlap"] is True


def test_resolve_vendor_registry_overlap_none_when_no_registry_data():
    products = [_cpe_product("djangoproject", "django", "Django")]
    with patch("it_security_agent.cpe_dictionary.search", return_value=products), \
         patch("it_security_agent.registry.cached_fetch_metadata", return_value=None):
        candidates = normalize.resolve_vendor("django", "PyPI")
    assert candidates[0].signals["registry_overlap"] is None


def test_resolve_vendor_does_not_combine_signals_into_a_score():
    products = [_cpe_product("djangoproject", "django", "Django")]
    with patch("it_security_agent.cpe_dictionary.search", return_value=products), \
         patch("it_security_agent.registry.cached_fetch_metadata", return_value=None):
        candidates = normalize.resolve_vendor("django", "PyPI")
    assert not hasattr(candidates[0], "score")

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


def test_resolve_vendor_registry_overlap_true_for_npm_git_prefixed_url():
    # npm registry returns repository URLs like "git+https://github.com/lodash/lodash.git";
    # _domain must normalize these to match a plain CPE reference so overlap is detected.
    products = [_cpe_product("lodash", "lodash", "Lodash", refs=["https://github.com/lodash/lodash"])]
    registry_meta = {"urls": ["git+https://github.com/lodash/lodash.git"]}
    with patch("it_security_agent.cpe_dictionary.search", return_value=products), \
         patch("it_security_agent.registry.cached_fetch_metadata", return_value=registry_meta):
        candidates = normalize.resolve_vendor("lodash", "npm")
    assert candidates[0].signals["registry_overlap"] is True


def test_resolve_vendor_does_not_combine_signals_into_a_score():
    products = [_cpe_product("djangoproject", "django", "Django")]
    with patch("it_security_agent.cpe_dictionary.search", return_value=products), \
         patch("it_security_agent.registry.cached_fetch_metadata", return_value=None):
        candidates = normalize.resolve_vendor("django", "PyPI")
    assert not hasattr(candidates[0], "score")


# Weakness regression: _domain() used to collapse any URL down to its bare hosting
# domain (e.g. "github.com"), so two *different* GitHub-hosted projects looked like
# a registry match. Discovered by live-checking Week 2's four name collisions against
# the Week 3 pipeline: babel, json5 and jsonpointer all reproduced this exact bug
# because both the real PyPI package and the unrelated npm collision happen to be
# hosted on github.com, just under different owners/repos.
def test_domain_distinguishes_different_repos_on_the_same_host():
    assert normalize._domain("https://github.com/python-babel/babel") != \
        normalize._domain("https://github.com/babel/babel/tags")
    assert normalize._domain("https://github.com/dpranke/pyjson5") != \
        normalize._domain("https://github.com/json5/json5/tags")
    assert normalize._domain("https://github.com/stefankoegl/python-json-pointer") != \
        normalize._domain("https://github.com/janl/node-jsonpointer/tags")


def test_domain_still_matches_the_same_repo_with_a_different_path_suffix():
    # Must not regress the case _domain was originally written for: the same repo
    # referenced two different ways (bare vs. "/tags", git+ prefix vs. plain https).
    assert normalize._domain("git+https://github.com/lodash/lodash.git") == \
        normalize._domain("https://github.com/lodash/lodash")


def test_resolve_vendor_registry_overlap_false_for_different_repos_same_host():
    # Integration-level version of the two unit checks above: babel's real collision
    # (Week 2/3) - PyPI's babel points at python-babel/babel, the npm collision's CPE
    # ref points at babel/babel. Same host, different project; must not overlap.
    products = [_cpe_product("babel", "babel", "Babel", refs=["https://github.com/babel/babel/tags"])]
    registry_meta = {"urls": ["https://github.com/python-babel/babel"]}
    with patch("it_security_agent.cpe_dictionary.search", return_value=products), \
         patch("it_security_agent.registry.cached_fetch_metadata", return_value=registry_meta):
        candidates = normalize.resolve_vendor("babel", "PyPI")
    assert candidates[0].signals["registry_overlap"] is False

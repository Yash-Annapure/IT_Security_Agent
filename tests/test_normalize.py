from unittest.mock import patch

from it_security_agent import normalize


def _cve(vendor, product, description="", refs=None):
    """A cached CVE record naming (vendor, product) in its CPE configurations.

    Shaped like what nvd_cache.query_by_product_name returns - resolve_vendor reads
    vendors straight out of these now, instead of NVD's CPE dictionary API.
    """
    return {
        "cve": {
            "id": "CVE-0000-0001",
            "descriptions": [{"lang": "en", "value": description}],
            "references": [{"url": r} for r in (refs or [])],
            "configurations": [
                {"nodes": [{"cpeMatch": [
                    {"criteria": f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*"}
                ]}]}
            ],
        }
    }


def _resolve(package_name, ecosystem, cves, registry_meta=None):
    with patch("it_security_agent.nvd_cache.query_by_product_name", return_value=cves), \
         patch("it_security_agent.registry.cached_fetch_metadata", return_value=registry_meta):
        return normalize.resolve_vendor(package_name, ecosystem)


def test_resolve_vendor_reads_vendor_and_product_from_the_local_cve_cache():
    candidates = _resolve("django", "PyPI", [_cve("djangoproject", "django", "Django web framework")])
    assert len(candidates) == 1
    c = candidates[0]
    assert c.vendor == "djangoproject"
    assert c.product == "django"
    assert c.signals["vendor_equals_package"] == 0
    assert c.signals["name_similarity"] == 1.0


def test_resolve_vendor_makes_no_network_call():
    # The whole point of the change: a scan must not touch NVD. query_by_product_name is
    # the only lookup, and it is pure SQLite.
    with patch("it_security_agent.nvd_cache.query_by_product_name", return_value=[]) as q, \
         patch("it_security_agent.registry.cached_fetch_metadata", return_value=None):
        assert normalize.resolve_vendor("django", "PyPI") == []
    assert q.called


def test_resolve_vendor_deduplicates_a_vendor_seen_across_several_cves():
    # A popular package appears in dozens of CVEs, all naming the same vendor/product.
    # That must produce one candidate, not one per CVE.
    cves = [_cve("djangoproject", "django", "first"), _cve("djangoproject", "django", "second")]
    assert len(_resolve("django", "PyPI", cves)) == 1


def test_resolve_vendor_ignores_cpes_for_a_different_product():
    # query_by_product_name returns whole CVE records, and one CVE can name many
    # products - only the CPEs whose product field is the package may contribute.
    cve = _cve("djangoproject", "django")
    cve["cve"]["configurations"][0]["nodes"][0]["cpeMatch"].append(
        {"criteria": "cpe:2.3:a:someoneelse:flask:*:*:*:*:*:*:*:*"}
    )
    vendors = {c.vendor for c in _resolve("django", "PyPI", [cve])}
    assert vendors == {"djangoproject"}


def test_resolve_vendor_scores_ecosystem_keywords_from_the_cve_description():
    # The CPE title used to supply this text; the description replaces it and says
    # "npm package" far more often than a title does.
    candidates = _resolve("lodash", "npm", [_cve("lodash", "lodash", "The npm package lodash for Node.js")])
    signals = candidates[0].signals
    assert signals["js_keyword_score"] > 0
    assert signals["keyword_alignment"] > 0


def test_resolve_vendor_keyword_score_counts_presence_not_repetition():
    # Scores must describe the package, not how many CVEs mention it - otherwise a
    # widely-reported package scores higher purely for being widely reported.
    once = _resolve("lodash", "npm", [_cve("lodash", "lodash", "nodejs")])
    many = _resolve("lodash", "npm", [_cve("lodash", "lodash", "nodejs nodejs nodejs")])
    assert once[0].signals["js_keyword_score"] == many[0].signals["js_keyword_score"]


def test_resolve_vendor_registry_overlap_true_when_domains_match():
    candidates = _resolve("django", "PyPI",
                          [_cve("djangoproject", "django", refs=["https://github.com/django/django"])],
                          registry_meta={"urls": ["https://github.com/django/django"]})
    assert candidates[0].signals["registry_overlap"] is True


def test_resolve_vendor_registry_overlap_none_when_no_registry_data():
    candidates = _resolve("django", "PyPI", [_cve("djangoproject", "django")])
    assert candidates[0].signals["registry_overlap"] is None


def test_resolve_vendor_registry_overlap_true_for_npm_git_prefixed_url():
    # npm registry returns repository URLs like "git+https://github.com/lodash/lodash.git";
    # _domain must normalize these to match a plain CVE reference so overlap is detected.
    candidates = _resolve("lodash", "npm",
                          [_cve("lodash", "lodash", refs=["https://github.com/lodash/lodash"])],
                          registry_meta={"urls": ["git+https://github.com/lodash/lodash.git"]})
    assert candidates[0].signals["registry_overlap"] is True


def test_resolve_vendor_does_not_combine_signals_into_a_score():
    candidates = _resolve("django", "PyPI", [_cve("djangoproject", "django")])
    assert not hasattr(candidates[0], "score")


def test_resolve_vendor_looks_up_every_name_spelling():
    # matching.find_candidates searches all three spellings; resolve_vendor must look up
    # the same ones or a vendor it finds would have no candidate attached to it.
    with patch("it_security_agent.nvd_cache.query_by_product_name", return_value=[]) as q, \
         patch("it_security_agent.registry.cached_fetch_metadata", return_value=None):
        normalize.resolve_vendor("python-dateutil", "PyPI")
    assert {call.args[0] for call in q.call_args_list} == set(
        normalize.name_variants("python-dateutil"))


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
    # (Week 2/3) - PyPI's babel points at python-babel/babel, the CVE reference points
    # at babel/babel. Same host, different project; must not overlap.
    candidates = _resolve("babel", "PyPI",
                          [_cve("babel", "babel", refs=["https://github.com/babel/babel/tags"])],
                          registry_meta={"urls": ["https://github.com/python-babel/babel"]})
    assert candidates[0].signals["registry_overlap"] is False

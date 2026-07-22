from dataclasses import dataclass, field

from rapidfuzz import fuzz

from it_security_agent import nvd_cache, registry

PY_KEYWORDS = ["python", "pypi", "pip ", "django", "flask", "wsgi", "cpython"]
JS_KEYWORDS = ["javascript", "node.js", "nodejs", "npm ", "react", "webpack", "ecmascript"]


@dataclass
class VendorCandidate:
    vendor: str
    product: str
    signals: dict = field(default_factory=dict)


# Hosts where one domain hosts millions of unrelated projects. On these, "same
# domain" proves nothing - github.com/python-babel/babel and github.com/babel/babel
# are two different projects that would otherwise look identical to _domain().
MULTI_TENANT_HOSTS = {"github.com", "gitlab.com", "bitbucket.org"}


def _domain(url: str) -> str:
    # npm repository URLs commonly use a "git+" prefix and a ".git" suffix, e.g.
    # "git+https://github.com/lodash/lodash.git". Strip both so the domain matches
    # a plain CPE reference like "https://github.com/lodash/lodash".
    url = url.lower().strip()
    if url.startswith("git+"):
        url = url[len("git+"):]
    url = url.replace("https://", "").replace("http://", "")
    if url.endswith(".git"):
        url = url[: -len(".git")]
    parts = url.split("/")
    host = parts[0].replace("www.", "")
    if host in MULTI_TENANT_HOSTS and len(parts) >= 3:
        # Keep the owner/repo segments too, e.g. "github.com/janl/node-jsonpointer" -
        # otherwise every GitHub-hosted project in NVD's CPE dictionary would look
        # like a registry match for every GitHub-hosted PyPI/npm package (see Week 2/3
        # "name collision" false positives: babel, json5, jsonpointer all reproduced
        # this exact bug because both sides just happened to live on github.com).
        return "/".join([host, parts[1], parts[2]])
    return host


def _registry_overlap(ecosystem, name, product_refs, conn):
    metadata = registry.cached_fetch_metadata(ecosystem, name, conn=conn)
    if not metadata or not metadata.get("urls"):
        return None
    reg_domains = {_domain(u) for u in metadata["urls"]}
    ref_domains = {_domain(u) for u in product_refs}
    return bool(reg_domains & ref_domains)


def name_variants(name):
    """Spellings of a package name to look for as a CPE product.

    Lives here rather than in matching.py so resolve_vendor can look up exactly the
    same spellings matching.find_candidates will; matching re-exports it.
    """
    n = name.lower()
    return sorted({n, n.replace("-", "_"), n.replace("_", "-")})


def _english_description(cve) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def _cpe_pairs(cve, spelling):
    """(vendor, product) from every CPE in `cve` whose product field is `spelling`.

    Field 3 of a CPE 2.3 URI is the vendor and field 4 the product - the same parse
    matching.find_candidates does when it reads a match's vendor back off the record.
    """
    for group in cve.get("configurations") or []:
        for node in group.get("nodes", []):
            for m in node.get("cpeMatch", []):
                parts = m.get("criteria", "").split(":")
                if len(parts) > 5 and parts[4].lower() == spelling:
                    yield parts[3].lower(), parts[4].lower()


def resolve_vendor(package_name: str, ecosystem: str, conn=None):
    """Vendor candidates for a package name, read out of the local CVE cache.

    This used to call NVD's CPE dictionary API once per package name, and that was
    the single worst thing in a scan: a network round trip per name, rate-limited to
    one request a second, behind a time budget that a real npm lockfile blew straight
    through. A 257-package `package-lock.json` needed ~250 of those calls; a repo's
    own `uv.lock` needed none, because its names were already cached from earlier
    runs. That is the entire reason npm scans crawled and uv.lock scans didn't - not
    anything about npm.

    None of it was necessary. A cached CVE record carries the full CPE 2.3 URI of
    every product it affects, and the vendor is simply field 3 of that string -
    matching.find_candidates has always read it back that way. With the whole catalog
    cached locally, the vendors for a package name are already on disk, indexed by
    cve_products; the dictionary API was fetching a second copy of data the cache
    already held. So the lookup is now local, and a scan makes no NVD requests at all.

    What the API did supply that a CVE record doesn't is a short product title and a
    set of reference URLs. The CVE's own description and references stand in, and are
    better suited to the job - a description says "the npm package foo" far more often
    than a CPE title does.
    """
    entries = {}
    for spelling in name_variants(package_name):
        for item in nvd_cache.query_by_product_name(spelling, conn=conn):
            cve = item.get("cve", {})
            description = _english_description(cve)
            refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]
            for vendor, product in _cpe_pairs(cve, spelling):
                entry = entries.setdefault((vendor, product), {"text": set(), "refs": set()})
                entry["text"].add(description)
                entry["refs"].update(refs)

    candidates = []
    for (vendor, product), entry in sorted(entries.items()):
        refs = sorted(entry["refs"])
        text = " ".join(sorted(entry["text"])).lower()
        # Presence, not occurrence count. The old score counted hits in a single short
        # CPE title, where a keyword appeared once or not at all; here the text is every
        # description this (vendor, product) appears in, so counting occurrences would
        # scale the feature with how many CVEs a package has rather than describing the
        # package. Presence keeps it bounded and comparable to what the model trained on.
        py_score = sum(1 for k in PY_KEYWORDS if k in text)
        js_score = sum(1 for k in JS_KEYWORDS if k in text)
        candidates.append(VendorCandidate(
            vendor=vendor, product=product,
            signals={
                "vendor_equals_package": int(vendor == package_name.lower()),
                "name_similarity": fuzz.token_set_ratio(package_name.lower(), product) / 100.0,
                "registry_overlap": _registry_overlap(ecosystem, package_name, refs, conn),
                "py_keyword_score": py_score,
                "js_keyword_score": js_score,
                "keyword_alignment": (py_score - js_score) if ecosystem == "PyPI" else (js_score - py_score),
            },
        ))
    return candidates

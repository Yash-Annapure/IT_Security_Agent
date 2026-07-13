from dataclasses import dataclass, field

from rapidfuzz import fuzz

from it_security_agent import cpe_dictionary, registry

PY_KEYWORDS = ["python", "pypi", "pip ", "django", "flask", "wsgi", "cpython"]
JS_KEYWORDS = ["javascript", "node.js", "nodejs", "npm ", "react", "webpack", "ecmascript"]


@dataclass
class VendorCandidate:
    vendor: str
    product: str
    signals: dict = field(default_factory=dict)


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
    return url.split("/")[0].replace("www.", "")


def _registry_overlap(ecosystem, name, product_refs, conn):
    metadata = registry.cached_fetch_metadata(ecosystem, name, conn=conn)
    if not metadata or not metadata.get("urls"):
        return None
    reg_domains = {_domain(u) for u in metadata["urls"]}
    ref_domains = {_domain(u) for u in product_refs}
    return bool(reg_domains & ref_domains)


def resolve_vendor(package_name: str, ecosystem: str, conn=None):
    products = cpe_dictionary.search(package_name, conn=conn)
    candidates = []
    for p in products:
        cpe = p.get("cpe", {})
        parts = cpe.get("cpeName", "").split(":")
        if len(parts) < 5:
            continue
        vendor, product = parts[3], parts[4]
        title = next((t["title"] for t in cpe.get("titles", []) if t.get("lang") == "en"), product)
        refs = [r.get("ref", "") for r in cpe.get("refs", [])]

        name_similarity = fuzz.token_set_ratio(package_name.lower(), product.lower()) / 100.0
        overlap = _registry_overlap(ecosystem, package_name, refs, conn)
        text = title.lower()
        py_score = sum(text.count(k) for k in PY_KEYWORDS)
        js_score = sum(text.count(k) for k in JS_KEYWORDS)
        alignment = (py_score - js_score) if ecosystem == "PyPI" else (js_score - py_score)

        candidates.append(VendorCandidate(
            vendor=vendor, product=product,
            signals={
                "vendor_equals_package": int(vendor.lower() == package_name.lower()),
                "name_similarity": name_similarity,
                "registry_overlap": overlap,
                "py_keyword_score": py_score,
                "js_keyword_score": js_score,
                "keyword_alignment": alignment,
            },
        ))
    return candidates

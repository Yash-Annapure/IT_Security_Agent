import pandas as pd

from it_security_agent import normalize, osv

FEATURES = [
    "vendor_equals_package", "name_similarity", "py_keyword_score",
    "js_keyword_score", "keyword_alignment", "ecosystem_pypi", "osv_corroborated",
]


def build_training_row(package_name, ecosystem, vendor_candidate, component_version, label, conn=None):
    osv_vulns = osv.query(ecosystem, package_name, component_version, conn=conn)
    signals = vendor_candidate.signals
    return {
        "package": package_name, "ecosystem": ecosystem, "vendor": vendor_candidate.vendor,
        "vendor_equals_package": signals["vendor_equals_package"],
        "name_similarity": signals["name_similarity"],
        "py_keyword_score": signals["py_keyword_score"],
        "js_keyword_score": signals["js_keyword_score"],
        "keyword_alignment": signals["keyword_alignment"],
        "ecosystem_pypi": int(ecosystem == "PyPI"),
        "osv_corroborated": int(len(osv_vulns) > 0),
        "label_real_match": label,
    }


def build_dataset(components, conn=None) -> pd.DataFrame:
    rows = []
    for component in components:
        for candidate in normalize.resolve_vendor(component.name, component.ecosystem, conn=conn):
            overlap = candidate.signals.get("registry_overlap")
            if overlap is None:
                continue  # can't confidently label without registry data
            rows.append(build_training_row(
                component.name, component.ecosystem, candidate, component.version, bool(overlap), conn=conn,
            ))
    return pd.DataFrame(rows)

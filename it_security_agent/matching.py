from packaging.version import InvalidVersion, Version

from it_security_agent import normalize, nvd_cache


def parse_version(text):
    try:
        return Version(text)
    except (InvalidVersion, TypeError):
        return None


def name_variants(name):
    n = name.lower()
    return sorted({n, n.replace("-", "_"), n.replace("_", "-")})


def version_applies(m, pinned):
    if pinned is None:
        return False
    if not m.get("vulnerable", True):
        return False
    cpe_version = m["criteria"].split(":")[5]
    if cpe_version not in ("*", "-"):
        return parse_version(cpe_version) == pinned
    checks = (
        ("versionStartIncluding", lambda b: pinned < b),
        ("versionStartExcluding", lambda b: pinned <= b),
        ("versionEndIncluding", lambda b: pinned > b),
        ("versionEndExcluding", lambda b: pinned >= b),
    )
    for field_name, fails in checks:
        if field_name not in m:
            continue
        bound = parse_version(m[field_name])
        if bound is None or fails(bound):
            return False
    return True


def best_cvss(metrics):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m = metrics[key][0]
            data = m.get("cvssData", {})
            return data.get("baseScore"), m.get("baseSeverity", data.get("baseSeverity"))
    return None, None


def cwe_ids(weaknesses):
    ids = []
    for w in weaknesses or []:
        for d in w.get("description", []):
            if d.get("lang") == "en" and d.get("value", "").startswith("CWE-"):
                ids.append(d["value"])
    return ids


def english_description(cve):
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d["value"]
    return ""


def find_candidates(component, conn=None):
    pinned = parse_version(component.version)
    resolved = {c.vendor: c for c in normalize.resolve_vendor(component.name, component.ecosystem, conn=conn)}
    seen = set()
    matches, rejected = [], []
    for spelling in name_variants(component.name):
        for item in nvd_cache.query_by_product_name(spelling, conn=conn):
            cve = item["cve"]
            if cve["id"] in seen:
                continue
            matched_vendor, name_matched_at_all = None, False
            for group in cve.get("configurations") or []:
                for node in group.get("nodes", []):
                    for m in node.get("cpeMatch", []):
                        parts = m.get("criteria", "").split(":")
                        if len(parts) > 5 and parts[4].lower() == spelling:
                            name_matched_at_all = True
                            if version_applies(m, pinned):
                                matched_vendor = parts[3]
                                break
                    if matched_vendor:
                        break
                if matched_vendor:
                    break
            seen.add(cve["id"])
            if matched_vendor:
                score, severity = best_cvss(cve.get("metrics", {}))
                matches.append({
                    "cve": cve["id"], "severity": severity or "UNKNOWN", "cvss_score": score,
                    "cwe_ids": cwe_ids(cve.get("weaknesses")), "description": english_description(cve),
                    "vendor": matched_vendor, "vendor_candidate": resolved.get(matched_vendor),
                })
            elif name_matched_at_all:
                rejected.append(cve["id"])
    return matches, rejected

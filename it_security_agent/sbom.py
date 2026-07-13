from it_security_agent.schema import Component, PURL_TYPE

_SCHEME_TO_ECOSYSTEM = {ptype: eco for eco, ptype in PURL_TYPE.items()}


def _ecosystem_from_purl(purl: str) -> str:
    scheme = purl.replace("pkg:", "").split("/")[0]
    return _SCHEME_TO_ECOSYSTEM.get(scheme, scheme)


def parse_cyclonedx(data: dict, source_label: str = "SBOM (CycloneDX)"):
    components = []
    for c in data.get("components", []):
        purl = c.get("purl")
        if not purl:
            continue
        components.append(Component(
            name=c.get("name", ""), version=c.get("version", ""),
            ecosystem=_ecosystem_from_purl(purl), source=source_label, purl=purl,
        ))
    return components


def parse_spdx(data: dict, source_label: str = "SBOM (SPDX)"):
    components = []
    unparsed = 0
    for pkg in data.get("packages", []):
        purl = next(
            (r.get("referenceLocator") for r in pkg.get("externalRefs", [])
             if r.get("referenceType") == "purl"),
            None,
        )
        if not purl:
            unparsed += 1
            continue
        components.append(Component(
            name=pkg.get("name", ""), version=pkg.get("versionInfo", ""),
            ecosystem=_ecosystem_from_purl(purl), source=source_label, purl=purl,
        ))
    return components, unparsed

import datetime
import json
from pathlib import Path

from it_security_agent.schema import Component, PURL_TYPE

_SCHEME_TO_ECOSYSTEM = {ptype: eco for eco, ptype in PURL_TYPE.items()}
CYCLONEDX_SPEC_VERSION = "1.5"


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


def to_cyclonedx(components, bom_name: str = "generated-sbom", bom_version: str = "0.0.0") -> dict:
    """The inverse of parse_cyclonedx(): build a real CycloneDX document from a
    component list, without any external tool (Syft/cdxgen). image_scan.py
    covers the container-image case, which does need Syft; this covers a plain
    checkout's own dependency files (see generate_sbom.py)."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "component": {"type": "application", "name": bom_name, "version": bom_version},
        },
        "components": [
            {"type": "library", "name": c.name, "version": c.version, "purl": c.purl}
            for c in components
        ],
    }


def write_cyclonedx(components, out_path: Path, bom_name: str = "generated-sbom", bom_version: str = "0.0.0") -> dict:
    bom = to_cyclonedx(components, bom_name=bom_name, bom_version=bom_version)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(bom, indent=2))
    return bom

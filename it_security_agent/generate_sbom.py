"""Build a CycloneDX SBOM directly from a repo checkout's own dependency
files - no external tool required. `image_scan.py` covers the container-
image case (which does need Syft); this covers a plain source checkout.
"""
from pathlib import Path

from it_security_agent import repo_scan, sbom

# Order matters when a repo has more than one of these: prefer the most
# precisely pinned format first.
DETECTORS = (
    ("uv.lock", repo_scan.parse_uv_lock),
    ("package-lock.json", repo_scan.parse_package_lock),
    ("requirements.txt", repo_scan.parse_requirements_txt),
)


def discover_components(repo_dir) -> list:
    repo_dir = Path(repo_dir)
    components = []
    for filename, parser in DETECTORS:
        path = repo_dir / filename
        if path.exists():
            components += parser(path)
    return components


def generate_sbom(repo_dir, bom_name: str | None = None, bom_version: str = "0.0.0") -> dict:
    repo_dir = Path(repo_dir)
    components = discover_components(repo_dir)
    if not components:
        supported = ", ".join(name for name, _ in DETECTORS)
        raise ValueError(f"no supported dependency files ({supported}) found in {repo_dir}")
    return sbom.to_cyclonedx(components, bom_name=bom_name or repo_dir.resolve().name, bom_version=bom_version)

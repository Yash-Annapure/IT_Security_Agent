import json
import tomllib
from pathlib import Path

from it_security_agent.schema import Component


def parse_uv_lock(path: Path, source_label: str = "uv.lock"):
    lock = tomllib.loads(Path(path).read_text(encoding="utf-8"))
    components = []
    for pkg in lock.get("package", []):
        if "registry" not in pkg.get("source", {}):
            continue  # skips the virtual project package itself
        components.append(Component(
            name=pkg["name"], version=pkg["version"], ecosystem="PyPI", source=source_label,
        ))
    return components


def parse_package_lock(path: Path, source_label: str = "package-lock.json"):
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    components = []
    for key, pkg in data.get("packages", {}).items():
        if key == "":
            continue  # the root project package itself
        name = key.split("node_modules/")[-1]
        version = pkg.get("version")
        if not version:
            continue
        components.append(Component(
            name=name, version=version, ecosystem="npm", source=source_label,
        ))
    return components

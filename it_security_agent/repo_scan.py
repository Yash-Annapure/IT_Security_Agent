import json
import tomllib
from pathlib import Path

from it_security_agent.schema import Component


def parse_uv_lock_text(text: str, source_label: str = "uv.lock"):
    lock = tomllib.loads(text)
    components = []
    for pkg in lock.get("package", []):
        if "registry" not in pkg.get("source", {}):
            continue  # skips the virtual project package itself
        components.append(Component(
            name=pkg["name"], version=pkg["version"], ecosystem="PyPI", source=source_label,
        ))
    return components


def parse_uv_lock(path: Path, source_label: str = "uv.lock"):
    return parse_uv_lock_text(Path(path).read_text(encoding="utf-8"), source_label=source_label)


def parse_package_lock_text(text: str, source_label: str = "package-lock.json"):
    data = json.loads(text)
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


def parse_package_lock(path: Path, source_label: str = "package-lock.json"):
    return parse_package_lock_text(Path(path).read_text(encoding="utf-8"), source_label=source_label)


def parse_requirements_txt_text(text: str, source_label: str = "requirements.txt"):
    components = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue  # blank/comment lines, and options like -r, -e, --index-url
        if "==" not in line:
            continue  # unpinned (>=, ~=, bare name, ...) - nothing exact to match against NVD
        name, _, version = line.partition("==")
        name = name.split(";")[0].split("[")[0].strip()  # drop environment markers and extras
        version = version.split(";")[0].strip()
        if not name or not version:
            continue
        components.append(Component(
            name=name, version=version, ecosystem="PyPI", source=source_label,
        ))
    return components


def parse_requirements_txt(path: Path, source_label: str = "requirements.txt"):
    return parse_requirements_txt_text(Path(path).read_text(encoding="utf-8"), source_label=source_label)

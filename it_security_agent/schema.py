from dataclasses import dataclass

PURL_TYPE = {
    "PyPI": "pypi",
    "npm": "npm",
    "Debian": "deb",
    "Alpine": "apk",
    "Go": "golang",
    "Maven": "maven",
    "Cargo": "cargo",
    "RubyGems": "gem",
}


def build_purl(ecosystem: str, name: str, version: str) -> str:
    ptype = PURL_TYPE.get(ecosystem, ecosystem.lower())
    return f"pkg:{ptype}/{name}@{version}"


@dataclass
class Component:
    name: str
    version: str
    ecosystem: str
    source: str
    purl: str = ""

    def __post_init__(self):
        if not self.purl:
            self.purl = build_purl(self.ecosystem, self.name, self.version)

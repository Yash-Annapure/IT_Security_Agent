"""Condense a lockfile to just name==version pairs before handing it to scan_repo.

    uv run condense_lockfile.py [path/to/lockfile]

`scan_repo`'s parsers (see repo_scan.py) only ever keep a component's name, version, and
ecosystem from a uv.lock or package-lock.json - everything else (sdist/wheel URLs, sha256
hashes, one wheel entry per platform) is bytes that exist for `uv`/`npm` themselves, not
for vulnerability matching. On a real dependency tree that bulk dominates the file: this
project's own uv.lock is ~170KB raw, almost all of it wheel manifests, versus a few KB of
actual name/version pairs.

That distinction matters once a local/small model is the one reading the file: Cline's
`.clinerules/scan-repo.md` workflow has the model read the lockfile itself and pass its
text as `lockfile_content` - a 170KB raw uv.lock is enough to blow a 32K-context model's
entire context window in one message (this project hit exactly that: a 176,548-character
lockfile pushed one request to ~135,000 tokens and crashed the GPU with an OOM). Condensing
first keeps the *scan* results identical (same components, same matches) while cutting the
token cost by ~95%+.

Output format: for a PyPI-only lockfile (uv.lock/requirements.txt), one `name==version`
line per package - `scan_repo` auto-detects this as requirements.txt. For an npm lockfile
(package-lock.json), a minimal JSON document with just `packages` -> `{"version": ...}` -
`scan_repo` auto-detects this as package-lock.json. Both round-trip through scan_repo's
existing parsers to the exact same Component list the original file would have produced.

Defaults to `uv.lock` in the current directory if no path is given.
"""
import json
import sys
from pathlib import Path

from it_security_agent.mcp_server import parse_lockfile_components


def condense(lockfile_text: str) -> str:
    components = parse_lockfile_components(lockfile_text)
    if not components:
        raise ValueError("No components parsed from this lockfile - nothing to condense.")

    if all(c.ecosystem == "npm" for c in components):
        packages = {f"node_modules/{c.name}": {"version": c.version} for c in components}
        return json.dumps({"packages": packages})

    pypi_lines = [f"{c.name}=={c.version}" for c in components if c.ecosystem == "PyPI"]
    return "\n".join(pypi_lines)


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("uv.lock")
    if not path.exists():
        print(f"No such file: {path}", file=sys.stderr)
        sys.exit(1)
    print(condense(path.read_text(encoding="utf-8")))


if __name__ == "__main__":
    main()

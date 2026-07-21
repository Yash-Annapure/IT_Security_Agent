"""Thin CLI wrapper around the `condense_lockfile` MCP tool - see
it_security_agent/mcp_server.py for the real implementation and its full docstring.

    uv run condense_lockfile.py [path/to/lockfile]

This is a convenience for condensing a lockfile *outside* of an MCP/Cline session -
scripting, or just checking what `scan_repo` would actually receive. Inside Cline,
`condense_lockfile` is an MCP tool like `scan_repo`, never invoked as a script - see
.clinerules/scan-repo.md.

Defaults to `uv.lock` in the current directory if no path is given.
"""
import sys
from pathlib import Path

from it_security_agent.mcp_server import condense_lockfile


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("uv.lock")
    if not path.exists():
        print(f"No such file: {path}", file=sys.stderr)
        sys.exit(1)
    print(condense_lockfile(path.read_text(encoding="utf-8")))


if __name__ == "__main__":
    main()

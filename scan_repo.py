"""Not a real script - `scan_repo` only exists as an MCP tool.

This file exists purely so `python scan_repo.py` fails with a clear,
actionable message instead of a bare "No such file or directory" or
"No module named" error - that exact mistake has happened more than once in
practice (an agent assuming scan_repo works like condense_lockfile.py, which
really is a script). `scan_repo` (and `get_setup_rules`) are tools on the
running `it-security-agent` MCP server (see it_security_agent/mcp_server.py)
- call them through your MCP tool-use mechanism, never via `python`, `pip`,
or `uv`. No install step makes this importable, because it isn't meant to
be - see .clinerules/scan-repo.md for the real workflow.
"""
import sys

if __name__ == "__main__":
    print(__doc__, file=sys.stderr)
    sys.exit(1)

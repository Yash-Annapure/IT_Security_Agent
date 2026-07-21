"""Not a real module - `scan_repo` only exists as an MCP tool.

This file exists purely so `python -m it_security_agent.scan_repo` fails
with a clear, actionable message instead of a bare "No module named" error -
that exact mistake has happened in practice. `scan_repo` (and
`get_setup_rules`) are tools on the running `it-security-agent` MCP server
(see mcp_server.py in this package) - call them through your MCP tool-use
mechanism, never via `python -m`. No install step makes this importable as a
runnable entry point, because it isn't meant to be - see
.clinerules/scan-repo.md for the real workflow.
"""
import sys

if __name__ == "__main__":
    print(__doc__, file=sys.stderr)
    sys.exit(1)

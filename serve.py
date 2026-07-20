"""Plug-and-play entry point for a datalab server.

    git clone <this repo>
    cd IT_Security_Agent
    uv run serve.py

That's it - `uv run` installs dependencies from uv.lock automatically, and
this prints the URL plus the exact Cline config to paste before it starts
listening. See README.md for the one-time Mistral (vLLM) setup on the same
box, and for MCP_HOST/MCP_PORT/MCP_PUBLIC_HOST if the printed URL isn't the
right one to hand to Cline.
"""
from it_security_agent.mcp_server import main

if __name__ == "__main__":
    main()

# IT_Security_Agent

Scans a Python/npm dependency list against NVD, CISA KEV, and OSV.dev, and
triages each match into `escalated` / `confirmed` / `review_queue` /
`rejected` using a trained model with SHAP explanations. See
`notebooks/week3_agent.ipynb` for the full pipeline walked through end-to-end.

Three ways to feed it dependencies:
- **An existing SBOM** (CycloneDX or SPDX) - `sbom.parse_cyclonedx` / `parse_spdx`.
- **A lockfile** - `uv.lock`, `package-lock.json`, or `requirements.txt` via `repo_scan.py`.
- **A container image** - `image_scan.scan_image()`, via Syft.

If a repo has none of the above but does have a lockfile, this project can
also *generate* a real CycloneDX SBOM itself, with no external tool -
`generate_sbom.generate_sbom(repo_dir)` (Section 10 of the notebook
demonstrates it end-to-end: generate -> round-trip through the same parser a
third-party SBOM would use -> scan).

## Setup

```
uv sync
```

`NVD_API_KEY` in a `.env` file at the repo root is optional but strongly
recommended - without it every NVD/CPE request is spaced 6s apart instead of
1s, and the initial sync (Section 2 of the notebook, or the MCP server's
first `scan_repo` call) takes several times longer.

## Plug-and-play: expose this as an MCP tool for Cline + a self-hosted model

This repo ships an MCP server (`it_security_agent/mcp_server.py`) with one
tool, `scan_repo`, over Streamable HTTP - so it can run on a remote machine
(e.g. next to a self-hosted LLM) and be registered as a remote MCP server in
Cline. A `.clinerules` file at the repo root already tells Cline's model how
and when to call it, with no extra prompt setup needed on your end.

### 1. Host Mistral-7B-Instruct with tool calling, on your datalab server

```
vllm serve mistralai/Mistral-7B-Instruct-v0.3 \
  --host 0.0.0.0 --port 8000 \
  --enable-auto-tool-choice --tool-call-parser mistral
```

`--enable-auto-tool-choice` and `--tool-call-parser mistral` are both
required for vLLM to parse Mistral's tool-call output correctly. If tool
calls come back malformed, add `--chat-template
examples/tool_chat_template_mistral.jinja` (from the vLLM repo checkout) -
some Mistral-7B-Instruct revisions need the explicit template. Any other
OpenAI-compatible server (TGI, Ollama, etc.) works the same way from Cline's
side; only the serving command differs.

### 2. Run this repo's MCP server, on the same (or any reachable) machine

```
MCP_HOST=0.0.0.0 MCP_PORT=8765 uv run it-security-agent-mcp
```

It listens on `http://<host>:8765/mcp`. It has no access to a caller's local
filesystem by design (`scan_repo` takes file *content*, not a path) - see
`.clinerules` for how Cline is instructed to read files locally and pass
their content through.

### 3. Register both in Cline (VS Code extension)

**Model** - Settings -> API Provider -> "OpenAI Compatible":
- Base URL: `http://<datalab-server>:8000/v1`
- API Key: any non-empty placeholder (vLLM ignores it unless you've
  configured auth)
- Model ID: `mistralai/Mistral-7B-Instruct-v0.3`

**Tool** - "Configure MCP Servers" -> add to `cline_mcp_settings.json`:
```json
{
  "mcpServers": {
    "it-security-agent": {
      "type": "streamableHttp",
      "url": "http://<datalab-server>:8765/mcp",
      "timeout": 300
    }
  }
}
```
The 300s timeout matters: the first `scan_repo` call after the server starts
does a full NVD sync and can take 1-2 minutes. Cline's default timeout is
much shorter and will otherwise report a false failure.

### 4. Use it

In Cline, open this repo and ask something like "check this repo's
dependencies for vulnerabilities." `.clinerules` tells the model to read the
lockfile/SBOM itself and call `scan_repo` with its content - no further
prompting needed.

If you ask for "an SBOM" and the repo only has a lockfile, `scan_repo`
generates one from it (a real CycloneDX document, not a description of one)
and returns it inline alongside the findings - `.clinerules` tells the model
this counts as the answer, not a "can't do that" response.
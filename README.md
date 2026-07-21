# IT_Security_Agent

Scans a Python/npm dependency list against NVD, CISA KEV, and OSV.dev, and
triages each match into `escalated` / `confirmed` / `review_queue` /
`rejected` using a trained model with SHAP explanations. See
`notebooks/week3_agent.ipynb` for the full pipeline walked through end-to-end.

Three ways to feed it dependencies, as a Python library:
- **A lockfile** - `uv.lock`, `package-lock.json`, or `requirements.txt` via `repo_scan.py`.
- **A container image** - `image_scan.scan_image()`, generates a fresh SBOM by
  running Syft against the actual image.
- **An existing SBOM** (CycloneDX or SPDX) - `sbom.parse_cyclonedx` / `parse_spdx`.
  This one is for parsing output your own tooling just produced (e.g. Syft's,
  or `generate_sbom.py`'s own), not for trusting an arbitrary file someone
  hands you - see the tamper-proofing note below.

Given a lockfile but no SBOM, this project can also *generate* a real
CycloneDX SBOM itself, with no external tool - `generate_sbom.generate_sbom(repo_dir)`
(Section 10 of the notebook demonstrates it end-to-end: generate -> round-trip
through the same parser a third-party SBOM would use -> scan).

**Tamper-proofing:** the MCP server (below) only ever accepts a lockfile, never
a pre-made SBOM. A caller-supplied SBOM is an unverified claim about what's
pinned - it could omit or misstate a vulnerable package with no way to tell.
The lockfile is the only thing treated as ground truth; every scan builds its
own SBOM from it, every time. This is a deliberate restriction on the MCP
tool's surface, not a missing feature - `sbom.parse_cyclonedx`/`parse_spdx`
still exist in the library for parsing SBOMs *this project itself* just
generated (from Syft or `generate_sbom.py`), which is a different trust
situation than accepting one from an arbitrary caller.

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
(e.g. your datalab server, next to a self-hosted LLM) and be registered as a
remote MCP server in Cline. A `.clinerules/` directory at the repo root
already tells Cline's model how and when to call it - no extra prompt setup
needed (the JSON config shape and rules-directory format below were verified
against Cline's own source, not just its docs - both have changed recently).

### On the datalab server

```
git clone <this repo's URL>
cd IT_Security_Agent
uv run serve.py
```

That's it - `uv run` installs everything from `uv.lock` automatically (no
separate `uv sync` step), and `serve.py` starts listening on `0.0.0.0:8765`
and prints something like:

```
URL for Cline: http://192.168.1.42:8765/mcp

Paste into Cline -> "Configure MCP Servers" (merge into an existing
"mcpServers" block if you already have one):

{
  "mcpServers": {
    "it-security-agent": {
      "type": "streamableHttp",
      "url": "http://192.168.1.42:8765/mcp",
      "timeout": 300,
      "autoApprove": ["scan_repo"]
    }
  }
}
```

Copy that URL and JSON block directly - nothing to fill in by hand.
`autoApprove` skips Cline's per-call confirmation prompt for `scan_repo`
(safe to leave in - it never writes to or executes anything on the caller's
machine; drop it from the list if you'd rather approve each scan by hand).
It auto-detects the box's LAN-reachable IP; if that's wrong for your network
(behind NAT, inside a container, etc.), set `MCP_PUBLIC_HOST` to the correct
address/hostname and restart. `MCP_PORT` overrides the port (default 8765).
There's no built-in auth, so only expose this on a private/trusted network.

A `.env` file with `NVD_API_KEY` is optional but strongly recommended -
without it every NVD/CPE request is spaced 6s apart instead of 1s.

Separately, host Qwen2.5-7B-Instruct with tool calling on the same box:
```
vllm serve Qwen/Qwen2.5-7B-Instruct \
  --host 0.0.0.0 --port 8000 \
  --enable-auto-tool-choice --tool-call-parser hermes
```
Qwen2.5's own `tokenizer_config.json` already ships a working tool-calling
chat template (hermes-style `<tool_call>` blocks) - unlike Mistral, no
`--chat-template` override is needed. Any other OpenAI-compatible server
(TGI, Ollama, `serve_mistral.py` in this repo, etc.) works the same way from
Cline's side; only the serving command differs. Note Qwen2.5-7B-Instruct's
real context is 32768 tokens - see "Keeping lockfiles small enough to fit in
context" below, since a raw lockfile can overflow that in one message on a
real dependency tree.

### In Cline (VS Code extension)

**Model** - Settings -> API Provider -> "OpenAI Compatible":
- Base URL: `http://<datalab-server>:8000/v1`
- API Key: any non-empty placeholder (vLLM ignores it unless you've
  configured auth)
- Model ID: `Qwen/Qwen2.5-7B-Instruct`

**Tool** - "Configure MCP Servers" -> paste the JSON block `serve.py` printed.

The 300s timeout in that block matters: the first `scan_repo` call after the
server starts does a full NVD sync and can take 1-2 minutes. Cline's default
timeout is much shorter and will otherwise report a false failure.

### Use it

In Cline, open this repo and ask something like "check this repo's
dependencies for vulnerabilities." `.clinerules/` tells the model to condense
the lockfile (see below), then call `scan_repo` with the condensed content -
no further prompting needed. The tool has no parameter for a pre-made SBOM at
all, by design (see the tamper-proofing note above) - `.clinerules/` also
tells the model not to go looking for one.

If you ask for "an SBOM" and the repo only has a lockfile, `scan_repo`
generates one from it (a real CycloneDX document, not a description of one)
and returns it inline alongside the findings - `.clinerules/` tells the model
this counts as the answer, not a "can't do that" response.

### Keeping lockfiles small enough to fit in context

`condense_lockfile.py` (repo root) strips a lockfile down to just
`name==version` pairs (or the npm equivalent), using the exact same parser
`scan_repo` uses server-side - the scan result is identical either way, since
wheel/sdist URLs and hashes were never part of what gets matched against
NVD/KEV/OSV anyway. On this repo's own `uv.lock` that's a ~99.5% size cut
(618KB -> 3KB, 158 packages). Run it before calling `scan_repo`:

```
uv run condense_lockfile.py uv.lock
```

`.clinerules/` tells the model to always do this instead of reading the raw
lockfile directly. This matters more than it sounds: a raw lockfile is often
large enough to overflow a small local model's entire context window in one
message - this project hit that directly (a 176,548-character raw `uv.lock`
pushed one request to ~135,000 tokens against Qwen2.5-7B-Instruct's real
32768-token context, and crashed the GPU with a CUDA out-of-memory error
trying to allocate KV-cache space for it). `serve_mistral.py` now also
rejects any prompt over `MAX_INPUT_TOKENS` (default 28000, override via env
var) with a clear HTTP 413 before calling `model.generate()`, so an oversized
prompt fails cleanly instead of crashing the server - but condensing first is
what actually avoids hitting that limit on a real dependency tree.

### Using it against a different repo for the first time

The MCP server is registered once in Cline's settings (globally, not per
repo), so pointing Cline at some other project and asking it to check for
vulnerabilities works immediately - except that other repo won't have this
project's `.clinerules/scan-repo.md` yet, so the model won't know the
lockfile-first workflow, the "no pre-made SBOM" rule, etc.

A second tool, `get_setup_rules`, closes that gap: the server-wide MCP
`instructions` field (sent to the client alongside the tool list, so it's
visible even in a repo with no `.clinerules/` at all) tells the model to
check locally for `.clinerules/scan-repo.md` before its first scan in any
repo, and if missing, call `get_setup_rules` and write the returned text
there verbatim - a one-time per-repo bootstrap. The text it returns is read
straight from this repo's own `.clinerules/scan-repo.md`, so the two never
drift - edit that one file and both this project's Cline setup and every
newly-bootstrapped repo pick up the change.
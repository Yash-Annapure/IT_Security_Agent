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

### Warm the cache once (recommended - makes scans near-instant)

```
uv run warm_cache.py
```

Pre-populates `nvd_cache.db` with the NVD CVE window, the CISA KEV feed, and
CPE vendor data for every package in your lockfile(s), so scans afterwards
hit the local cache instead of the network. Worth doing once per machine
right after `uv sync`.

This matters because CPE vendor lookups are the slowest part of a scan and
NVD rate-limits them (1s/request with an API key, 6s without). The server
prewarms them inside each scan under a 90s budget, so a large lockfile
converges over several scans; this script does the same fetching with no
budget cap and no timeout pressure, and prints per-package progress with an
up-front ETA. On this repo (151 unique names) that's ~2.5 minutes with an
API key, once - after which every name is a cache hit.

```
uv run warm_cache.py path/to/uv.lock path/to/package-lock.json   # specific files
uv run warm_cache.py --days 90     # widen the CVE window (default 14 days)
uv run warm_cache.py --full        # pull NVD's entire CVE catalog - see below first
```

**On `--full`:** it fetches all ~370,000 CVEs in NVD, which is ~185 sequential
requests: 10-20 minutes with an API key, 30-45 without. You almost never want
it - matching only consults recently-changed CVEs, which the default window
already covers, and `--days 90` covers more still. If you do run it, pages are
written to SQLite as they arrive (never held in memory) and progress prints
every couple of seconds, so you can watch it work rather than guess whether
it hung.

Re-run it occasionally to pick up newly published CVEs. It's incremental -
already-cached names are skipped, so a re-run only fetches what's new.

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
      "autoApprove": ["get_scan_command", "condense_lockfile", "scan_repo"]
    }
  }
}
```

Copy that URL and JSON block directly - nothing to fill in by hand.
`autoApprove` skips Cline's per-call confirmation prompt for those tools
(safe to leave in - none of them writes to or executes anything on the
caller's machine; drop any name from the list if you'd rather approve those
calls by hand).
It auto-detects the box's LAN-reachable IP; if that's wrong for your network
(behind NAT, inside a container, etc.), set `MCP_PUBLIC_HOST` to the correct
address/hostname and restart. `MCP_PORT` overrides the port (default 8765).
There's no built-in auth, so only expose this on a private/trusted network.

A `.env` file with `NVD_API_KEY` is optional but strongly recommended -
without it every NVD/CPE request is spaced 6s apart instead of 1s.

Separately, host Qwen2.5-14B-Instruct with tool calling on the same box:
```
vllm serve Qwen/Qwen2.5-14B-Instruct \
  --host 0.0.0.0 --port 8000 \
  --enable-auto-tool-choice --tool-call-parser hermes \
  --gpu-memory-utilization 0.85
```
Qwen2.5's own `tokenizer_config.json` already ships a working tool-calling
chat template (hermes-style `<tool_call>` blocks) at every size in the
family - unlike Mistral, no `--chat-template` override is needed, and this
is why moving up from the 7B variant (see below) needed no code changes to
`serve_mistral.py`'s response parsing, only the model name. Any other
OpenAI-compatible server (TGI, Ollama, `serve_mistral.py` in this repo, etc.)
works the same way from Cline's side; only the serving command differs.

**14B needs real headroom - check before running:**
`nvidia-smi --query-gpu=memory.total,memory.used,memory.free --format=csv`
first. Qwen2.5-14B-Instruct needs roughly 28-30GB of VRAM in bf16; the
`--gpu-memory-utilization 0.85` flag above caps how much of the GPU vLLM
will try to claim, which matters on a shared/multi-tenant box where other
processes may hold memory vLLM can't see reflected in a clean number. A 7B
variant (`Qwen/Qwen2.5-7B-Instruct`, ~14GB) is a safer fallback if VRAM is
tight - same tool-call format, same command shape, just less reliable in
practice at sticking to correct tool-call arguments than the 14B (see this
project's own history for why the jump was made). Note Qwen2.5-Instruct's
real context is 32768 tokens at every size - see "Keeping lockfiles small
enough to fit in context" below, since a raw lockfile can overflow that in
one message on a real dependency tree.

### In Cline (VS Code extension)

**Model** - Settings -> API Provider -> "OpenAI Compatible":
- Base URL: `http://<datalab-server>:8000/v1`
- API Key: any non-empty placeholder (vLLM ignores it unless you've
  configured auth)
- Model ID: `Qwen/Qwen2.5-14B-Instruct` (or whichever `MODEL_ID`/`vllm serve`
  argument you actually used)

**Tool** - "Configure MCP Servers" -> paste the JSON block `serve.py` printed.

The 300s timeout in that block matters: the first `scan_repo` call after the
server starts does a full NVD sync and can take 1-2 minutes. Cline's default
timeout is much shorter and will otherwise report a false failure.

### Use it

In Cline, open this repo and ask something like "check this repo's
dependencies for vulnerabilities." The whole workflow is three trivial
actions, and `.clinerules/` walks the model through them:

1. Call the `get_scan_command` MCP tool (no arguments) - it returns one
   terminal command with the server's current URL filled in.
2. Run that command - it POSTs the lockfile straight from disk to the
   server's `/scan` endpoint, streams live pipeline progress as each stage
   runs, and prints the finished triaged report.
3. Save the printed report to `reports/<date>-scan.md`.

The stream is the transparency layer: rather than an opaque wait, you watch
the actual pipeline work - components parsed, CycloneDX SBOM generated,
NVD/KEV sync state, how many package names were already CPE-cached vs
fetched, LogisticRegression-vs-RandomForest training and which model won at
what threshold, SHAP explainer construction, and the final triage counts.
The same log is appended to the saved report as a `## Pipeline` section, so
every report is a record of exactly which stages ran and how long each took.

### What a finding looks like

Every finding is written up twice over, so the report serves both a
non-specialist and a practitioner:

- **"What this means"** - one plain-English paragraph: whether it's being
  actively exploited right now (CISA KEV), what the CVSS score means in
  words rather than as a bare number, what kind of flaw it is (the CWE
  translated out of jargon - "an attacker can run their own scripts in
  another user's browser" rather than "CWE-79"), and whether OSV.dev
  independently agreed. Followed by a concrete **Fix** line.
- **The technical specifics** - severity and CVSS, CWE IDs with their
  proper names linked to MITRE, model confidence against the decision
  threshold, the OSV cross-check result, which NVD CPE vendor matched, the
  verbatim NVD description, and a link to the full record. For anything in
  the review queue, the top SHAP factors showing *why* the model hesitated.

The CWE translations live in `it_security_agent/cwe.py` (the CWE Top 25 plus
common library-level flaws); an unmapped ID degrades to the bare identifier
and its MITRE link rather than breaking the report.

If you ask for "an SBOM," the model appends `?include_sbom=true` to the
scan URL and a real CycloneDX document (not a description of one) comes
back inline with the findings. There is no way to pass in a pre-made SBOM,
by design (see the tamper-proofing note above) - `.clinerules/` also tells
the model not to go looking for one.

### Keeping lockfiles out of the model's context entirely

The load-bearing rule of this design: **lockfile content never passes
through the model's context window - not raw, not condensed.** A real
`uv.lock` is often hundreds of KB (this repo's own is 618KB / ~131K
tokens - 4x a 32K-context model's entire window), and it doesn't matter
*how* it gets into the conversation - a file-read tool, `type`/`cat`
output, or an MCP tool argument all end up in context just the same. Two
earlier designs learned this the hard way: a terminal-script flow where the
model `type`d the raw file (crashed the GPU with an out-of-memory error),
and an MCP-tool-only flow where the model dutifully *read* the file to pass
it as a tool argument (instantly overflowed its context - the read itself
was the failure).

The fix is architectural. The server exposes `POST /scan`: raw lockfile
bytes in, finished report out, in one shot -

```
curl -s -X POST http://<server>:8765/scan --data-binary @uv.lock
```

`curl` streams the file from disk straight to the server, which condenses
and scans it server-side; the model's context only ever holds the command
itself and the small final report it relays. The model never needs to be
told the server's URL either - a quick cloudflared tunnel mints a new
random hostname on every boot, so hardcoding it anywhere would rot
immediately. Instead, the `get_scan_command` MCP tool returns the command
with the current public URL already filled in, derived from the caller's
own connection: every MCP request arrives *through* the tunnel, carrying
the live hostname in its `Host` header (and the original scheme in
`X-Forwarded-Proto`), so the server reads its own address off the request
being handled. `.clinerules/` tells the model to always ask that tool
rather than guessing, remembering, or fabricating a URL.

Secondary paths, for completeness: `POST /condense` returns just the
condensed `name==version` list (~99.5% smaller than the raw file - 618KB ->
3KB on this repo's own lockfile) without scanning; the `scan_repo` and
`condense_lockfile` MCP tools accept lockfile *content* for the rare case
it's already legitimately in-context; `condense_lockfile.py` (repo root) is
a thin CLI wrapper for use outside Cline; and `serve_mistral.py` rejects
any prompt over `MAX_INPUT_TOKENS` (default 28000) with a clear HTTP 413
before `model.generate()`, so an oversized prompt fails cleanly instead of
crashing the server.

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
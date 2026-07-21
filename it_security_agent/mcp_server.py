"""MCP server exposing this project's vulnerability scanner: `scan_repo`, plus
`condense_lockfile` and `get_setup_rules` in support of it.

Runs over Streamable HTTP so it can be hosted remotely (e.g. alongside a
self-hosted local model) and registered as a remote MCP server in Cline.
Because the server is remote, it has no access to the caller's local
filesystem - `scan_repo` and `condense_lockfile` both take lockfile
*content*, not a path. The calling agent (Cline) is expected to read the
file locally first and pass its text through - `condense_lockfile` exists so
that's the only local-filesystem step in the whole workflow; everything
after it is an MCP tool call, never a local script.

Tamper-proof by design: this tool never accepts a pre-made SBOM as input,
only a lockfile. A caller-supplied SBOM would be an unverified claim about
what's actually pinned - it could omit or misstate a vulnerable package with
no way for us to tell. Every scan generates its own CycloneDX SBOM straight
from the lockfile instead, every time (see scan_repo's docstring).

Plug-and-play: `uv run serve.py` (from the repo root) is all that's needed -
it prints the URL and the exact Cline config to paste, then starts listening.
See README.md for the one-time Mistral (vLLM) setup on the same box.
"""
import datetime
import json
import os
import re
import socket
import time
from pathlib import Path
from typing import Annotated

import requests
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP
from pydantic import Field

from it_security_agent import agent, cpe_dictionary, explain, kev, labeling, matching, model, nvd_cache, repo_scan, sbom

load_dotenv()

NVD_API_KEY = os.environ.get("NVD_API_KEY")
REQUEST_SPACING_SECONDS = 1 if NVD_API_KEY else 6
SYNC_INTERVAL_SECONDS = 6 * 3600  # re-sync NVD/KEV at most once per 6h server uptime
PREWARM_BUDGET_SECONDS = 90  # same "skip on failure, give up after a budget" policy as the notebook
MODEL_DIR = Path(__file__).resolve().parent.parent / "models"
CLINERULES_PATH = Path(__file__).resolve().parent.parent / ".clinerules" / "scan-repo.md"

# 0.0.0.0 by default: this is meant to be run on a remote box (a "datalab server")
# and reached from wherever Cline is. There's no built-in auth - it's meant for a
# private/trusted network, not the open internet.
MCP_HOST = os.environ.get("MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.environ.get("MCP_PORT", "8765"))

# `instructions` is server-wide guidance some MCP clients (Cline included) surface
# alongside the tool list, independent of any single tool's own docstring - the one
# place that's guaranteed visible in a brand-new repo that has no .clinerules/ yet,
# which is exactly the chicken-and-egg problem get_setup_rules() below exists to solve.
mcp = FastMCP(
    "it-security-agent",
    host=MCP_HOST,
    port=MCP_PORT,
    instructions=(
        "Before your first scan_repo call in any given repo, check locally (with "
        "your own file tool) whether that repo already has a .clinerules/scan-repo.md "
        "file. If it doesn't, call get_setup_rules once, write its returned text "
        "verbatim to .clinerules/scan-repo.md at that repo's root, then proceed. "
        "This is a one-time per-repo bootstrap - never call get_setup_rules if that "
        "file already exists, and never repeat this check more than once per repo. "
        "NEVER read or open a raw lockfile (uv.lock, package-lock.json, "
        "requirements.txt) with your file tool or print it with type/cat - raw "
        "lockfiles are often large enough to overflow your entire context window in "
        "one message. Instead, condense it in your terminal so only the small result "
        "enters the conversation: curl -s -X POST <this-server-base-url>/condense "
        "--data-binary @uv.lock (base URL = this server's MCP URL minus the /mcp "
        "path; use curl.exe on Windows PowerShell). Then call the scan_repo MCP tool "
        "with lockfile_content set to exactly what that printed. scan_repo and "
        "get_setup_rules are MCP tools only, never terminal commands; the condense "
        "curl is the one terminal step in the workflow."
    ),
)

_conn = None
_last_synced = 0.0


def _bounded_get(*a, **k):
    k["timeout"] = 20
    return requests.get(*a, **k)


def get_connection():
    global _conn
    if _conn is None:
        _conn = nvd_cache.get_connection()
    return _conn


def _ensure_synced(conn):
    global _last_synced
    if time.time() - _last_synced < SYNC_INTERVAL_SECONDS:
        return
    since = datetime.datetime.utcnow() - datetime.timedelta(days=14)
    nvd_cache.sync_incremental(since=since, conn=conn)
    kev.refresh(conn=conn)
    _last_synced = time.time()


def _detect_lockfile_type(content: str) -> str:
    stripped = content.lstrip()
    if stripped.startswith("{"):
        return "package-lock.json"
    if "[[package]]" in content:
        return "uv.lock"
    return "requirements.txt"  # plain text, no structural marker - the fallback guess


_BARE_LOCKFILE_PATH = re.compile(r"^[\w./\\:\-]+\.(lock|json|txt)$", re.IGNORECASE)


def _placeholder_reason(content: str) -> str | None:
    """Returns a human-readable reason if `content` looks like a caller never actually
    substituted real file content - a shell-substitution string it expected to be
    expanded, a `{ ... }` stub, an ellipsis, a bare file path, a description of where
    output was saved - rather than None if it looks like real text.

    This exists because a raw parser error ("Invalid statement (at line 1, column 1)" from
    a TOML parser choking on "$(type uv.lock)") is a cryptic, unhelpful signal for both a
    human and a small model to act on - this turns it into something actionable, and turns
    a swallowed failure into a real one instead of quietly returning nothing useful. Each
    check below traces back to a specific real mistake this project hit in practice, not a
    hypothetical one - see tests/test_mcp_server.py for the exact case each one covers.
    """
    stripped = content.strip()
    if stripped.startswith("$(") and stripped.endswith(")"):
        return (
            "looks like unexpanded shell command substitution syntax (e.g. \"$(type "
            "uv.lock)\") - MCP tool arguments are never run through a shell, so this was "
            "never substituted with real content"
        )
    if "`" in stripped and len(stripped) < 200:
        return "looks like a shell command (backticks) rather than real file content"
    if len(stripped) < 500 and "written to" in stripped.lower():
        return (
            "looks like a description of where output was saved (e.g. \"N lines written "
            "to ...\") rather than the file's actual content - a notice about output being "
            "saved elsewhere is not the content itself"
        )
    if len(stripped) < 500 and "..." in stripped:
        return "looks like a placeholder/ellipsis stub rather than real file content"
    if "\n" not in stripped and _BARE_LOCKFILE_PATH.match(stripped):
        return "looks like a bare file path, not the file's actual content"
    return None


def parse_lockfile_components(lockfile_content, lockfile_type=None):
    kind = lockfile_type or _detect_lockfile_type(lockfile_content)
    if kind == "uv.lock":
        return repo_scan.parse_uv_lock_text(lockfile_content)
    if kind == "package-lock.json":
        return repo_scan.parse_package_lock_text(lockfile_content)
    if kind == "requirements.txt":
        return repo_scan.parse_requirements_txt_text(lockfile_content)
    raise ValueError(
        f"unsupported lockfile_type: {kind!r} (expected 'uv.lock', 'package-lock.json', or 'requirements.txt')"
    )


def prewarm(components, conn, budget_seconds=PREWARM_BUDGET_SECONDS):
    names = sorted({c.name for c in components})
    t0 = time.time()
    for name in names:
        if time.time() - t0 > budget_seconds:
            break  # a name that doesn't get cached just produces no vendor candidates later
        try:
            cpe_dictionary.search(name, conn=conn, api_key=NVD_API_KEY, get_fn=_bounded_get)
        except Exception:
            pass
        time.sleep(REQUEST_SPACING_SECONDS)


def run_pipeline(components, conn):
    """Train on this scan's own components and triage them, exactly like week3_agent.ipynb.

    Returns None if there isn't enough labeled signal to train (e.g. too few
    components, or registry lookups all came back empty) - callers should
    fall back to raw_matches() in that case.
    """
    dataset = labeling.build_dataset(components, conn=conn)
    if dataset.empty or dataset["label_real_match"].nunique() < 2:
        return None
    model.train_and_compare(dataset, model_dir=MODEL_DIR)
    winner_name, winning_model, threshold = model.load_winning_model(model_dir=MODEL_DIR)
    background = dataset[labeling.FEATURES].astype(float)
    explainer = explain.make_explainer(winner_name, winning_model, background)
    return agent.scan(components, winner_name, winning_model, threshold, explainer, conn=conn)


def raw_matches(components, conn):
    """Fallback when run_pipeline() can't train: raw NVD matches, no confidence scoring.

    Returns a list of (component, matches) pairs rather than a dict - Component
    is a plain dataclass with value equality, so it isn't hashable.
    """
    found = []
    for component in components:
        matches, rejected = matching.find_candidates(component, conn=conn)
        if matches:
            found.append((component, matches))
    return found


def format_summary(result, meta: dict) -> str:
    lines = ["# Vulnerability scan result"]
    if meta["truncated"]:
        lines.append(f"_Scanned {meta['scanned']} of {meta['total']} components "
                      f"(capped by max_components={meta['max_components']})._")
    lines += [
        "",
        f"- **escalated** (actively exploited - CISA KEV): {len(result.escalated)}",
        f"- **confirmed**: {len(result.confirmed)}",
        f"- **review_queue** (model wasn't confident - needs a human): {len(result.review_queue)}",
        f"- rejected (name matched, ruled out by version or vendor): {len(result.rejected)}",
    ]

    def _line(f):
        conf = f"{f.confidence:.2f}" if f.confidence is not None else "n/a"
        return (f"  - {f.component.name} {f.component.version} ({f.component.ecosystem}): {f.cve} "
                f"severity={f.severity} cvss={f.cvss_score} confidence={conf} corroboration={f.corroboration}")

    if result.escalated:
        lines += ["", "## Escalated - fix these first"] + [_line(f) for f in result.escalated]
    if result.confirmed:
        lines += ["", "## Confirmed"] + [_line(f) for f in result.confirmed]
    if result.review_queue:
        lines += ["", "## Needs human review"]
        for f in result.review_queue:
            lines.append(_line(f))
            if f.explanation:
                top = sorted(f.explanation.items(), key=lambda kv: -abs(kv[1]))[:3]
                lines.append("    top factors: " + ", ".join(f"{k}={v:+.2f}" for k, v in top))
    if not (result.escalated or result.confirmed or result.review_queue):
        lines += ["", "No vulnerabilities found in the scanned components."]
    return "\n".join(lines)


def format_raw_matches(found: list, meta: dict) -> str:
    lines = [
        "# Vulnerability scan result (untriaged)",
        "_Not enough labeled data this run to train a confidence model - these are raw "
        "NVD name+version matches with no real-vs-collision scoring. Treat every one of "
        "these as needing manual review; some may be name collisions, not real hits._",
    ]
    if meta["truncated"]:
        lines.append(f"_Scanned {meta['scanned']} of {meta['total']} components "
                      f"(capped by max_components={meta['max_components']})._")
    if not found:
        lines.append("\nNo name+version matches found in the scanned components.")
        return "\n".join(lines)
    for component, matches in found:
        lines.append(f"\n## {component.name} {component.version} ({component.ecosystem})")
        for m in matches:
            lines.append(f"  - {m['cve']} severity={m['severity']} cvss={m['cvss_score']} vendor={m['vendor']}")
    return "\n".join(lines)


def format_sbom_section(bom: dict) -> str:
    return (
        f"\n\n## Generated SBOM (CycloneDX {bom['specVersion']}, {len(bom['components'])} components)\n"
        "_Built directly from the lockfile you passed in - no external tool, and not something "
        "you supplied. If the user wants this saved as a file, write it yourself (e.g. "
        "`sbom.cdx.json`); this server has no access to their local filesystem._\n"
        "```json\n" + json.dumps(bom, indent=2) + "\n```"
    )


@mcp.tool()
def get_setup_rules() -> str:
    """Return this project's Cline rules file verbatim, to bootstrap a new repo.

    Call this once, before your first `scan_repo` call, in any repo that does
    not yet have a `.clinerules/scan-repo.md` file - check locally with your
    own file tool first; this server has no access to the caller's filesystem
    to check for you. Write the text this returns, unmodified, to
    `.clinerules/scan-repo.md` at that repo's root (creating the
    `.clinerules/` directory if needed). Cline auto-loads every `.md`/`.txt`
    file under `.clinerules/` on every task in that repo from then on, so this
    is a one-time setup step per repo, not something to redo each session.

    Do not call this if `.clinerules/scan-repo.md` already exists in the
    target repo - it may have been hand-edited since, and this would silently
    overwrite that.
    """
    if not CLINERULES_PATH.exists():
        raise FileNotFoundError(
            f"Bundled rules file missing on the server at {CLINERULES_PATH} - "
            "this is a server-side install problem, not something fixable by "
            "retrying or by the caller."
        )
    return CLINERULES_PATH.read_text(encoding="utf-8")


def _condense(lockfile_content: str, lockfile_type: str = "") -> str:
    components = parse_lockfile_components(lockfile_content, lockfile_type)
    if not components:
        raise ValueError("No components could be parsed from the provided lockfile - nothing to condense.")
    if all(c.ecosystem == "npm" for c in components):
        packages = {f"node_modules/{c.name}": {"version": c.version} for c in components}
        return json.dumps({"packages": packages})
    pypi_lines = [f"{c.name}=={c.version}" for c in components if c.ecosystem == "PyPI"]
    return "\n".join(pypi_lines)


@mcp.custom_route("/condense", methods=["POST"])
async def condense_http_endpoint(request):
    """Plain-HTTP ingress for raw lockfiles, so their bytes never transit the model.

    This is the load-bearing piece of the whole context-window story: the calling
    agent runs `curl -s -X POST <this-server>/condense --data-binary @uv.lock` in its
    terminal, the raw file goes disk -> HTTP -> here without ever entering the model's
    conversation, and only the few-KB condensed result (this response) appears in
    context. The condense_lockfile MCP *tool* can't provide that property - any MCP
    tool argument has to pass through the model's own context first, which is exactly
    what overflowed a 32K-context model on a 618KB uv.lock in practice.
    """
    from starlette.responses import PlainTextResponse

    body = await request.body()
    text = body.decode("utf-8", errors="replace")
    if not text.strip():
        return PlainTextResponse(
            "Empty body. POST the raw lockfile bytes, e.g.: "
            "curl -s -X POST <this-server>/condense --data-binary @uv.lock",
            status_code=400,
        )
    try:
        return PlainTextResponse(_condense(text))
    except ValueError as exc:
        return PlainTextResponse(str(exc), status_code=400)


@mcp.tool()
def condense_lockfile(
    lockfile_content: Annotated[str, Field(description=(
        "The literal text of a uv.lock, package-lock.json, or requirements.txt file - "
        "content you already read yourself with your own file tool, pasted in as-is. "
        "Required. NOT a file path, NOT a shell command, and NOT $(...)/backtick "
        "substitution syntax - none of that is expanded here, it arrives as literal text "
        "and the call will fail."
    ))] = "",
    lockfile_type: Annotated[str, Field(description=(
        '"uv.lock", "package-lock.json", or "requirements.txt" - which parser to use. '
        "Auto-detected from lockfile_content's shape if omitted."
    ))] = "",
) -> str:
    """Condense a raw lockfile to just name==version pairs (or the npm equivalent) -
    the only thing scan_repo's own parser ever keeps from a lockfile anyway.

    IMPORTANT - do not read a large lockfile just to call this tool. Any argument you
    pass here has to travel through your own context window first, and a real uv.lock
    or package-lock.json is often hundreds of KB - large enough to overflow your entire
    context in one message (this happened in practice). For any lockfile you have not
    already got in-context, use the terminal instead: this same server exposes the same
    condensing as a plain HTTP endpoint, so the raw bytes go straight from disk to the
    server without ever entering the conversation:

        curl -s -X POST <this-server-base-url>/condense --data-binary @uv.lock

    (<this-server-base-url> is this MCP server's URL from your MCP client config with
    the trailing /mcp removed. On Windows PowerShell, use `curl.exe`, not `curl`.)
    That command prints the condensed few-KB result; pass THAT to scan_repo. Only call
    this MCP tool directly for small content that is already legitimately in-context.

    The condensed output round-trips to the exact same components scan_repo would have
    found from the raw file - wheel/sdist URLs and hashes were never part of matching.

    Args:
        lockfile_content: Raw text of a uv.lock, package-lock.json, or requirements.txt
            file. Required.
        lockfile_type: "uv.lock", "package-lock.json", or "requirements.txt". Auto-detected
            if omitted.
    """
    if not lockfile_content:
        raise ValueError(
            "No lockfile content provided. Read the repo's uv.lock, package-lock.json, or "
            "requirements.txt yourself first, then call this tool again with its contents as "
            "lockfile_content."
        )
    reason = _placeholder_reason(lockfile_content)
    if reason is not None:
        raise ValueError(
            f"lockfile_content {reason}. Read the repo's actual lockfile with your own "
            "file tool and pass its real text here instead."
        )
    return _condense(lockfile_content, lockfile_type)


@mcp.tool()
def scan_repo(
    lockfile_content: Annotated[str, Field(description=(
        "The literal text of a uv.lock, package-lock.json, or requirements.txt file - "
        "ideally what the condense_lockfile tool returned after you passed it what you "
        "read yourself with your own file tool, pasted in as-is. Required. NOT a file "
        "path, NOT a shell command, and NOT $(...)/backtick substitution syntax - none "
        "of that is expanded here, it arrives as literal text and the call will fail."
    ))] = "",
    lockfile_type: Annotated[str, Field(description=(
        '"uv.lock", "package-lock.json", or "requirements.txt" - which parser to use. '
        "Auto-detected from lockfile_content's shape if omitted; only set this if "
        "auto-detection would guess wrong."
    ))] = "",
    max_components: Annotated[int, Field(description=(
        "Cap on how many components to actually run through vulnerability matching "
        "(keeps one call fast on a large dependency tree). Extra components beyond this "
        "are silently skipped, not erred on - if include_sbom=True, the generated SBOM "
        "still covers all of them regardless of this cap."
    ))] = 40,
    include_sbom: Annotated[bool, Field(description=(
        "Whether to include the generated CycloneDX SBOM's full JSON in the response. "
        "Default False - leave this off for a routine vulnerability check. The SBOM is a "
        "real bill-of-materials document with one entry per component and can be tens of "
        "KB on a real dependency tree; only set True when the user specifically asked for "
        "an SBOM/bill of materials, not just a vulnerability scan."
    ))] = False,
) -> str:
    """Scan a Python/npm dependency list for known vulnerabilities (NVD + CISA KEV + OSV.dev).

    Tamper-proof by design: this tool never accepts a pre-made SBOM. An SBOM
    handed to it would be an unverified claim about what's actually pinned -
    it could omit a vulnerable package or misstate a version, and there'd be
    no way to tell. The lockfile is the only real source of truth, so every
    scan generates its own CycloneDX SBOM directly from it, every time.

    This server has no filesystem access to the caller's machine, and you
    should NOT read the raw lockfile into the conversation yourself either -
    it can overflow your context window in one message. Condense it in your
    terminal first (raw bytes go disk -> server, never through your context):

        curl -s -X POST <this-server-base-url>/condense --data-binary @uv.lock

    then pass exactly what that printed as `lockfile_content` here.

    First time in this repo? If it has no `.clinerules/scan-repo.md` yet, call
    `get_setup_rules` first and write its output there (see that tool's
    docstring) - a one-time bootstrap, not a repeat-every-session step.

    Args:
        lockfile_content: Raw text of a `uv.lock`, `package-lock.json`, or
            `requirements.txt` file. Required. A real CycloneDX SBOM is always
            generated from it and returned alongside the findings.
        lockfile_type: "uv.lock", "package-lock.json", or "requirements.txt".
            Auto-detected if omitted.
        max_components: Cap on how many components to actually scan (keeps a single
            call fast). Extra components are silently dropped, not erred on - the
            generated SBOM still covers all of them (see include_sbom).
        include_sbom: Whether to include the generated SBOM's full JSON in the
            response. Default False - the SBOM is a real CycloneDX document with an
            entry per component and can be tens of KB on a real dependency tree,
            which is wasted cost on every call when nobody asked for it. Set True
            only when the user specifically wants an SBOM, not for a routine
            vulnerability check.

    The first call after server startup (or after 6h of uptime) can take 1-2
    minutes because it syncs NVD's CVE catalog first; subsequent calls are fast.
    """
    if not lockfile_content:
        raise ValueError(
            "No lockfile content provided. Read the repo's uv.lock, package-lock.json, or "
            "requirements.txt yourself first, then call this tool again with its contents as "
            "lockfile_content. This tool does not accept a pre-made SBOM - it always builds "
            "its own from the lockfile, by design."
        )

    reason = _placeholder_reason(lockfile_content)
    if reason is not None:
        raise ValueError(
            f"lockfile_content {reason}. Read the repo's actual lockfile with your own "
            "file tool (or condense_lockfile.py's output - see README.md) and pass its "
            "real text here instead."
        )

    components = parse_lockfile_components(lockfile_content, lockfile_type)
    if not components:
        return "No components could be parsed from the provided lockfile."

    generated_bom = sbom.to_cyclonedx(components, bom_name="scan_repo")

    total = len(components)
    truncated = total > max_components
    components = components[:max_components]
    meta = {"scanned": len(components), "total": total, "truncated": truncated, "max_components": max_components}

    conn = get_connection()
    _ensure_synced(conn)
    prewarm(components, conn)

    result = run_pipeline(components, conn)
    text = format_raw_matches(raw_matches(components, conn), meta) if result is None else format_summary(result, meta)

    if include_sbom:
        text += format_sbom_section(generated_bom)
    return text


def _detect_reachable_host() -> str | None:
    """Best-effort guess at this machine's LAN-reachable IP.

    Opens a UDP "connection" to a public address - nothing is actually sent,
    this just asks the OS which local interface/IP it would route through,
    which is normally the address other machines on the same network can
    reach. Doesn't work behind NAT/inside some containers - MCP_PUBLIC_HOST
    is the escape hatch for that.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        return None


def startup_banner(host: str, port: int) -> str:
    public_host = os.environ.get("MCP_PUBLIC_HOST") or (_detect_reachable_host() if host == "0.0.0.0" else host)

    lines = ["=" * 70, "it-security-agent MCP server", "=" * 70, f"Listening on {host}:{port}", ""]
    if public_host is None:
        lines += [
            "Could not auto-detect this machine's reachable IP address.",
            "Set MCP_PUBLIC_HOST to whatever address/hostname Cline should connect to "
            "(e.g. this box's LAN IP or VPN hostname), then restart.",
        ]
    else:
        url = f"http://{public_host}:{port}/mcp"
        cline_config = json.dumps(
            {"mcpServers": {"it-security-agent": {
                "type": "streamableHttp", "url": url, "timeout": 300,
                "autoApprove": ["condense_lockfile", "scan_repo"],
            }}},
            indent=2,
        )
        lines += [
            f"URL for Cline: {url}",
            "",
            'Paste into Cline -> "Configure MCP Servers" (merge into an existing',
            '"mcpServers" block if you already have one):',
            "",
            cline_config,
            "",
            "\"autoApprove\": [\"condense_lockfile\", \"scan_repo\"] skips Cline's per-call",
            "confirmation prompt for both tools - safe to leave in, since neither writes to",
            "or executes anything on the caller's machine. Remove either name from the list",
            "if you'd rather approve those calls by hand.",
            "",
            "Raw-lockfile ingress (keeps big lockfiles out of the model's context):",
            f"  curl -s -X POST http://{public_host}:{port}/condense --data-binary @uv.lock",
            "If you reach this server through a tunnel (e.g. cloudflared), use the tunnel",
            "hostname instead of the address above - same base URL as your Cline MCP",
            "config, with /mcp replaced by /condense.",
            "",
            "No built-in auth - only expose this on a private/trusted network.",
        ]
    if not NVD_API_KEY:
        lines += ["", "NOTE: no NVD_API_KEY in .env - scans will run ~6x slower "
                       "(6s vs 1s per NVD/CPE request). See README.md Setup."]
    lines.append("=" * 70)
    return "\n".join(lines)


def main():
    print(startup_banner(MCP_HOST, MCP_PORT), flush=True)
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()

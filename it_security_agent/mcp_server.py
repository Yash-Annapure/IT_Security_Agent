"""MCP server exposing this project's vulnerability scanner as one tool: `scan_repo`.

Runs over Streamable HTTP so it can be hosted remotely (e.g. alongside a
self-hosted Mistral-7B-Instruct) and registered as a remote MCP server in
Cline. Because the server is remote, it has no access to the caller's local
filesystem - `scan_repo` takes lockfile/SBOM *content*, not a path. The
calling agent (Cline) is expected to read the file locally first and pass
its text through.

Run with: `uv run it-security-agent-mcp` (see README.md for the full
Cline + self-hosted-Mistral setup).
"""
import datetime
import json
import os
import time
from pathlib import Path

import requests
from dotenv import load_dotenv
from mcp.server.fastmcp import FastMCP

from it_security_agent import agent, cpe_dictionary, explain, kev, labeling, matching, model, nvd_cache, repo_scan, sbom

load_dotenv()

NVD_API_KEY = os.environ.get("NVD_API_KEY")
REQUEST_SPACING_SECONDS = 1 if NVD_API_KEY else 6
SYNC_INTERVAL_SECONDS = 6 * 3600  # re-sync NVD/KEV at most once per 6h server uptime
PREWARM_BUDGET_SECONDS = 90  # same "skip on failure, give up after a budget" policy as the notebook
MODEL_DIR = Path(__file__).resolve().parent.parent / "models"

MCP_HOST = os.environ.get("MCP_HOST", "127.0.0.1")
MCP_PORT = int(os.environ.get("MCP_PORT", "8765"))

mcp = FastMCP("it-security-agent", host=MCP_HOST, port=MCP_PORT)

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


def parse_components(lockfile_content=None, lockfile_type=None, sbom_content=None, sbom_format=None):
    components = []
    if lockfile_content:
        components += parse_lockfile_components(lockfile_content, lockfile_type)
    if sbom_content:
        data = json.loads(sbom_content)
        kind = sbom_format or ("cyclonedx" if "bomFormat" in data else "spdx")
        if kind == "cyclonedx":
            components += sbom.parse_cyclonedx(data)
        elif kind == "spdx":
            parsed, _ = sbom.parse_spdx(data)
            components += parsed
        else:
            raise ValueError(f"unsupported sbom_format: {kind!r} (expected 'cyclonedx' or 'spdx')")
    return components


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
        "_Built directly from the lockfile you passed in - no external tool. If the user wants "
        "this saved as a file, write it yourself (e.g. `sbom.cdx.json`); this server has no "
        "access to their local filesystem._\n```json\n" + json.dumps(bom, indent=2) + "\n```"
    )


@mcp.tool()
def scan_repo(
    lockfile_content: str | None = None,
    lockfile_type: str | None = None,
    sbom_content: str | None = None,
    sbom_format: str | None = None,
    max_components: int = 40,
    include_sbom: bool = True,
) -> str:
    """Scan a Python/npm dependency list for known vulnerabilities (NVD + CISA KEV + OSV.dev).

    This server has no filesystem access to the caller's machine - read the
    lockfile or SBOM file yourself first, then pass its raw text here.

    Args:
        lockfile_content: Raw text of a `uv.lock`, `package-lock.json`, or
            `requirements.txt` file. If given (and sbom_content isn't), a real
            CycloneDX SBOM is generated from it and returned alongside the
            findings - this is "create an SBOM from repo files," not just
            scanning, when no SBOM already exists.
        lockfile_type: "uv.lock", "package-lock.json", or "requirements.txt".
            Auto-detected if omitted.
        sbom_content: Raw JSON text of an existing CycloneDX or SPDX SBOM file.
            Use this instead of lockfile_content when the repo already has one -
            nothing is (re)generated in that case.
        sbom_format: "cyclonedx" or "spdx". Auto-detected if omitted.
        max_components: Cap on how many components to actually scan (keeps a single
            call fast). Extra components are silently dropped, not erred on.
        include_sbom: Whether to include the generated SBOM's full JSON in the
            response (only applies when lockfile_content produced it). Default True.

    At least one of lockfile_content or sbom_content is required. Both may be
    given together. The first call after server startup (or after 6h of
    uptime) can take 1-2 minutes because it syncs NVD's CVE catalog first;
    subsequent calls are fast.
    """
    if not lockfile_content and not sbom_content:
        raise ValueError(
            "No input provided. Read the repo's uv.lock/package-lock.json/requirements.txt "
            "or SBOM file yourself first, then call this tool again with its contents as "
            "lockfile_content or sbom_content."
        )

    components = parse_components(lockfile_content, lockfile_type, sbom_content, sbom_format)
    if not components:
        return "No components could be parsed from the provided content."

    # Only generate an SBOM from a lockfile - if the caller already handed us an SBOM
    # (sbom_content), there's nothing to generate, it already exists.
    generated_bom = sbom.to_cyclonedx(components, bom_name="scan_repo") if lockfile_content else None

    total = len(components)
    truncated = total > max_components
    components = components[:max_components]
    meta = {"scanned": len(components), "total": total, "truncated": truncated, "max_components": max_components}

    conn = get_connection()
    _ensure_synced(conn)
    prewarm(components, conn)

    result = run_pipeline(components, conn)
    text = format_raw_matches(raw_matches(components, conn), meta) if result is None else format_summary(result, meta)

    if include_sbom and generated_bom is not None:
        text += format_sbom_section(generated_bom)
    return text


def main():
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()

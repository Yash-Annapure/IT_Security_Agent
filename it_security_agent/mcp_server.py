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
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field

from it_security_agent import (
    agent, cpe_dictionary, cwe, explain, kev, labeling, matching, model, nvd_cache, repo_scan, sbom,
)

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
        "one message. The whole scan is three trivial actions: (1) call the "
        "get_scan_command tool, (2) run the single command it returns, exactly as "
        "printed, (3) save that command's printed output as the report. Never guess "
        "or reuse a server URL (it changes on reboot - get_scan_command always has "
        "the current one), never invent a web address for any MCP tool, and never "
        "wrap the command in $(...) or nest it inside another command."
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


# NVD's published catalog size, for reporting how much of it this cache actually holds.
# Only ever used to contextualise a result - never to gate a scan.
NVD_CATALOG_SIZE = 368_000
# Below this, "no vulnerabilities found" says more about the cache than about the code.
THIN_CACHE_FRACTION = 0.9


def _cache_coverage(conn):
    """How much of NVD this cache holds, so a clean result can be read in context.

    Matching can only find CVEs that are cached. A partial sync therefore produces a
    reassuringly empty report rather than an error, which is the most dangerous way for
    this tool to be wrong - so every report states its own coverage. Returns None when
    the cache can't be read at all: a report with no coverage claim is honest, a report
    claiming zero coverage would not be.
    """
    try:
        cves = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
    except Exception:
        return None
    try:
        kev_count = conn.execute("SELECT COUNT(*) FROM kev").fetchone()[0]
    except Exception:
        kev_count = 0  # KEV table is created on first refresh; absent just means none yet
    return {
        "cves": cves,
        "kev": kev_count,
        "fraction": cves / NVD_CATALOG_SIZE,
        "thin": cves / NVD_CATALOG_SIZE < THIN_CACHE_FRACTION,
    }


def _ensure_synced(conn):
    global _last_synced
    if time.time() - _last_synced < SYNC_INTERVAL_SECONDS:
        return
    since = datetime.datetime.utcnow() - datetime.timedelta(days=14)
    nvd_cache.sync_incremental(since=since, conn=conn)
    kev.refresh(conn=conn)
    _last_synced = time.time()


def _start_background_sync():
    """Kick off the NVD/KEV sync in a daemon thread at server startup.

    The sync takes 1-2 minutes cold - previously it ran lazily inside the FIRST scan
    request, which pushed that request's total time past Cloudflare's ~100s proxy
    timeout and returned a 524 to the caller. Doing it at startup means it has usually
    finished long before anyone scans, and the request path's _ensure_synced() becomes
    a no-op (the thread updates _last_synced on success). Uses its own SQLite
    connection - connections aren't shareable across threads.
    """
    import threading

    def work():
        try:
            # Opening the cache also runs the one-time product-index backfill if it's
            # outstanding, so a cold server absorbs it here rather than inside a request.
            _ensure_synced(nvd_cache.get_connection())
            print("[sync] NVD/KEV background sync complete.", flush=True)
        except Exception as exc:
            # A failed startup sync isn't fatal - the request path will retry lazily.
            print(f"[sync] background sync failed ({exc}) - will retry on first scan.", flush=True)

    threading.Thread(target=work, daemon=True, name="nvd-kev-sync").start()


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


def prewarm(components, conn, budget_seconds=PREWARM_BUDGET_SECONDS, step=None):
    names = sorted({c.name for c in components})
    if step is not None:
        # Reported here rather than by the caller so the cache-hit logic lives in one
        # place - this function already owns it.
        to_fetch = [n for n in names if not cpe_dictionary.is_cached(n, conn=conn)]
        if to_fetch:
            step(f"Prewarming CPE vendor data: {len(names) - len(to_fetch)}/{len(names)} already "
                 f"cached, fetching up to {len(to_fetch)} from NVD ({budget_seconds}s budget, "
                 f"{REQUEST_SPACING_SECONDS}s spacing)...")
        else:
            step(f"CPE vendor data: all {len(names)} package names already cached (no NVD calls needed)")
    t0 = time.time()
    for name in names:
        # Cache hits make no network request, so they need no rate-limit spacing and
        # cost no budget. This is what makes repeat scans fast: previously every name
        # paid the sleep unconditionally, ~40-90s of pure sleeping per scan even when
        # every single name was already cached from the last run.
        if cpe_dictionary.is_cached(name, conn=conn):
            continue
        if time.time() - t0 > budget_seconds:
            break  # a name that doesn't get cached just produces no vendor candidates later
        try:
            cpe_dictionary.search(name, conn=conn, api_key=NVD_API_KEY, get_fn=_bounded_get)
        except Exception:
            pass
        time.sleep(REQUEST_SPACING_SECONDS)


def run_pipeline(components, conn, step=None, meta=None):
    """Train on this scan's own components and triage them, exactly like week3_agent.ipynb.

    Returns None if there isn't enough labeled signal to train (e.g. too few
    components, or registry lookups all came back empty) - callers should
    fall back to raw_matches() in that case.

    `step` is an optional progress callback (see _run_scan) - each stage reports
    through it so callers can surface what the pipeline is doing.
    """
    def report(message):
        if step is not None:
            step(message)

    dataset = labeling.build_dataset(components, conn=conn)
    if dataset.empty or dataset["label_real_match"].nunique() < 2:
        return None
    report(f"Built training set: {len(dataset)} candidate matches, {len(labeling.FEATURES)} features")
    report("Training + comparing LogisticRegression vs RandomForest (risk weighting FN x10 + FP x1)...")
    model.train_and_compare(dataset, model_dir=MODEL_DIR)
    winner_name, winning_model, threshold = model.load_winning_model(model_dir=MODEL_DIR)
    report(f"Winning model: {winner_name} (decision threshold {threshold:.2f})")
    if meta is not None:
        meta["model"] = {"name": winner_name, "threshold": threshold,
                         "training_rows": len(dataset), "features": len(labeling.FEATURES)}
    background = dataset[labeling.FEATURES].astype(float)
    explainer = explain.make_explainer(winner_name, winning_model, background)
    report("Built SHAP explainer - scoring every match and applying the triage policy...")
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


def _coverage_caveat(meta: dict, found_anything: bool) -> list:
    """State how much of NVD was searched. Matching only finds cached CVEs, so a thin
    cache yields a reassuringly empty report - never let that read as "clean"."""
    cache = meta.get("cache")
    if not cache:
        return []
    lines = ["", f"_Searched {cache['cves']:,} cached CVEs (~{cache['fraction']:.0%} of NVD's "
                 f"~{NVD_CATALOG_SIZE:,}) and {cache['kev']:,} CISA known-exploited entries._"]
    if not cache["thin"]:
        return lines
    if found_anything:
        return lines + ["", "> **Coverage caveat:** the cache is incomplete, so this list is a "
                            "lower bound - other vulnerabilities may simply not be cached yet."]
    return lines + ["", "> **This is not a clean bill of health.** Only cached CVEs can be "
                        f"matched, and this cache holds ~{cache['fraction']:.0%} of NVD. Finish "
                        "`uv run warm_cache.py --full` before treating an empty result as real."]


def _verdict(result, meta: dict) -> list:
    """The headline answer - vulnerabilities or not - stated before any section."""
    actionable = len(result.escalated) + len(result.confirmed)
    review = len(result.review_queue)

    if actionable:
        headline = (f"**VULNERABILITIES FOUND: {actionable}** ({len(result.escalated)} actively "
                    f"exploited, {len(result.confirmed)} confirmed)"
                    + (f", plus {review} needing human review." if review else "."))
    elif review:
        headline = (f"**NO CONFIRMED VULNERABILITIES**, but {review} candidate "
                    f"match{'es' if review > 1 else ''} need human review.")
    else:
        headline = "**NO VULNERABILITIES FOUND** in the scanned components."
    return ["", headline] + _coverage_caveat(meta, bool(actionable))


def _flagging_policy(meta: dict) -> list:
    """How each match got its bucket. The buckets are policy, not model output - saying
    so stops "confirmed" reading as certainty or "rejected" as absence."""
    m = meta.get("model")
    lines = ["", "## How these were flagged", ""]
    if m:
        lines += [f"A `{m['name']}` trained on this scan's own {m['training_rows']:,} candidate "
                  f"matches across {m['features']} features, weighting a missed vulnerability "
                  f"{model.FN_WEIGHT}x a false alarm - decision threshold **{m['threshold']:.2f}**.", ""]
    lines += [
        "- **escalated** - on CISA's Known Exploited Vulnerabilities list; exploited in the wild.",
        "- **confirmed** - confidence cleared the threshold, *or* OSV.dev agrees for this "
        "version, AND the CPE vendor isn't one the package's registry page contradicts.",
        "- **review_queue** - either below threshold and uncorroborated, or confident but "
        "matched to a CPE vendor the package's own registry page contradicts. Undecided, "
        "not dismissed; carries SHAP values showing which signals moved the score.",
        "- **rejected** - name matched but the pinned version isn't affected, or no plausible "
        "vendor. The name-collision case (PyPI `babel` vs Babel.js).",
    ]
    return lines


def format_summary(result, meta: dict) -> str:
    lines = ["# Vulnerability scan result"]
    if meta["truncated"]:
        lines.append(f"_Scanned {meta['scanned']} of {meta['total']} components "
                      f"(capped by max_components={meta['max_components']})._")
    lines += _verdict(result, meta)
    lines += [
        "",
        f"- **escalated** (actively exploited - CISA KEV): {len(result.escalated)}",
        f"- **confirmed**: {len(result.confirmed)}",
        f"- **review_queue** (model wasn't confident - needs a human): {len(result.review_queue)}",
        f"- rejected (name matched, ruled out by version or vendor): {len(result.rejected)}",
    ]
    lines += _flagging_policy(meta)

    if result.escalated:
        lines += ["", "## Escalated - fix these first",
                  "_Actively exploited in the wild right now, per CISA's Known Exploited "
                  "Vulnerabilities catalog. These are not theoretical._"]
        lines += [_detail_block(f) for f in result.escalated]
    if result.confirmed:
        lines += ["", "## Confirmed",
                  "_The model was confident these are real matches for your pinned "
                  "versions (or OSV.dev independently agreed)._"]
        lines += [_detail_block(f) for f in result.confirmed]
    if result.review_queue:
        lines += ["", "## Needs human review",
                  "_Held back for a person to decide, for one of two reasons: the model "
                  "wasn't confident enough either way, or it was confident but matched a "
                  "CPE vendor this package's registry page contradicts (a likely name "
                  "collision). Each finding's **Note** says which. The SHAP factors show "
                  "how much each signal pushed the score up (+) or down (-)._"]
        lines += [_detail_block(f) for f in result.review_queue]
    return "\n".join(lines)


def _severity_in_plain_terms(f) -> str:
    """One sentence a non-specialist can act on, built from what we actually know."""
    parts = []
    if f.kev_hit:
        parts.append("**Attackers are exploiting this right now** (it's in CISA's "
                     "actively-exploited catalog) - treat it as urgent, not theoretical")
    score = f.cvss_score
    if score is not None:
        if score >= 9.0:
            parts.append(f"rated {score}/10, which is about as severe as vulnerabilities get")
        elif score >= 7.0:
            parts.append(f"rated {score}/10 - serious, worth fixing soon")
        elif score >= 4.0:
            parts.append(f"rated {score}/10 - moderate; fix it, but it's not an emergency")
        else:
            parts.append(f"rated {score}/10 - low severity")
    else:
        parts.append("NVD hasn't published a severity score for this one yet")

    flaw_notes = [note for note in (cwe.plain_explanation(c) for c in f.cwe_ids) if note]
    if flaw_notes:
        parts.append(f"the underlying flaw is that {flaw_notes[0]}")

    if f.corroboration == "osv_agrees":
        parts.append("OSV.dev independently reports a vulnerability for this exact "
                     "package version too, which is a good sign the match is real")
    elif f.corroboration == "osv_disagrees":
        parts.append("OSV.dev does *not* list a vulnerability for this exact version, "
                     "so this may be a false alarm worth checking by hand")

    sentence = "; ".join(parts)
    return sentence[0].upper() + sentence[1:] + "." if sentence else ""


def _detail_block(f) -> str:
    """Full per-finding write-up: plain-English first, then the technical specifics."""
    c = f.component
    out = [
        "",
        f"### {c.name} {c.version} ({c.ecosystem}) - {f.cve}",
        "",
        f"**What this means:** {_severity_in_plain_terms(f)}",
        "",
        # Remediation advice is only safe once the finding is known to be about this
        # package. For a suspected collision, "upgrade past X" points at the wrong
        # software entirely - the fix, if any, belongs to whoever owns the other product.
        (f"**Fix:** check first whether this CVE is about `{c.name}` at all - the CPE "
         f"vendor doesn't match this package's registry page, so it may describe a "
         f"different product with the same name. Only if it does apply: upgrade "
         f"`{c.name}` past {c.version}."
         if f.vendor_conflict else
         f"**Fix:** upgrade `{c.name}` to a version newer than {c.version}, or apply the "
         f"vendor's patch - check the NVD link below for the fixed version range."),
        "",
    ]

    facts = [f"- **Severity:** {f.severity}" + (f" (CVSS {f.cvss_score}/10)" if f.cvss_score is not None else "")]
    if f.cwe_ids:
        named = []
        for cwe_id in f.cwe_ids:
            link = cwe.url(cwe_id)
            name = cwe.technical_name(cwe_id)
            # technical_name() falls back to the bare ID when unmapped - don't print
            # it twice ("CWE-640 CWE-640") in that case.
            label = cwe_id if name == cwe_id else f"{cwe_id} {name}"
            named.append(f"[{label}]({link})" if link else label)
        facts.append(f"- **Weakness type:** {', '.join(named)}")
    if f.confidence is not None:
        facts.append(f"- **Model confidence:** {f.confidence:.2f} "
                     f"({'above' if f.model_confident else 'below'} the decision threshold)")
    facts.append(f"- **OSV.dev cross-check:** {f.corroboration.replace('_', ' ')}")
    if f.vendor:
        facts.append(f"- **Matched NVD vendor:** `{f.vendor}` (the CPE vendor whose product "
                     f"entry matched this package)")
    if f.note:
        facts.append(f"- **Note:** {f.note}")
    facts.append(f"- **Full record:** https://nvd.nist.gov/vuln/detail/{f.cve}")
    out += facts

    if f.description:
        text = f.description.strip()
        if len(text) > 900:  # NVD descriptions are usually short; a few run very long
            text = text[:900].rstrip() + " [...truncated - see the NVD link above for the full text]"
        out += ["", "**Technical description (verbatim from NVD):**", "", f"> {text}"]

    if f.explanation:
        top = sorted(f.explanation.items(), key=lambda kv: -abs(kv[1]))[:3]
        # A finding the vendor gate demoted didn't hesitate - it scored above the
        # threshold and was held back on separate evidence. Labelling its SHAP values
        # "why the model hesitated" would misdescribe both the score and the decision.
        label = ("**What drove the model's score (top SHAP factors):**" if f.model_confident
                 else "**Why the model hesitated (top SHAP factors):**")
        out += ["", label + " " + ", ".join(f"`{k}` {v:+.2f}" for k, v in top)]
    return "\n".join(out)


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
    # The untriaged fallback can report an empty result for exactly the same reason the
    # triaged path can - an incomplete cache - so it carries the same caveat.
    lines += _coverage_caveat(meta, bool(found))
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


def _derive_public_base(headers) -> str | None:
    """Derive this server's publicly reachable base URL from an incoming request.

    The server can't know its own tunnel URL from config - quick cloudflared tunnels
    mint a new random hostname on every boot. But every MCP request *arrives through*
    that tunnel, carrying the public hostname in its Host header (and the original
    scheme in X-Forwarded-Proto, since the tunnel terminates TLS and forwards plain
    HTTP). So the freshest answer to "what URL am I reachable at?" is sitting on
    whatever request is being handled right now.
    """
    host = headers.get("x-forwarded-host") or headers.get("host")
    if not host:
        return None
    scheme = headers.get("x-forwarded-proto") or "http"
    return f"{scheme}://{host}"


@mcp.tool()
def get_scan_command(ctx: Context) -> str:
    """START HERE for any vulnerability scan. Returns the single terminal command that
    performs the entire scan, with this server's CURRENT public URL already filled in.

    The whole workflow is: (1) call this tool, (2) run the one command it returns,
    exactly as printed, (3) save the command's printed output as the report. That's
    everything - the command sends the lockfile straight from disk to this server and
    prints back the finished triaged report. Do not read the lockfile, do not modify
    the command, do not wrap it in $(...) or nest it inside anything.

    The URL in the command is derived live from your own connection to this server -
    the very request you just made carries the hostname you reached it through - so it
    is always current, even though a tunnel URL can change on every server reboot.
    Never guess the URL, never reuse one remembered from an earlier conversation, and
    never invent a web address for any MCP tool - tools have no URLs; this tool hands
    you the only URL the workflow needs.
    """
    try:
        request = ctx.request_context.request
        headers = request.headers if request is not None else None
    except Exception:
        headers = None
    base = _derive_public_base(headers) if headers is not None else None
    if base is None:
        return (
            "Could not determine this server's public URL from the current connection "
            "(no Host header available). Ask the user for the it-security-agent server's "
            "base URL - it's the MCP URL in their Cline settings with the trailing /mcp "
            "removed - then run: curl -s -X POST <base-url>/scan --data-binary @uv.lock"
        )
    # The report path is filled in here rather than left as a placeholder: it removes a
    # decision from the caller, and it keeps the command a single copy-paste unit that
    # both shows progress and saves the report.
    report_path = f"reports/{datetime.date.today():%Y-%m-%d}-scan.md"
    return (
        "Run exactly ONE of these in the terminal, as printed - substituting only the "
        "lockfile filename after the @ if it isn't uv.lock:\n\n"
        f"  Windows PowerShell (use this one on Windows - plain `curl` will NOT work "
        f"there):\n    New-Item -ItemType Directory -Force reports | Out-Null; "
        f"curl.exe -sN -X POST {base}/scan --data-binary \"@uv.lock\" | "
        f"Tee-Object -Variable report; "
        f"[IO.File]::WriteAllLines(\"$PWD\\{report_path.replace('/', chr(92))}\", $report)\n\n"
        f"  bash / zsh (Linux/macOS):\n    mkdir -p reports && "
        f"curl -sN -X POST {base}/scan --data-binary @uv.lock | tee {report_path}\n\n"
        "The quotes around \"@uv.lock\" are REQUIRED on PowerShell - an unquoted @ is "
        "a parse error there. Copy them exactly.\n\n"
        "DO NOT redirect this with `>`, and do not simplify the PowerShell line. Each "
        f"part earns its place: `Tee-Object -Variable` shows every pipeline stage on "
        f"screen as it happens while capturing the text, and `[IO.File]::WriteAllLines` "
        f"writes {report_path} as plain UTF-8. A `>` redirect hides all the progress "
        "AND writes UTF-16 on some PowerShell hosts, which doubles the file size and "
        "makes git treat the report as binary. `-N` stops curl buffering, so stages "
        "appear as they happen rather than all at once at the end.\n\n"
        "You will see stages stream in - SBOM generation, cache coverage, CPE state, "
        "model training, SHAP, triage - then the finished report; usually seconds, up "
        "to ~2 minutes on the first run after a server restart. Wait for it to finish, "
        f"don't retry or cancel. The file is already saved by the time it ends, so do "
        "not re-save it; just relay the FULL output to the user - the report ends with "
        "a '## Pipeline' section recording exactly which stages ran, which is part of "
        "the report, not noise to strip. If the user explicitly asked for an SBOM, "
        "append ?include_sbom=true to the URL."
    )


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

    return _run_scan(lockfile_content, lockfile_type, max_components, include_sbom)


def _run_scan(lockfile_content: str, lockfile_type: str = "", max_components: int = 40,
              include_sbom: bool = False, progress=None) -> str:
    """The actual scan pipeline, shared by the scan_repo MCP tool and the /scan HTTP
    endpoint - parse, generate SBOM, sync caches, match, triage, format.

    `progress` is an optional callable taking one string. Every pipeline stage reports
    through it as it happens, so a streaming caller can show live what the scan is
    doing (rather than an opaque wait), and the same log is appended to the finished
    report so the saved artifact records exactly which stages ran.
    """
    t0 = time.time()
    log: list[str] = []

    def step(message: str) -> None:
        line = f"[{time.time() - t0:5.1f}s] {message}"
        log.append(line)
        if progress is not None:
            progress(line)

    components = parse_lockfile_components(lockfile_content, lockfile_type)
    if not components:
        return "No components could be parsed from the provided lockfile."
    kind = lockfile_type or _detect_lockfile_type(lockfile_content)
    ecosystems = sorted({c.ecosystem for c in components})
    step(f"Parsed {len(components)} components from {kind} ({', '.join(ecosystems)})")

    generated_bom = sbom.to_cyclonedx(components, bom_name="scan_repo")
    sbom_note = "included in report below" if include_sbom else "not included (add ?include_sbom=true to include)"
    step(f"Generated CycloneDX {generated_bom['specVersion']} SBOM from the lockfile, "
         f"{len(generated_bom['components'])} components - {sbom_note}")

    total = len(components)
    truncated = total > max_components
    components = components[:max_components]
    meta = {"scanned": len(components), "total": total, "truncated": truncated, "max_components": max_components}
    if truncated:
        step(f"Capped to first {len(components)} of {total} components (max_components={max_components})")

    conn = get_connection()
    coverage = _cache_coverage(conn)
    if coverage is not None:
        meta["cache"] = coverage
        step(f"Local NVD cache holds {coverage['cves']:,} CVEs "
             f"(~{coverage['fraction']:.0%} of NVD's ~{NVD_CATALOG_SIZE:,}) "
             f"+ {coverage['kev']:,} known-exploited")

    # A warmed cache needs nothing from the network. The sync exists to fill a thin
    # cache, not to re-check a complete one on every restart.
    if coverage is not None and not coverage["thin"]:
        step("Cache is complete - scanning offline, no NVD sync needed")
    elif time.time() - _last_synced < SYNC_INTERVAL_SECONDS:
        step("NVD CVE catalog + CISA KEV feed already synced (cached, <6h old)")
    else:
        step("Cache is incomplete - topping up with CVEs modified in the last 14 days "
             "(incremental; the cached catalog is kept, not refetched)...")
        _ensure_synced(conn)
        coverage = _cache_coverage(conn) or coverage
        if coverage is not None:
            meta["cache"] = coverage
        step("WARNING: cache coverage is incomplete - matching can only find CVEs that "
             "are cached, so a clean result here is not proof the code is clean")

    prewarm(components, conn, step=step)

    step("Matching components against NVD (name + version + vendor), cross-checking OSV.dev...")
    result = run_pipeline(components, conn, step=step, meta=meta)
    if result is None:
        step("Not enough labeled signal to train a confidence model - falling back to untriaged raw matches")
        text = format_raw_matches(raw_matches(components, conn), meta)
    else:
        step(f"Triaged: {len(result.escalated)} escalated (CISA KEV), {len(result.confirmed)} confirmed, "
             f"{len(result.review_queue)} need review, {len(result.rejected)} rejected as collisions")
        text = format_summary(result, meta)

    step("Done")
    text += "\n\n## Pipeline (what this scan actually ran)\n\n```\n" + "\n".join(log) + "\n```"

    if include_sbom:
        text += format_sbom_section(generated_bom)
    return text


@mcp.custom_route("/scan", methods=["POST"])
async def scan_http_endpoint(request):
    """One-shot HTTP scan: POST raw lockfile bytes, get the final triaged report back.

    This is the whole workflow in a single terminal command - the calling agent runs
    the curl that get_scan_command returns, and the printed output IS the finished
    report, ready to save. Nothing lockfile-related ever enters the model's context:
    not the raw file (which can overflow a small model's context on its own), and not
    even the condensed package list - the model only relays the report. Condensing
    happens implicitly (the parser here is the same one /condense uses).

    The response STREAMS: a short header goes out immediately and keepalive dots
    follow while the scan runs. This is what makes the command work through proxies
    like Cloudflare's tunnels, which kill any request with no response bytes within
    ~100 seconds (a cold first scan used to blow through that and 524) - once the
    first byte is out, the connection stays alive for as long as the scan needs.

    Query params: include_sbom=true to append the generated CycloneDX SBOM (only when
    the user explicitly asked for an SBOM - it adds tens of KB on a real tree).
    """
    import threading

    import anyio
    from starlette.responses import PlainTextResponse, StreamingResponse

    body = await request.body()
    text = body.decode("utf-8", errors="replace")
    if not text.strip():
        return PlainTextResponse(
            "Empty body. POST the raw lockfile bytes, e.g.: "
            "curl -s -X POST <this-server>/scan --data-binary @uv.lock",
            status_code=400,
        )
    # Parsing is pure and fast - validate it up front so garbage input still gets a
    # proper 400 status, which is impossible once the streamed 200 has started.
    try:
        components = parse_lockfile_components(text)
        if not components:
            return PlainTextResponse("No components could be parsed from the provided lockfile.", status_code=400)
    except Exception as exc:
        return PlainTextResponse(f"Could not parse lockfile: {exc}", status_code=400)

    include_sbom = request.query_params.get("include_sbom", "").lower() in ("true", "1", "yes")

    import queue

    outcome = {}
    updates: "queue.Queue[str]" = queue.Queue()

    def work():
        try:
            # No component cap here, unlike scan_repo's MCP default of 40: this is the
            # primary path and every package in the lockfile gets scanned. Streaming
            # keeps the connection alive however long that takes, so there's no
            # latency ceiling forcing a cap anymore.
            outcome["report"] = _run_scan(text, "", len(components), include_sbom,
                                          progress=updates.put)
        except Exception as exc:
            outcome["error"] = str(exc)

    async def stream():
        worker = threading.Thread(target=work, daemon=True)
        worker.start()
        yield b"Scanning - live pipeline progress follows, then the report:\n\n"

        def drain():
            out = []
            while True:
                try:
                    out.append(updates.get_nowait())
                except queue.Empty:
                    return out

        # Relay progress lines as they happen. Each one is also a keepalive byte,
        # which is what stops proxies (Cloudflare's ~100s cap) from timing us out.
        while worker.is_alive():
            for line in drain():
                yield (line + "\n").encode("utf-8")
            await anyio.sleep(0.5)
        for line in drain():  # anything logged between the last poll and thread exit
            yield (line + "\n").encode("utf-8")

        yield b"\n"
        # Both branches end with a newline: without one, terminal integrations glue
        # their own shell-prompt artifacts onto the report's last line.
        if "error" in outcome:
            yield f"ERROR: {outcome['error']}\n".encode("utf-8")
        else:
            yield (outcome["report"] + "\n").encode("utf-8")

    return StreamingResponse(stream(), media_type="text/plain")


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
                "autoApprove": ["get_scan_command", "condense_lockfile", "scan_repo"],
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
            "\"autoApprove\" skips Cline's per-call confirmation prompt for those tools -",
            "safe to leave in, since none of them writes to or executes anything on the",
            "caller's machine. Remove any name from the list if you'd rather approve",
            "those calls by hand.",
            "",
            "One-shot scan over HTTP (raw lockfile bytes in, finished report out - the",
            "model's context never touches lockfile content):",
            f"  curl -s -X POST http://{public_host}:{port}/scan --data-binary @uv.lock",
            "Behind a tunnel (e.g. cloudflared) the hostname above is wrong - but nobody",
            "needs to track it: the get_scan_command tool returns this command with the",
            "live public URL filled in, derived from the caller's own connection, so it",
            "stays correct even when a quick tunnel mints a new URL every boot.",
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
    _start_background_sync()
    mcp.run(transport="streamable-http")


if __name__ == "__main__":
    main()

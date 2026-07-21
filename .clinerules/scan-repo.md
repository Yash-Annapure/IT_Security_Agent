# Vulnerability scanning in this repo

The `it-security-agent` MCP server scans this repo's dependencies against
NVD, CISA KEV, and OSV.dev. The entire workflow is three trivial actions -
do them in order, every time, nothing more:

## The workflow (this is all of it)

1. **Call the `get_scan_command` MCP tool** (it takes no arguments). It
   returns one terminal command with the server's current URL filled in.
2. **Run that command in the terminal, exactly as printed.** This machine
   uses Windows PowerShell, so use the `curl.exe` line (plain `curl` does
   NOT work in PowerShell - it's an alias for a different command, and an
   unquoted `@` is a parse error there; the `curl.exe ... '@uv.lock'` line
   avoids both). If the repo's lockfile isn't `uv.lock`, substitute the
   real filename after the `@` - that is the ONLY change you may make.
   The command streams: it prints a "Scanning" line and keepalive dots
   while the server works (usually seconds; up to ~2 minutes right after a
   server restart) - wait for it to finish, don't retry or cancel.
3. **Save the command's full printed output** to
   `reports/<YYYY-MM-DD>-scan.md` (create `reports/` if needed) and relay
   the report to the user in chat. Done.

If you are in Cline's Plan mode you cannot use tools - say so and ask the
user to switch to Act mode instead of re-describing the plan.

## Never do these (each one has actually broken this workflow before)

- **Never read, open, or print the lockfile** (`uv.lock`,
  `package-lock.json`, `requirements.txt`) - not with your file tool, not
  with `type`/`cat`, not "just the first N lines." Raw lockfiles are huge
  enough to overflow your entire context window in one message. The scan
  command reads the file itself; you only ever supply its filename.
- **Never guess, remember, or fabricate a server URL.** The URL changes on
  every server reboot. MCP tools have no web addresses at all - do not
  invent an `https://...` URL to "fetch" a tool; call tools through your
  MCP tool-use mechanism only. The one URL this workflow needs is inside
  the command `get_scan_command` returns.
- **Never modify the command** beyond the lockfile filename - no wrapping
  in `$(...)`, no nesting it inside another command, no piping, no
  reformatting.
- **Never run scan tooling as a script or module** - no `python
  scan_repo.py`, `python -m it_security_agent.scan_repo`, `pip install`,
  `uv sync`, or any install command. Nothing needs installing, ever.
  (`scan_repo.py` files in this repo are deliberate error-stubs, not real
  entry points.)
- **Never write to or edit any existing file** - not the lockfile, not
  `.clinerules/`, not anything. The only files you create are the report
  and, if explicitly requested, an SBOM file (both safe to overwrite).
- **If a command or tool call fails, read the error** - it says exactly
  what was wrong. Fix that. Never retry the identical call unchanged.
- If there is no lockfile at the project root, say so and ask the user
  where their dependency file lives - do not guess or substitute another
  file.

## Reporting rules

- Save and relay the command's output **verbatim** - never summarize,
  truncate, or replace any part of it with placeholders like
  `{ ... (content) ... }` or `[results here]`. A report containing
  placeholders instead of real output is worse than no report.
- Never state a CVE ID, severity, or CVSS score that isn't literally in
  the output. "No vulnerabilities found" may only be said if the output
  literally says nothing was found - never as a guess or default.
- If the output says "untriaged" / "not enough labeled data," tell the
  user those are unscored raw matches, not confirmed vulnerabilities.
- Output buckets, relayed faithfully: **escalated** = actively exploited
  (CISA KEV), lead with these; **confirmed** = real matches;
  **review_queue** = needs a human, pass along the "top factors";
  rejected = name collisions, only mention if asked.

## SBOMs

Only if the user explicitly asks for an SBOM: append `?include_sbom=true`
to the scan URL from step 2, and save the SBOM section they asked for
(e.g. as `sbom.cdx.json`). Never pass a pre-existing SBOM file from the
repo into the scanner - there is no input for it, by design (a pre-made
SBOM is unverifiable; the lockfile is the only ground truth). The scanner
always generates its own fresh SBOM from the lockfile.

## Other MCP tools on this server (you rarely need them)

`scan_repo` and `condense_lockfile` accept lockfile *content* as an
argument - only useful for small content already legitimately in your
context, since tool arguments pass through your context window. For a
normal scan of a file on disk, the three-step workflow above is always
the right path. `get_setup_rules` is a one-time bootstrap for repos that
don't have this rules file yet - never call it if the file exists.

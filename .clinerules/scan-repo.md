# Vulnerability scanning in this repo

The `it-security-agent` MCP server scans this repo's dependencies against
NVD, CISA KEV, and OSV.dev. The entire workflow is three trivial actions -
do them in order, every time, nothing more:

## The workflow (this is all of it)

1. **Call the `get_scan_command` MCP tool** (it takes no arguments) through
   your MCP tool-use mechanism. It returns one terminal command with the
   server's current URL filled in. `get_scan_command` is an MCP tool, not a
   program: it has no command-line form, no module path, no file on disk.
   `python -m it_security_agent.get_scan_command` and anything like it will
   always fail, because there is nothing there to run.
2. **Run that command in the terminal, exactly as printed.** This machine
   uses Windows PowerShell, so use the `curl.exe` line (plain `curl` does
   NOT work in PowerShell - it's an alias for a different command, and an
   unquoted `@` is a parse error there). **Substitute nothing** - the
   command finds the lockfile itself, anywhere in the repo, and prints
   which one it picked. **Never add a `>` redirect** and never simplify
   the pipeline: `Tee-Object`/`tee` captures the full report to
   `reports/<YYYY-MM-DD>-scan.md` while `Select-String`/`grep` prints a
   trimmed view to screen. Stages stream in - SBOM generation, cache
   coverage, model training, SHAP, triage - then the headline and one
   line per finding. Usually seconds; up to ~2 minutes right after a
   server restart. Wait for it to finish, don't retry or cancel. Its
   first `curl` refreshes this rules file from the server - that is the
   entire repo setup, already done by running the command, and you must
   never write this file yourself.
3. **Relay what it printed, verbatim, and point at the file.** What you
   see is already the trimmed view: progress, the headline, the bucket
   counts, and every finding with its severity and CVSS. Pass that on as
   printed, then tell the user the full detail for each finding -
   descriptions, CWEs, SHAP factors, fixes - is in
   `reports/<YYYY-MM-DD>-scan.md`. Do not re-save it, and **do not open
   it to quote more**: the full report runs ~500 tokens per finding, and
   reading it back is what puts you over the context limit on a repo with
   real findings. The trimmed view is the deliverable; the file is for
   the human. Done.

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
- **Never run ANY scan tooling as a script, module, or command.** The only
  terminal command in this entire workflow is the `curl.exe` line that
  `get_scan_command` hands you in step 1. If you are about to type
  `python`, `python -m`, `uv run`, `pip install`, or `uv sync` for any
  reason at all, stop - it is wrong, whatever the module or file name is.
  This applies to names not listed here: no MCP tool on this server has a
  command-line equivalent, so there is never a module path worth guessing.
  (`scan_repo.py` files in this repo are deliberate error-stubs, not real
  entry points.)
- **Never write to or edit any existing file** - not the lockfile, not the
  source, not this rules file. The command writes the report and refreshes
  `.clinerules/scan-repo.md` itself; the only file you ever write by hand is
  an SBOM, and only if explicitly asked. Never retype this rules file: a
  model asked to reproduce it verbatim truncated it and silently lost the
  reporting rules below. `curl` copies it exactly and costs nothing.
- **If a command or tool call fails, read the error** - it says exactly
  what was wrong. Fix that. Never retry the identical call unchanged.
- **Never run `npm install`, `uv sync`, `pip install` or any other install
  command.** Scanning reads a lockfile; it never builds anything. `npm
  install` in a directory with no `package.json` still leaves behind an
  empty `package-lock.json` that then shadows the project's real one, and
  every scan afterwards reports "no components" - that has happened.
- **If the lockfile isn't at the repo root, find it - don't guess and don't
  ask.** Monorepos keep it in a subdirectory (`my-app/`, `client/`,
  `frontend/`). List, never open: `Get-ChildItem -Recurse -Filter
  package-lock.json` on PowerShell (or `find . -name package-lock.json -not
  -path '*/node_modules/*'` on bash), then put that path after the `@`, e.g.
  `"@my-app/package-lock.json"`. A file *listing* is safe; the file is not.
  Only ask the user if the search finds nothing at all.
- **"No components could be parsed" is never a reason to open the file.**
  It means the file you sent pins nothing - usually an empty stub at the
  root while the real lockfile is in a subdirectory. Search for the other
  lockfiles and send one of those.

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
normal scan of a file on disk, the workflow above is always the right path.
`get_setup_rules` returns this rules file's text as a tool response - you do
not need it, because step 2's command already fetches the same file straight
to disk. Only reach for it in a client that cannot run terminal commands.

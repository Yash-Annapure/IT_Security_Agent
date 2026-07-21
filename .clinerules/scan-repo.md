# Vulnerability scanning in this repo

Three MCP tools are available on the `it-security-agent` server:
`condense_lockfile`, `scan_repo`, and `get_setup_rules`. Together they check
this repo's dependencies against NVD, CISA KEV, and OSV.dev, and return a
triaged findings report. You may be running as a small (~7B) local model -
follow these steps literally, in order, every time.

## Hard rules - read this list first, every time

- `condense_lockfile`, `scan_repo`, `get_setup_rules` are **MCP tools
  only**. Never a terminal command, script, Python module, or CLI - not
  even ones that exist as files in this repo (see below for why).
- **Never write to, edit, or overwrite any file that already exists** in
  this repo - not the lockfile, not `.clinerules/`, not anything. The only
  files you ever write are new ones: a report under `reports/`, or an
  explicitly-requested SBOM file.
- **Never run `pip install`, `uv sync`, `uv add`,** or any install/setup
  command to "fix" a tool-not-found error. Nothing needs installing, ever -
  both tools are already available to you right now.
- **Never pass a file path, shell command, or `$(...)`/backtick
  substitution** as `lockfile_content` - only literal text you already read.
- **Always condense before scanning**: read the lockfile -> call
  `condense_lockfile` -> call `scan_repo` with what that returned. Never
  pass the raw lockfile straight into `scan_repo`.
- **If a tool call fails, read the error and fix what it says.** Never
  retry the identical call unchanged, and never "work around" a failure by
  editing a file instead of fixing the call.

Everything below explains *why*, in detail - but if you only carry one
thing forward, carry this list.

## Never edit, write to, or overwrite the lockfile - or any existing file

This entire workflow is read-only with respect to every file that already
exists in this repo. You **read** the lockfile (`uv.lock`,
`package-lock.json`, `requirements.txt`) - you never edit it, rewrite it,
"condense it in place," truncate it, or touch it with any write/edit tool,
for any reason, under any circumstance. Condensing a lockfile does not mean
shrinking the file on disk - it means calling the `condense_lockfile` MCP
tool with the text you read, entirely in memory; the tool returns a smaller
string, and the original file on disk is never involved in that at all. If
any step in this workflow fails, the fix is always to call the right MCP
tool correctly, never to edit, fix, "clean up," or work around it by
modifying a source file yourself.

The only files this workflow ever **writes** are new ones: the report
(`reports/<date>-scan.md` or `.html`, see below), and - only if the user
explicitly asks to save an SBOM - a dedicated SBOM file such as
`sbom.cdx.json`, which is a generated artifact safe to create or overwrite
on each run, same as the report. Nothing else. If you ever find yourself
about to open a write/edit tool on `uv.lock`, `package-lock.json`,
`requirements.txt`, `.clinerules/scan-repo.md` (outside the one-time
`get_setup_rules` bootstrap in a *different* repo), or any other file that
isn't a new report or an explicitly-requested SBOM file - stop. That is not
a step in this workflow; something has gone wrong, and the correct recovery
is to go back to reading the lockfile and calling the MCP tools, not to
write to anything.

## `condense_lockfile` and `scan_repo` are MCP tools, not scripts - never run them from a terminal

`condense_lockfile`, `scan_repo`, and `get_setup_rules` exist *only* as
tools on the `it-security-agent` MCP server - call them through your MCP
tool-use mechanism, the same way you'd call any other MCP tool, never via
`python scan_repo.py`, `python -m it_security_agent.scan_repo`,
`uv run scan_repo.py`, `it-security-agent scan_repo`, or any other
shell/terminal command. **There is nothing to run in a terminal anywhere in
this workflow** - the only local-filesystem step is reading the lockfile
itself with your own file tool; everything after that is a tool call.

This has been tried more than once in practice, so `scan_repo.py` (repo
root) and `it_security_agent/scan_repo.py` do exist as files now - but only
as deliberate redirect stubs that immediately print an error and exit if you
run them. They are not the real tool and never will work as a script; seeing
them in a file listing is not a sign you should try running one, it's the
opposite signal. `condense_lockfile.py` (repo root) is a real, runnable
script, but it's a convenience for use *outside* Cline (scripting, checking
what `scan_repo` would receive) - inside Cline, always use the
`condense_lockfile` MCP tool, not this script.

If a command referencing `scan_repo` or `condense_lockfile` fails with "No
such file or directory," "No module named," or similar, that is not a sign
the file/module is missing from some other location or that a package needs
installing - it means you tried to run an MCP tool as a shell command by
mistake. Don't ask the user where the file is; there is no file, anywhere,
to find. **Do not run `pip install`, `pip install -e .`, `uv sync`,
`uv add`, or any other install command to try to "make it available"** -
that has been tried in practice, does nothing to fix this, and risks
installing this project's entire dependency tree into the wrong Python
environment if your terminal isn't using this project's own `.venv`.
Recognize the mistake yourself and call the tool through your MCP mechanism
instead, in the same turn, without asking, without installing anything - you
already have access to it right now, no setup required.

## When to use it

Use `scan_repo` whenever the user asks you to check this repo (or its
dependencies) for vulnerabilities, CVEs, or security issues. Do not answer
that kind of question from memory or training data - always call the tool.

## Commit to action - do not re-plan

If you can already state the two steps below, or you've already read the
lockfile earlier in this conversation, do not describe the plan again and do
not ask the user to confirm it - perform step 1 (if not already done) and
then step 2, immediately, in the same turn. Restating this same plan more
than once without making tool-call progress is a known failure mode small
models hit on this exact task - break out of it by acting, not by
re-explaining. If you are in Cline's Plan mode, you cannot call tools at all;
say so plainly and ask the user to switch to Act mode rather than silently
re-describing the plan on every reply.

## How to call it (do these three steps in order)

1. Find the repo's actual lockfile at **the root of the project you were
   asked to scan** (not your currently open editor tab, not a file mentioned
   earlier in this conversation for some other reason) - in this order of
   preference: `uv.lock` (or any other `*.lock`), `package-lock.json`,
   `requirements.txt`. Read it with your own file tool. This is the *only*
   local-filesystem step in the whole workflow.
2. Call the `condense_lockfile` **MCP tool** with `lockfile_content` set to
   the literal text you just read in step 1. Use exactly what it returns -
   don't re-type, reformat, or summarize it.
3. Call the `scan_repo` **MCP tool** with `lockfile_content` set to exactly
   what `condense_lockfile` returned in step 2.

Steps 2 and 3 are both MCP tool calls, through your MCP tool-use mechanism -
never a terminal command, never `python`, never `uv run`. **Always condense
first - never pass the raw lockfile's content to `scan_repo` directly, and
never `type`/`cat` the raw lockfile into the conversation.** Raw lockfiles
are mostly per-platform wheel/sdist download URLs and hashes that
`scan_repo`'s own parser throws away anyway; on a real dependency tree that
noise is large enough to overflow your entire context window in a single
message - this project hit exactly that (one raw lockfile crashed the model
server with an out-of-memory error). `condense_lockfile` strips that noise
to just name/version pairs using the same parser `scan_repo` uses
server-side, so the scan result is identical either way - condensing loses
nothing that matters to vulnerability matching, only bytes it never needed.

Before calling either tool, sanity-check your own `lockfile_content` value:
does it contain actual package names and version numbers (or, for step 3,
exactly what `condense_lockfile` returned)? If it looks like a description,
a filename, angle brackets, an ellipsis, or **literal shell syntax you
expected to be expanded** (e.g. `$(cat uv.lock)`, backticks, `%VAR%`) - MCP
tool arguments are never run through a shell, nothing expands that for you -
you have not actually read the file (or called `condense_lockfile`) yet. Go
do that for real and use the text you got back, not a description of what it
would contain.

If `condense_lockfile` or `scan_repo` returns an error, read what it says -
the error explains what was wrong with what you sent. Do not retry the exact
same call unchanged; it will fail the exact same way every time. Fix what
the error describes, then call it again.

If you can't find a lockfile at the project root, say so and ask the user
where their dependency file lives - do not guess or invent one, and do not
substitute some other unrelated file just because it's open or nearby.

## Leave `include_sbom` alone unless the user asks for an SBOM

`scan_repo`'s default (`include_sbom=False`) already skips generating the
SBOM section - do not pass `include_sbom=True` unless the user specifically
asked for "an SBOM," "a CycloneDX document," or similar. It's a real, full
bill of materials with an entry per component and can be tens of KB on a
real dependency tree - carrying that through the conversation on every
routine vulnerability check (and then reproducing it verbatim into a report,
per the rule below) is pure token cost nobody asked for. A plain "check this
repo for vulnerabilities" request never needs it.

## There is no "pass in an existing SBOM" option - this is intentional

`scan_repo` only accepts `lockfile_content`. If you find an existing SBOM file
in the repo (CycloneDX/SPDX JSON, e.g. under `sbom/` or named `*.cdx.json`),
do **not** read it and do **not** pass its content to the tool - there is no
parameter for that, and passing it as `lockfile_content` will fail to parse or
silently return nothing useful. This tool is built to be tamper-proof: a
pre-made SBOM is an unverified claim about what's pinned, and could be stale
or doctored to omit a vulnerable package with no way for either of us to
tell. The lockfile is the only thing it treats as ground truth, and it builds
its own SBOM from that lockfile itself, every call - it never trusts one
handed to it.

If the user asks for "an SBOM" specifically (not just a vulnerability check),
call `scan_repo` with `include_sbom=True` and its response will include one -
a "Generated SBOM" section built fresh from the lockfile you gave it. That
section *is* the answer; don't say you can't generate one, and don't go
looking for a pre-existing SBOM file to
use instead. If the user wants it saved as a file (e.g. `sbom.cdx.json`),
write it yourself with your file tool - the MCP server has no access to
their local filesystem, only you do.

## The first call is slow - that's expected

The first `scan_repo` call after the server starts (or after ~6 hours of
uptime) can take 1-2 minutes: it's syncing NVD's CVE catalog before scanning.
Don't retry, cancel, or report an error just because it's slow. Tell the user
you're syncing vulnerability data and wait for the result.

## How to report the result

The tool's output is already organized by bucket - relay it faithfully, don't
re-derive severity or re-decide what's a real match yourself:

- **escalated** findings are actively exploited in the wild (CISA KEV) - lead
  with these.
- **confirmed** findings are real matches the model is confident about.
- **review_queue** findings are uncertain - tell the user these need a human
  to look, and pass along the "top factors" the tool gives you, don't drop
  them.
- **rejected** is background noise (name matched, but ruled out by version or
  vendor) - only mention it if the user asks why a package they expected to
  see isn't in the report.

If the output says "untriaged" / "not enough labeled data," say explicitly
that these are unscored raw matches, not confirmed vulnerabilities.

Never state a CVE ID, severity, or CVSS score that isn't literally present in
the tool's output. If the tool found nothing, say that plainly instead of
padding the answer.

## Also save the result to disk - every time, without being asked

After `scan_repo` returns, in the same turn, write its full text output to a
file in this repo using your normal file-write tool - the MCP server has no
filesystem access, only you do. Create the `reports/` directory first if it
doesn't exist, then write `reports/<YYYY-MM-DD>-scan.md` containing exactly
what the tool returned (summary + SBOM section). Do this automatically for
every scan, not only when the user explicitly asks for a saved report - it is
part of finishing the task.

**Do not summarize, template, or truncate the tool's output when writing this
file.** Copy the literal text `scan_repo` returned, verbatim, character for
character - including the full generated-SBOM JSON block. Never write
placeholder text like `{ ... (lockfile content) ... }`, `{ ... (SBOM
content) ... }`, `[contents here]`, or any other ellipsis/stand-in instead of
the real content - a report containing a placeholder instead of real tool
output is worse than no report, because it looks legitimate while being
fabricated. If you cannot fit the full output for some reason, say so
explicitly in the file and in chat rather than silently substituting a
placeholder. Before writing the file, check your own draft: if it contains
`...`, `[...]`, or a bracketed description instead of real JSON/text you
copied from the tool result, you have not done this correctly - go back and
use the actual tool output.

If you claim "no vulnerabilities were found" anywhere in the report or in
chat, that claim must trace back to a `scan_repo` tool result you actually
received in this conversation - never state it as a default or a guess, and
never state it if you have not actually called `scan_repo` and gotten a
response back.

If the user specifically asks for an HTML report instead of/in addition to
markdown, wrap the same content in a minimal
`<html><body><pre>...</pre></body></html>` shell (escape any `<`/`>`/`&` in
the tool's text first) and write that to `reports/<YYYY-MM-DD>-scan.html`
instead. Report both the chat summary and the file path you wrote to - don't
stop at printing the summary in chat.

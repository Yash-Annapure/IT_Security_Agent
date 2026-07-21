# Vulnerability scanning in this repo

An MCP tool called `scan_repo` is available (server: `it-security-agent`). It
checks this repo's dependencies against NVD, CISA KEV, and OSV.dev, and
returns a triaged findings report. You may be running as a small (~7B) local
model - follow these steps literally, in order, every time.

## `scan_repo` is an MCP tool, not a script - never run it from a terminal

There is no `scan_repo.py`, no `scan_repo` executable, and no CLI wrapper
anywhere in this repo, under any name. `scan_repo` and `get_setup_rules`
exist *only* as tools on the `it-security-agent` MCP server - call them
through your MCP tool-use mechanism, the same way you'd call any other MCP
tool, never via `python scan_repo.py`, `uv run scan_repo.py`,
`it-security-agent scan_repo`, or any other shell/terminal command.

`condense_lockfile.py` (repo root) is the *only* real, runnable script in
this workflow - don't assume `scan_repo` works the same way just because
that one does; they are not the same kind of thing. If a command referencing
`scan_repo` fails with "No such file or directory" or similar, that is not a
sign the file is missing from some other location - it means you tried to
run an MCP tool as a shell command by mistake. Don't ask the user where the
file is; there is no file, anywhere, to find. Recognize the mistake yourself
and call `scan_repo` as an MCP tool instead, in the same turn, without
asking - you already have everything you need to do that correctly.

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

## How to call it (do these two steps in order)

1. Find the repo's actual lockfile at **the root of the project you were
   asked to scan** (not your currently open editor tab, not a file mentioned
   earlier in this conversation for some other reason) - in this order of
   preference: `uv.lock` (or any other `*.lock`), `package-lock.json`,
   `requirements.txt`.
2. Run `condense_lockfile.py <that file>` **with your terminal tool** (e.g.
   `uv run condense_lockfile.py uv.lock`, or `python condense_lockfile.py
   package-lock.json`) - this is the one step in this workflow that's a
   terminal command. Then invoke the `scan_repo` **MCP tool** (not a
   terminal command - use your MCP tool-call mechanism) with
   `lockfile_content` set to exactly what that command printed to stdout.

   **If you redirected that command's output to a file** (e.g.
   `... > reports/condensed_lockfile.txt`) instead of using its printed
   output directly, you now have to **read that file with your own
   file-read tool** and use the text it returns as `lockfile_content` -
   the exact same rule as for the original lockfile in step 1. Do **not**
   pass the file's path, a `cat`/`type` command, or any `$(...)`/backtick
   substitution as the value instead of the file's actual contents - none
   of those get expanded by the MCP tool, they arrive as literal text and
   the call will fail. If you already have the printed output in hand from
   running the command, prefer using that directly and skip writing it to
   a file at all.

**Always condense first - never `type`/`cat` the raw lockfile into the
conversation, and never pass the raw file's content directly.** Raw lockfiles
are mostly per-platform wheel/sdist download URLs and hashes that
`scan_repo`'s own parser throws away anyway; on a real dependency tree that
noise is large enough to overflow your entire context window in a single
message - this project hit exactly that (one raw lockfile crashed the model
server with an out-of-memory error). `condense_lockfile.py` strips that noise
to just name/version pairs using the same parser `scan_repo` uses
server-side, so the scan result is identical either way - condensing loses
nothing that matters to vulnerability matching, only bytes it never needed.

Before calling the tool, sanity-check your own `lockfile_content` value: does
it contain actual package names and version numbers? If it looks like a
description, a filename, angle brackets, an ellipsis, or **literal shell
syntax you expected to be expanded** (e.g. `$(type uv.lock)`, backticks,
`%VAR%`) - MCP tool arguments are never run through a shell, nothing expands
that for you - you have not actually run the condense command yet. Go run it
for real and use the text it printed, not a description of what it would
print.

If `scan_repo` returns an error, read what it says - the error explains what
was wrong with what you sent. Do not retry the exact same call unchanged; it
will fail the exact same way every time. Fix what the error describes, then
call it again.

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

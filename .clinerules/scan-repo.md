# Vulnerability scanning in this repo

An MCP tool called `scan_repo` is available (server: `it-security-agent`). It
checks this repo's dependencies against NVD, CISA KEV, and OSV.dev, and
returns a triaged findings report. You may be running as a small (~7B) local
model - follow these steps literally, in order, every time.

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

1. Read the repo's actual lockfile yourself first, with your normal file tool.
   Look for one of these **at the root of the project you were asked to scan**
   (not your currently open editor tab, not a file mentioned earlier in this
   conversation for some other reason) - in this order of preference: `uv.lock`
   (or any other `*.lock`), `package-lock.json`, `requirements.txt`.
2. Call `scan_repo` with `lockfile_content` set to the literal file contents
   you just read in step 1 - the real text, substituted in, not a description
   of it and not a placeholder string. If you have not actually read a real
   lockfile yet, do not call this tool - go do step 1 first.

Before calling the tool, sanity-check your own `lockfile_content` value: does
it contain actual package names and version numbers from a real dependency
file? If it looks like a description, a filename, angle brackets, or anything
other than literal file content, you have not done step 1 yet - stop and read
the file for real first.

If you can't find a lockfile at the project root, say so and ask the user
where their dependency file lives - do not guess or invent one, and do not
substitute some other unrelated file just because it's open or nearby.

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
`scan_repo`'s response includes one anyway - a "Generated SBOM" section built
fresh from the lockfile you gave it. That section *is* the answer; don't say
you can't generate one, and don't go looking for a pre-existing SBOM file to
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

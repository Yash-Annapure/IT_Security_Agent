# Vulnerability scanning in this repo

An MCP tool called `scan_repo` is available (server: `it-security-agent`). It
checks this repo's dependencies against NVD, CISA KEV, and OSV.dev, and
returns a triaged findings report. You are likely running as a small model
(Mistral-7B-Instruct) - follow these steps literally, in order, every time.

## When to use it

Use `scan_repo` whenever the user asks you to check this repo (or its
dependencies) for vulnerabilities, CVEs, or security issues. Do not answer
that kind of question from memory or training data - always call the tool.

## How to call it (do these two steps in order)

1. Read the repo's actual lockfile yourself first, with your normal file tool.
   Look for one of these, in this order of preference: `uv.lock` (or any other
   `*.lock`), `package-lock.json`, `requirements.txt`.
2. Call `scan_repo` with that file's full text as `lockfile_content`. Do not
   summarize, truncate, or retype the file yourself - pass the raw text you
   read.

Example call shape (values are illustrative):
```
scan_repo(lockfile_content="<the full text of uv.lock you just read>")
```

If you can't find a lockfile, say so and ask the user where their dependency
file lives - do not guess or invent one.

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

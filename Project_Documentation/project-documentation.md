# Project documentation: IT Security Agent

What this project is, how it is put together, and why it was built this way. The
[README](../README.md) covers setup; this document covers the design and the reasoning,
including the parts that were wrong the first time.

## What it does, in one paragraph

You point it at a project. It reads the list of libraries that project depends on, checks
each one against public records of known security flaws, and hands back a report sorted by
how sure it actually is. The important word is *sure*: it does not dump every name match on
you and call them all vulnerabilities. It separates the ones it can stand behind from the
ones a person needs to look at, and it says why for each.

## The problem it exists to solve

Two different worlds describe the same software using two different naming systems, and
nobody made them agree.

- **Your project** names a library the way its package registry does: `requests`, version
  `2.19.1`, from PyPI. This is a *purl* — a package URL.
- **Vulnerability databases** name software by vendor and product: vendor `python`, product
  `requests`. This is a *CPE* — a Common Platform Enumeration entry, typed in by a human.

Nothing links the two. So "does my `requests` have a known flaw?" becomes "which of NVD's
vendor/product strings, if any, is the same software as this package?" — a guess.

Guessing wrong goes badly in both directions:

- **Miss a match** and you ship a known vulnerability believing you are clean.
- **Match the wrong thing** and you get a *name collision*: the Python package `click` shares
  its name with Ubuntu's Click package manager, so a phone-OS flaw gets reported as a critical
  issue in your web app. Real example from this project's own scans.

Week 1's analysis set the ceiling on how well this can ever work: across a full 90-day NVD
pull, only about **52.6%** of CVEs carry a machine-matchable CPE entry at all — around 17% for
Debian and Alpine packages, up to 61% for PyPI. That is why this was never built as a pure
lookup tool. Nearly every design decision below exists to handle that gap honestly rather than
paper over it.

## Architecture

### The flow

```
  dependency file                 ┌─────────────────────────────────────────┐
  (uv.lock / package-lock.json    │  1. PARSE      repo_scan, sbom, schema  │
   / requirements.txt / SBOM)  ───▶│     what do you actually depend on?     │
                                  └────────────────┬────────────────────────┘
                                                   ▼
                                  ┌─────────────────────────────────────────┐
   NVD catalog ────── sync ──────▶│  2. LOOK UP    nvd_cache, matching      │
   CISA KEV    ────── sync ──────▶│     which CVEs name this package, and   │
                                  │     does the pinned version fall in     │
                                  │     the affected range?                 │
                                  └────────────────┬────────────────────────┘
                                                   ▼
                                  ┌─────────────────────────────────────────┐
   package registry ─────────────▶│  3. IDENTIFY   normalize               │
   (PyPI / npm homepage URLs)     │     which CPE vendor is really this     │
                                  │     package? (the collision problem)    │
                                  └────────────────┬────────────────────────┘
                                                   ▼
                                  ┌─────────────────────────────────────────┐
                                  │  4. SCORE      labeling, model, explain │
                                  │     how likely is this a real match?    │
                                  │     + SHAP: which signals drove it      │
                                  └────────────────┬────────────────────────┘
                                                   ▼
   OSV.dev ──── cross-check ─────▶┌─────────────────────────────────────────┐
                                  │  5. TRIAGE     agent                    │
                                  │     four buckets, explained below       │
                                  └────────────────┬────────────────────────┘
                                                   ▼
                                  ┌─────────────────────────────────────────┐
                                  │  6. REPORT     report, mcp_server       │
                                  │     markdown / JSON / HTML              │
                                  └─────────────────────────────────────────┘
```

### The modules

| Module | Job |
|---|---|
| `schema.py` | The one shape everything speaks: name, version, ecosystem, purl. |
| `repo_scan.py` | Reads `uv.lock`, `package-lock.json`, `requirements.txt`. |
| `sbom.py` | Reads and writes CycloneDX/SPDX. Builds an SBOM from a component list. |
| `generate_sbom.py` | Makes a real SBOM from a repo that has none, using no external tool. |
| `image_scan.py` | Catalogues a container image by shelling out to Syft. |
| `nvd_client.py` | Talks to NVD's API — paging, retries, rate limiting. |
| `nvd_cache.py` | Local SQLite copy of the CVE catalog, plus the product index. |
| `kev.py` | CISA's actively-exploited list. |
| `osv.py` | OSV.dev, used as an independent second opinion. |
| `registry.py` | Fetches a package's homepage URLs from PyPI/npm. |
| `normalize.py` | Turns a package name into candidate CPE vendors, with signals — read out of the cached CVE records, so no NVD call. |
| `matching.py` | Finds candidate CVEs and applies version-range logic. |
| `labeling.py` | Builds the training set and defines the seven features. |
| `model.py` | Trains logistic regression vs random forest, picks the winner. |
| `explain.py` | SHAP values — which signal pushed a score up or down. |
| `agent.py` | The triage policy. Decides which bucket each finding lands in. |
| `cwe.py` | Translates CWE IDs into plain English. |
| `report.py` | JSON and HTML output. |
| `mcp_server.py` | HTTP + MCP front end, and the markdown report. |

### Two things worth understanding

**The local cache is not just a speed trick.** Matching can only find CVEs that are in the
cache, so cache coverage is a *correctness* setting. A half-finished sync produces a
reassuringly empty report rather than an error — the most dangerous way this tool can be
wrong. Every report therefore states its own coverage, and an empty result on a thin cache is
explicitly denied the reading "your code is clean."

**Lookups are indexed, not scanned.** Finding "which CVEs mention this product" used to be a
text search across every stored record, costing time proportional to the whole cache — fine on
a small cache, 15+ minutes per scan on a complete one. A `cve_products` table maps product name
to CVE id, so a lookup is a direct seek. Counter-intuitively, the better the coverage, the
worse the old approach got.

## How it decides: the four buckets

Every candidate match lands in exactly one:

| Bucket | Meaning |
|---|---|
| **escalated** | On CISA's actively-exploited list. Being used against real targets now. |
| **confirmed** | The model cleared its threshold *or* OSV.dev independently agrees — **and** the CPE vendor is not one the package's own homepage contradicts. |
| **review_queue** | Undecided, not dismissed. Either the model was unsure, or it was confident but the vendor looks wrong. Carries SHAP values so a reviewer can check the reasoning. |
| **rejected** | The name matched but the pinned version is not affected, or no plausible vendor exists. The collision case. |

Two guards keep `confirmed` honest:

1. **Cost-weighted threshold.** A missed vulnerability is treated as ten times worse than a
   false alarm, and that weighting picks both the model and its cutoff. Not accuracy, which
   would treat both mistakes as equal.
2. **The vendor gate.** If the package's registry homepage identifies its real vendor, and the
   CVE matched a *different* vendor, the finding drops to review regardless of confidence. It
   only fires on positive evidence — absence of registry data never demotes anything. On a real
   scan this moved four false confirmations (`babel`→Babel.js, `click`→Ubuntu Click, `jupyter`
   ×2→VS Code) out of `confirmed` while leaving the one genuine finding alone.

Nothing is ever silently dropped. The strictest thing that happens to an uncertain finding is
that a human is asked to look at it.

## What this design buys you

Each of these is a property most dependency scanners do not have, and each traces to a
specific piece of the architecture rather than to effort or tuning.

| Strength | How the architecture delivers it | Where |
|---|---|---|
| **A clean result can be trusted** | Every report states how much of NVD it searched. On a thin cache, "nothing found" is explicitly denied the reading "you are clean" — most scanners report `0 findings` identically whether they searched everything or 11%. | `_cache_coverage`, `_coverage_caveat` in `mcp_server.py` |
| **Name collisions get caught** | A package's registry homepage identifies its real vendor; a CVE matching a *different* vendor is demoted. Fires only on positive evidence, so absence of data never demotes a real finding. Took `confirmed` precision from 1-in-5 to 1-in-1 on this repo. | `normalize._domain`, `matching.find_candidates`, `agent.triage_component` |
| **Nothing is silently dropped** | A miss is weighted 10× a false alarm, and that weighting picks both the model and its cutoff. The worst thing that happens to an uncertain finding is that a human is asked to look. | `model._best_threshold`, `agent.py` |
| **Uncertainty is explained** | SHAP values attached to exactly the findings a person has to judge, showing which signal moved the score and how far. | `explain.py`, `agent.py` |
| **Fast enough to run on every change** | Indexed product lookups instead of a full-table text search, batched scoring instead of per-row, and the exploit catalogue held in memory. 158 dependencies against ~368,000 CVEs in **~3.5 s, fully offline**. | `nvd_cache.cve_products`, `model.predict_confidence_batch`, `kev.load_kev_ids` |
| **Works with a small local model** | Dependency files never enter the model's context — they travel disk → `curl` → server. A 618KB lockfile would be ~4× a 32K window on its own. | `POST /scan`, `get_scan_command` |
| **The input cannot be doctored** | Only a lockfile is accepted; the SBOM is always rebuilt server-side. A supplied SBOM is a claim, and a claim can omit a vulnerable package. | `sbom.to_cyclonedx`, `_unsupported_input_reason` |
| **Two independent sources** | OSV.dev is queried separately and can confirm a match the model was unsure about, or flag one it was confident about. | `osv.py`, `report.osv_agreement_summary` |
| **Drops into any repo** | The scan tool's own response carries the rules file, so a fresh project bootstraps itself — the one channel guaranteed to be read, since Cline never surfaces an MCP server's `instructions`. | `_setup_rules_block`, `.clinerules/scan-repo.md` |
| **Reproducible** | 223 tests, ~94% coverage, every external call mocked — the suite never touches a live API or spends rate limit. | `tests/` |

### The workflow, end to end

```
  ask Cline "check this repo"
        │
        ├─ get_scan_command ──────────▶ returns one curl command, current URL filled in
        │                               (URL read off the caller's own request headers,
        │                                so a rotating tunnel address never goes stale)
        │
        ├─ curl --data-binary @uv.lock ─▶ POST /scan
        │        file goes disk → HTTP, never through the model
        │
        │   server: parse → SBOM → cache check → match → train → SHAP → triage
        │           streaming each stage back as it happens
        │
        └─ report printed + saved         verdict, coverage, findings, pipeline log
```

The streaming is not decoration: a proxy kills any request that produces no bytes for ~100
seconds, and it is also the only view a user gets of work happening on a remote machine.

## Design decisions, and why

**Read the project's own lockfile, not an SBOM someone hands us.** An SBOM supplied by a caller
is a claim, and a claim can be stale or edited to hide a vulnerable package. A lockfile is what
the project actually resolved against. The scanner builds its own SBOM from it every time.

**Registry-URL overlap is the training label, never a feature.** If the model could see the
exact signal used to generate its own answer key, it would learn to copy that signal rather than
generalise. Regression-tested so it cannot quietly creep back in.

**Explain only what needs explaining.** A confirmed finding does not need justification — someone
should be fixing it. An uncertain one does, because a bare confidence number gives a reviewer
nothing to argue with.

**Keep dependency files out of the model's context entirely.** This is the load-bearing rule of
the whole integration, and it is architectural rather than advisory. A real lockfile is hundreds
of kilobytes — this repo's own is 618KB, roughly four times a 32K-context model's entire window.
It does not matter *how* it arrives: a file read, a `cat`, or a tool argument all land in context
the same way. So the file travels disk → `curl` → server, and the model only ever holds the
command and the finished report.

That rule shaped the tool surface too. Tools that take file *content* as a parameter are hidden
by default, because a model asked to scan for vulnerabilities picks the most on-the-nose tool it
can see — and a required parameter named `lockfile_content` tells it to go read the file. No
amount of instruction text outranks a schema. Removing the parameter from view does.

**Verify every claim against a live run.** This appears three times in the project's history:
the collision fix, the feature-importance ranking, and a chart-rendering bug. Two of the three
were wrong when first written up. A chart or a sentence that has not been checked against real
execution is a hypothesis, not a finding.

## What went wrong, and what it taught

Four bugs found by checking rather than trusting:

1. **Domain matching was too coarse.** Every reference URL collapsed to its bare host, so two
   unrelated GitHub projects both became `github.com` and looked identical. Broke collision
   detection for `babel`, `json5`, and `jsonpointer`. Fixed by keeping owner and repo segments
   for multi-tenant hosts.
2. **The decision threshold sat at the floor.** Because misses are weighted so heavily, many
   thresholds tie for best risk score; the code picked the lowest, so almost any nonzero
   confidence auto-confirmed and the review queue was effectively bypassed. Fixed by taking the
   middle of the tied range.
3. **A SHAP chart was fed the wrong data shape**, producing a wrong feature ranking that had
   already been written up as a real finding. Once fixed, the ranking came out close to the
   opposite. The old claim was retracted in writing rather than quietly replaced.
4. **Vendor collisions still reached `confirmed`** even after 1 and 2. This one was not an
   implementation bug but the ceiling of a seven-proxy-feature model, and it is what the vendor
   gate was added to address.

## Regulatory analysis (EU-focused)

Week 1 did this same analysis before any of the scanning code existed, against a planned architecture. Below is the same kind of table, for the system as it actually stands now.

| Regulation | Relevance to this project |
|---|---|
| **Cyber Resilience Act (CRA)** | Manufacturers of products with digital elements must maintain an SBOM and handle vulnerabilities across the product lifecycle, including reporting actively exploited flaws to ENISA/CSIRTs (24h early warning, 72h follow-up). This project produces exactly that artifact, and does not depend on someone else's SBOM being trustworthy: `generate_sbom.py` rebuilds a real CycloneDX document from the project's own lockfile on every scan, so a stale or incomplete supplied SBOM can never quietly become the source of truth. The four-bucket triage (escalated, confirmed, review_queue, rejected) is the vulnerability-handling record that CRA compliance work would consume, with CISA KEV hits, actively exploited vulnerabilities, surfaced first. |
| **NIS2 Directive** | Imposes supply-chain security and incident-reporting obligations on essential and important entities. A working vulnerability scanner is a concrete control supporting that requirement, and the vendor gate (which caught four real name-collision false positives on this project's own dependencies during testing) plus the OSV.dev cross-check both cut down the false-positive load on whatever incident-response process NIS2 requires, so effort isn't spent chasing name coincidences instead of real issues. |
| **GDPR** | Still mostly indirect: the agent processes software component metadata (package names, versions, vendor strings), not personal data. One specific change is worth noting though: dependency-file content, which could include internal package or host naming, is deliberately kept out of the conversational model's context entirely, and that model now runs self-hosted, on infrastructure the user controls, rather than a third-party hosted API. That is a stronger data-minimization and data-residency posture than the project needed to consider before this architecture existed. |
| **EU AI Act** | This project ships exactly one AI system: the confidence classifier (logistic regression or random forest) that scores whether a vendor match is real. It almost certainly falls under minimal or limited risk, not an Annex III high-risk use case, but the transparency and human-oversight expectations that apply to any AI system are built into the architecture, not added afterward: every uncertain finding gets a SHAP explanation and a mandatory human review step (`review_queue`) rather than a silent pass or fail. The conversational, generative layer, Cline plus a self-hosted Mistral model, is a separate system this project calls into, not one it trains or ships, so this project acts as a deployer of that model, not its provider. |
| **NVD Terms of Use** | Not legislation, but still a binding practical constraint on API rate limits and attribution. `nvd_client.py` and `nvd_cache.py` implement that directly: a full NVD sync now runs once, locally, rather than as a live call per package on every scan. |

**Takeaway:** the finished system holds up against the same regulatory picture Week 1 sketched before any code existed, and in two places, CRA's SBOM obligation and the AI Act's transparency and oversight expectations, it satisfies the requirement more concretely than the original plan called for. That wasn't the explicit goal going in. The same design choices that solved the actual engineering problems, an auditable local cache, a narrow classifier kept separate from the conversational layer, mandatory human review for anything uncertain, turned out to serve the regulatory picture too.

## Current state

- **223 tests passing, ~94% coverage.** Every external call is mocked, so the suite never touches
  a live API or spends rate limit.
- A full scan of this repo's 158 dependencies against a complete ~368,000-CVE cache runs in about
  **3.5 seconds, entirely offline**.
- Reports state their own cache coverage, so a clean result can be read in context.

## What is still open

- **Container images are library-only.** `image_scan.py` shells out to Syft and is tested against
  a mocked subprocess, but the path is not exposed through the server, and it has never been run
  against a live Syft or Docker setup.
- **OS packages get no vendor resolution.** Registry lookups cover PyPI and npm only, so
  Debian/Alpine components carry no homepage signal — they cannot be labelled, cannot train the
  model, and cannot trigger the vendor gate. A mostly-OS image would fall back to untriaged raw
  matches.
- **The training signal has a ceiling.** Registry-URL overlap is real but coarse. Something that
  captures CPE-reference similarity more directly, with the same leakage guard, is the honest next
  step.
- **The training set is one project's dependencies.** A broader, more varied set would make the
  model comparison mean more than a single project's worth of collisions.

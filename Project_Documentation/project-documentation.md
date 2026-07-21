# Project documentation: IT Security Agent

This is the full record of the project: what got built, in what order, and why each decision was made the way it was. The [README](../README.md) is the setup guide and the [walkthrough](walkthrough.md) is a plain-language tour of the pipeline; this document is the history and the reasoning behind it, including the parts that didn't work on the first try.

## What this project is

The agent reads a project's dependencies, whatever form they show up in, and checks them against public vulnerability sources (NVD, CISA's actively-exploited list, OSV.dev), then sorts what it finds by how confident it actually is, rather than handing back a flat list of name matches. The hard part was never the lookup itself, it was that dependency files identify packages by purl and vulnerability databases identify software by CPE, a vendor and product string, and nothing guarantees those line up. Most of the project's design exists to handle that gap honestly instead of papering over it.

## Timeline: what got built, and in what order

### Week 1: understanding the problem before building anything

The first week was entirely analysis, no scanning code yet. It pulled data live from the NVD REST API 2.0, sketched a multi-week architecture, and did an EU regulatory pass (the Cyber Resilience Act, NIS2, GDPR, and the EU AI Act) to see what a tool like this would actually be obligated to do in production.

The finding that shaped everything after it: across a full, correctly paginated 90-day NVD pull, only about 52.6% of CVEs carry a structured, machine-matchable CPE entry at all, and that coverage varies a lot by ecosystem, around 17% for Debian and Alpine packages, up to 61% for PyPI. That's the reason this project never became a pure CPE-lookup tool. A hybrid approach, CPE matching plus independent cross-checks like OSV, was the only way to get reasonable coverage.

### Week 2: a working matching engine, and the first classifier

Week 2 built the first real matching engine: wildcard-vendor CVE queries against NVD, checked locally against version ranges, run against this project's own `uv.lock` plus 16 fixture packages with known vulnerabilities. On top of that sat a baseline logistic regression classifier meant to tell a real vendor match from a coincidental one, trained on 28 pairs labeled by hand from the scan's own false positives.

Two analyses came out of that baseline, and both mattered later. The risk analysis framed the cost of a missed vulnerability against the cost of a wasted review, and the finding was blunt: the classifier beat a naive "trust every match" baseline on plain accuracy, but lost on a false-negative-weighted risk score, because it introduced misses the naive approach never had. The conclusion carried straight into Week 3's design: a model like this should flag uncertain matches for a human, not silently filter them. The fairness analysis split model error rates by ecosystem (PyPI versus npm) as a first check on whether the model treated one ecosystem worse than another.

### Week 3: turning the prototype into an actual pipeline

Week 3 moved everything out of notebook-only code into a real package, `it_security_agent/`, and wired it into one pipeline: input parsing, a local NVD cache, vendor resolution, model training, explainability, triage, and reporting. The main changes from Week 2:

- Three input paths instead of one hardcoded file: an existing SBOM (CycloneDX or SPDX), a container image via Syft, or the repo's own lockfile (`uv.lock`, `package-lock.json`, later also `requirements.txt`).
- A local SQLite cache of the NVD catalog, synced once, so a scan never makes a live NVD call per package the way Week 2 did.
- A real CPE Dictionary lookup and vendor-resolution step (`normalize.py`), replacing Week 2's ad hoc keyword scoring.
- Automatic training labels instead of hand-labeled pairs: a vendor candidate counts as a real match if its CPE entry's reference URL shares a domain with the package's actual registry homepage. That signal became the label, and specifically never became a model feature, so the model can't just learn to reproduce the rule that generated its own answer key.
- Two models trained and compared, logistic regression and a random forest, scored on the same false-negative-weighted risk metric Week 2 introduced, with only the winner persisted.
- SHAP explanations for anything the triage policy sends to human review.
- A four-bucket triage policy (`agent.py`): escalated (CISA KEV hit), confirmed, review queue, rejected, cross-checked against OSV.dev where the ecosystem supports it.
- JSON and HTML report output.

### The follow-up work: analyzing the models, going deeper on explainability, and auditing our own claim

After the original Week 3 run, three more questions got asked, and answering them honestly turned up real problems worth fixing rather than confirming everything was fine.

**Comparing the two models properly.** Week 3 picked the random forest by risk score alone, a single number. The follow-up looked at where each model's mistakes actually land: on the same held-out test split, logistic regression missed 0 real matches but kept 494 collisions as false positives, while the random forest missed 1 real match but kept only 166. That's why it wins, a small increase in missed vulnerabilities buys a false-positive count less than a third the size.

**Going deeper on explainability than one global plot.** The first SHAP summary plot showed feature importance globally, but not what a specific ambiguous finding actually looks like to a reviewer. Two hand-built examples with the identical, perfect name-similarity score were run through the same explanation function the agent itself uses, one with supporting keyword and OSV evidence, one without, and they landed on opposite verdicts (confidence 0.91, confirmed, versus confidence 0.01, sent to review). Name similarity alone was never sufficient to tell a real match from a collision, that finding held up under scrutiny and is the actual reason the model has seven features instead of one.

**Checking whether the collision problem was actually fixed, not just claimed fixed.** Week 2 had found four PyPI packages in this project's own dependencies whose names collide with unrelated products: `babel` (versus Babel.js), `jupyter` (versus a Microsoft VS Code extension), `json5`, and `jsonpointer` (versus their npm namesakes). Rather than trust that the Week 3 design handled these, a dedicated test ran all four live against real NVD data. Two real bugs turned up:

1. `normalize._domain()` reduced every reference URL down to its bare hosting domain, so two different GitHub repositories, the real `babel` package and the unrelated npm `babel`, both collapsed to `github.com` and looked identical. This broke the collision check for `babel`, `json5`, and `jsonpointer` specifically.
2. `model._best_threshold()` picked the lowest threshold that tied for minimal risk, rather than a value from the middle of that tied range. Because a missed real vulnerability was weighted so much worse than a false alarm, there was usually a wide plateau of thresholds with identical risk scores, and picking the floor of that plateau meant almost any nonzero confidence was enough to auto-confirm a match, skipping the review queue entirely.

Both are fixed now, with regression tests. Three of the four collisions are correctly caught after the fix. The fourth, `jupyter`, still gets wrongly confirmed, and that one isn't a bug: `registry_overlap` is deliberately never given to the model as a feature (only as the label), so the model has to reconstruct that signal from proxies, and for this specific case those proxies read exactly like a real match. That's written down as an honest limitation, not hidden.

**Closing the last input-path gap.** `generate_sbom.py` was added so a repo with no SBOM at all, only its own lockfiles, gets a real CycloneDX document generated from them, with no external tool. It round-trips losslessly through the same parser a third-party SBOM would use, confirmed by a test that generates, reparses, and checks nothing was lost or invented in the process.

### The MCP server and the Cline integration

Once the pipeline worked end to end, it got exposed as a single MCP tool, `scan_repo`, in `it_security_agent/mcp_server.py`, running over Streamable HTTP rather than stdio so it can be hosted on a separate machine, such as one running a self-hosted model, instead of the user's own laptop. Because the server is remote, it was deliberately built with no access to the caller's filesystem: `scan_repo` takes a lockfile or SBOM's raw text as an argument, not a path, so whatever agent calls it has to read the file locally first and pass the contents through.

A `.clinerules` file at the repo root tells Cline's model exactly how to do that: read the dependency file itself, call `scan_repo` with its content, then relay the result bucket by bucket without inventing a CVE ID, severity, or score that wasn't literally in the tool's output. It also tells the model not to treat the first call's one-to-two-minute delay (the server syncing NVD's catalog before it can answer) as an error.

The setup this was built against runs a self-hosted Mistral-7B-Instruct through vLLM, registered in Cline as an OpenAI-compatible endpoint, with this repo's MCP server registered separately as a remote tool. Full setup steps are in the README.

### This session: re-running the pipeline for real, and catching a third bug

Everything above had been checked in isolation at some point, but the Week 3 notebook itself had drifted out of sync with a fresh, live run. Re-executing it end to end surfaced a third real bug, this time in the presentation material rather than the scanning logic: the cell that renders Section 4's global SHAP summary plot was feeding the model's raw, multi-class SHAP output directly into `shap.summary_plot()`, instead of slicing to the "real match" class first the way `explain.explain_match()` already did everywhere else. The visible symptom was a garbled, clipped chart. The actual consequence was worse: the wrong data shape produced a wrong ranking, and an earlier write-up had already recorded that wrong ranking as a genuine, "surprising" finding (that `keyword_alignment` and `osv_corroborated` mattered more than name similarity).

Once the plotting bug was fixed and the notebook re-run against fresh live data, the real ranking turned out to be close to the opposite: `name_similarity` and `vendor_equals_package` are the two features with the widest spread of impact on the model's output, `keyword_alignment` is third, and `osv_corroborated` barely moves the needle in aggregate. The notebook's Summary cell and the presentation script were both corrected to reflect this, with a note explaining that the old claim was retracted, not just quietly replaced. This is the same discipline Section 9 already established for the collision claim: a chart or a sentence that hasn't been checked against a live run is a hypothesis, not a finding.

## Decisions made, and why

**Read the repo's own lockfile as a first-class input, not just SBOMs.** An SBOM handed to the scanner could be stale, or edited to hide a vulnerable dependency before it ever reaches the tool. Reading the lockfile a repo already resolves its own dependencies against keeps that document outside the trust boundary the scanner has to reason about.

**Use fuzzy string matching for CPE vendor resolution, not exact string matching.** NVD's CPE Dictionary is vendor and product strings typed in by a person, with no purl mapping. Exact matching would miss almost everything; fuzzy matching against name similarity, combined with a registry-domain-overlap check, is what makes the vendor-resolution step workable at all, and it's also exactly where the babel-style collision risk comes from.

**Use registry-URL overlap only as a training label, never as a model feature.** If the model could see the exact signal used to generate its own answer key, it would just learn to reproduce that signal, not learn anything generalizable. This is regression-tested directly (`test_labeling.py`) so it can't quietly regress.

**Weight a missed vulnerability ten times worse than a false alarm, and use that weighting for both model selection and the confidence threshold.** A flat accuracy score, or a flat 0.5 cutoff, treats both kinds of mistakes as equally costly, and they aren't: a missed real vulnerability is a security incident waiting to happen, a false alarm is a few minutes of a reviewer's time.

**Sync NVD into a local cache once, instead of querying live per package per scan.** Week 2's live-per-package approach took minutes per run and didn't scale to repeated scans. A local SQLite cache, synced on an interval rather than per call, turned every lookup during an actual scan into a local read.

**Attach a SHAP explanation only to review-queue findings, not to every finding.** A confirmed or escalated finding doesn't need justification to act on, someone should already be fixing it. An uncertain finding does, because a bare confidence number gives a reviewer nothing to check their own judgment against.

**Run the MCP server over Streamable HTTP, with no filesystem access, rather than a local stdio server.** This was a deliberate choice to let the model side and the tool side live on different machines, one running a self-hosted LLM, one running this project's scanner, without either one needing direct access to the other's disk. The caller (Cline) reads files locally and passes content through; the server never touches a path it didn't receive as text.

**Treat every claim as something to verify against a live run, not something to write down once and trust.** This shows up three separate times in the project's own history: the collision-fix claim, the model feature-importance claim, and this session's chart-rendering claim. All three were checked against real execution, and two of the three turned out to be wrong on first write-up. That pattern is now the project's actual testing philosophy, not just an aspiration.

## Current state

The test suite runs 124 tests, all passing, with every external call (NVD, the CPE Dictionary, OSV, CISA, the PyPI and npm registries) mocked, so running the tests never touches a live API or spends rate limit. The last full coverage run measured around 94% across the package. What's still unverified in a live environment specifically: `image_scan.py`'s Syft integration is only exercised against a mocked subprocess call, since Syft and Docker haven't been available wherever this has run so far.

## The interface decision: why there is no standalone upload interface

This project does not have, and does not need, a page where someone uploads an SBOM file, points at a Docker image, or picks a lockfile from their machine. That kind of interface assumes a user interacting with a standalone tool as a distinct step, separate from asking for what they actually want. This project's actual interface is Cline, a conversational, prompt-driven coding agent, and that changes what "giving it a file" even means.

In this setup, a user doesn't hand the scanner a file at all. They ask, in plain language, something like "check this repo for vulnerabilities," and `.clinerules` tells Cline's model to read whatever dependency file is relevant on its own and pass the contents to the `scan_repo` tool as part of answering that request. The file-reading step still happens, but it happens inside the conversation, driven by intent, not as a separate upload action a user performs against a standalone interface.

Building a dedicated upload UI on top of that would be redundant, and arguably worse: it would ask a user to manually do a step the conversational interface already does for them, and it would need its own way to select a lockfile, a container image, or an SBOM format, decisions `.clinerules` already makes automatically based on what it finds in the repo. The prompt is the interface. That's a deliberate consequence of choosing Cline as the front end, not a missing feature.

## What's still open

- Proper packaging is in place (`[build-system]` in `pyproject.toml` makes the package genuinely pip-installable now), but the presentation notebook still adds the repo root to `sys.path` rather than relying on an editable install, since re-running the entire live pipeline just to drop that workaround hasn't been worth it yet.
- The training set still relies on registry-URL overlap as its only ground-truth signal. It's a real signal, but the `jupyter` limitation shows its ceiling: a feature that captures registry or CPE-reference similarity more directly, with the same leakage guard `registry_overlap` already has, is the honest next step.
- `image_scan.py`'s Syft integration has never run against a live Syft or Docker setup, only against its own mocked tests.
- A bigger, more varied training set beyond this project's own dependency list would make the model comparison in Section 7 more meaningful than a single project's worth of collisions.

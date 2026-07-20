# Week 3 presentation script

This has grown from a tight 3-minute script into a full reference: every section, plus how to talk through each chart and where its numbers actually come from. Each heading is labeled with the matching section in `week3_agent.ipynb`, so you know where to have the notebook scrolled to. Use the priority list at the bottom to cut it back down to whatever time slot you actually have. The "How to talk through this chart" and "finding, and how we got it" blocks under Sections 4, 7, and 8 are reference material for Q&A or an extended demo, not lines to memorize, skip them first if you're short on time and the plain paragraph above them already makes the point.

---

## Opening (10 seconds) — notebook: before Section 1

Week 2 gave us a matching engine and a first classifier, but it only read one hardcoded file, and nothing acted on what it found. This week turned that into a real pipeline, checked against real data, not just a claim.

## Notebook Section 1 — "Input: one component list from all input paths"

*Cue: used to only read one file format, now reads anything.*

First, what goes in. We used to only read `uv.lock`. Now there are three paths in: parse an existing SBOM, scan a container image with Syft, or read the repo's own lockfile directly, `uv.lock`, `package-lock.json`, or `requirements.txt`. And if a repo has none of those at all, Section 10 covers what happens then.

## Notebook Sections 2 and 3 — "Sync NVD + CISA KEV once" / "Train two models, keep the better one"

*Cue: live per-package NVD calls and 28 hand-labeled pairs, now a local cache and automatic labels at scale.*

Section 2: instead of hitting NVD live for every package on every scan, we sync once into a local cache and work off that from then on. Section 3 is the bigger change. Last week's classifier was trained on 28 pairs we labeled ourselves, which meant we were grading our own homework. Labels now come automatically, from whether a candidate vendor's registry link actually shares a domain with the package's real homepage, checked with fuzzy string matching against NVD's CPE dictionary. We trained two models on that, logistic regression and a random forest, and picked the winner using a cost where missing a real vulnerability counts ten times worse than a false alarm.

## Notebook Section 4 — "Explainability: SHAP for the winning model"

*Cue: bare confidence score, now a reason attached.*

A confidence score by itself isn't something a person can act on. So any finding the model isn't sure about gets a SHAP explanation attached, which specific signals pushed the score up or down, so a reviewer sees a reason, not just a number.

**How to talk through this chart:** it's a beeswarm plot, one dot per training example. The 7 features are stacked top to bottom by how much they matter overall, most important at the top. A dot's left-right position shows whether that signal pushed the model toward "real match" or toward "collision" for that one example, and the dot's color shows whether the feature's value was high or low there.

**The finding, and how we got it:** we ran this same plot across all 17,090 labeled rows from Section 3. The two features that matter most turn out not to be the obvious one. `keyword_alignment` and `osv_corroborated` do most of the separating, not raw name similarity. A perfect name match with nothing else backing it up actually pushes toward "collision," not away from it, the exact pattern Section 9 finds live in `babel` and `json5`.

## Notebook Sections 5 and 6 — "The agent: triage every match into four buckets" / "Report output"

*Cue: pipeline used to stop at a score, now a full triage policy.*

This used to just produce a score and stop. Now there's an actual policy. Anything on CISA's actively-exploited list gets escalated first. Confirmed findings and anything sent for human review are split automatically. And everything, including what got rejected, goes into a report, so nothing is silently dropped.

## Notebook Sections 7 and 8 — "Model analysis: logistic regression vs. random forest" / "XAI deep dive: worked examples"

*Cue: Section 3 picked a winner by one number, now we show our work on why, down to specific examples.*

Sections 7 and 8 go a level deeper on the model. Section 3 picked the random forest by risk score alone, one number. Section 7 shows why: the confusion matrix for both models on the same held-out data, and which features each one actually leans on. The important part is `registry_overlap`, the one signal that actually separates a real match from a collision, is deliberately kept out of both models' features, it's the label, not an input, so neither model can just look it up. Section 8 then walks two real findings through the exact same explanation function `agent.py` uses for every review-queue case, so what's on screen is literally what a human reviewer would see, not a summary of it.

**Section 7's chart, how to talk through it:** two horizontal bar charts side by side, one per model, same 7 features on both. The logistic regression bars can point left or right, since its coefficients have a direction, a feature can push toward "real match" or away from it. The random forest bars only point one way, it just reports how much each feature mattered, not which direction, that's how random forests work, not an inconsistency to explain away.

**Section 7's finding, and how we got it:** we ran both models against the same held-out 30 percent of the data and pulled the actual confusion matrix for each. Logistic regression missed 0 real matches but kept 507 collisions as false positives. Random forest missed 1 real match but only kept 166. That single extra miss out of roughly 600 real matches in the test set buys a false-positive count less than a third the size, which is why it wins on the risk score, 176 versus 507.

**Section 8's chart, how to talk through it:** same beeswarm idea as Section 4, but zoomed into one feature, `keyword_alignment`. The x-axis is the raw score itself, how clearly a CVE's own text reads as Python versus JavaScript. The y-axis is how much that value moved the prediction. Dots trending upward left to right is confirmation the feature is doing what it was designed to do.

**Section 8's finding, and how we got it:** we built two hand-picked rows with the exact same perfect name-similarity score, one with matching keyword and OSV evidence, one without, and ran both through the same explanation function a reviewer would see. Identical name match, opposite outcome: confidence 0.92 and confirmed for one, confidence 0.01 and sent to review for the other. Name similarity alone was never enough to tell a real match from a collision, that's the whole reason the other six features exist.

## Notebook Section 9 — "Weakness check: did we actually fix Week 2's name collisions?"

*Cue: the part worth slowing down for. We didn't just claim this was fixed, we tested it live and found real bugs.*

This is the section I actually want to highlight. Week 2 had four packages whose names collide with unrelated projects, `babel`, `jupyter`, `json5`, `jsonpointer`. We went back and tested, live, against real NVD data, whether we'd actually fixed that. Three of the four now get caught correctly, and running this check found two real bugs, which we fixed: a domain check that couldn't tell two different GitHub repos apart, and a threshold picker that was too permissive. The fourth, `jupyter`, still gets wrongly confirmed. Not a bug, just the honest limit of the current features, and that's written down as next steps, not hidden.

## Notebook Section 10 — "Generating an SBOM from repo files, then scanning it"

*Cue: last input-path gap. If there's no SBOM at all, we make one instead of giving up.*

Section 10 closes that gap. Up to now we'd either parsed a lockfile straight into components, or scanned an SBOM someone else already produced. This is the third case: no SBOM at all. `generate_sbom.py` builds a real CycloneDX document straight from this project's own `uv.lock`, no external tool. We then feed that generated SBOM back through the exact same parser a third-party SBOM would use, to confirm nothing was lost or invented in the round trip, and scan a subset of it with the model already trained in Section 3. This isn't a demo-only trick either, it's exactly what the MCP server's `scan_repo` tool does for Cline: generate a real SBOM from whatever lockfile it's handed, then scan it.

## Closing (10-15 seconds) — outside the notebook, live Cline demo

And this whole pipeline is now wired up so Cline, an AI coding assistant, can call it directly, talking to a model we're hosting ourselves. No dashboard to build. You just ask it to check your repo, and it reads your lockfile, runs the scan, and hands back a triaged answer.

---

**Rough timing:** the plain "say this" paragraphs alone (no chart breakdowns) still run about 4:20 to 4:40. Add the chart-reading and findings blocks under Sections 4, 7, and 8 and the whole thing runs closer to 7:30-8:00. Neither is a 3-minute script anymore, so use the priority order below rather than reading top to bottom.

Priority order for cutting, highest-value first (keep these), lowest-value last (cut these first):

1. Keep: Opening, Section 9 (the weakness audit), closing (the Cline demo). These are the three moments that make the talk memorable, not just correct.
2. Keep if time allows: Section 1, Sections 2/3, Sections 5/6. This is the actual pipeline story.
3. Cut first: the "How to talk through this chart" / "finding, and how we got it" blocks under Sections 4, 7, and 8. Keep them in your back pocket for if someone asks "wait, what does that graph mean," but they're the first thing to skip while talking.
4. Cut next: Sections 7/8's plain paragraph too. It elaborates on Sections 3/4 rather than covering new ground.
5. Cut last: Section 10. Real and worth having, but the least essential to the story if you're still over time.

Cutting 3 and 4 gets you back to roughly the original 3:00-3:15 version. Cutting just 3 keeps every section but trims the deep-dive material, landing around 4:20-4:40.

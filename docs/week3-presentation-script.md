# Week 3 presentation script

Written to be read aloud in about 3 minutes at a normal pace (roughly 140-150 words a minute). Each section is labeled with the matching section in `week3_agent.ipynb`, so you know where to have the notebook scrolled to while you say that part. Practice it once out loud before presenting, the timing below assumes you don't stop mid-sentence.

---

## Opening (10 seconds) — notebook: before Section 1

Week 2 gave us a matching engine and a first classifier, but it only read one hardcoded file, and nothing acted on what it found. This week turned that into a real pipeline, checked against real data, not just a claim.

## Notebook Section 1 — "Input: one component list from all input paths"

*Cue: used to only read one file format, now reads anything.*

First, what goes in. We used to only read `uv.lock`. Now there are three paths in: parse an existing SBOM, scan a container image with Syft, or read the repo's own lockfile directly, `uv.lock`, `package-lock.json`, or `requirements.txt`. And if a repo has none of those, Section 10, later on, generates a real CycloneDX SBOM ourselves, straight from the lockfile, no external tool needed.

## Notebook Sections 2 and 3 — "Sync NVD + CISA KEV once" / "Train two models, keep the better one"

*Cue: live per-package NVD calls and 28 hand-labeled pairs, now a local cache and automatic labels at scale.*

Section 2: instead of hitting NVD live for every package on every scan, we sync once into a local cache and work off that from then on. Section 3 is the bigger change. Last week's classifier was trained on 28 pairs we labeled ourselves, which meant we were grading our own homework. Labels now come automatically, from whether a candidate vendor's registry link actually shares a domain with the package's real homepage, checked with fuzzy string matching against NVD's CPE dictionary. We trained two models on that, logistic regression and a random forest, and picked the winner using a cost where missing a real vulnerability counts ten times worse than a false alarm.

## Notebook Section 4 — "Explainability: SHAP for the winning model"

*Cue: bare confidence score, now a reason attached.*

A confidence score by itself isn't something a person can act on. So any finding the model isn't sure about gets a SHAP explanation attached, which specific signals pushed the score up or down, so a reviewer sees a reason, not just a number.

## Notebook Sections 5 and 6 — "The agent: triage every match into four buckets" / "Report output"

*Cue: pipeline used to stop at a score, now a full triage policy.*

This used to just produce a score and stop. Now there's an actual policy. Anything on CISA's actively-exploited list gets escalated first. Confirmed findings and anything sent for human review are split automatically. And everything, including what got rejected, goes into a report, so nothing is silently dropped.

## Notebook Section 9 — "Weakness check: did we actually fix Week 2's name collisions?"

*Cue: the part worth slowing down for. We didn't just claim this was fixed, we tested it live and found real bugs.*

This is the section I actually want to highlight. Week 2 had four packages whose names collide with unrelated projects, `babel`, `jupyter`, `json5`, `jsonpointer`. We went back and tested, live, against real NVD data, whether we'd actually fixed that. Three of the four now get caught correctly, and running this check found two real bugs, which we fixed: a domain check that couldn't tell two different GitHub repos apart, and a threshold picker that was too permissive. The fourth, `jupyter`, still gets wrongly confirmed. Not a bug, just the honest limit of the current features, and that's written down as next steps, not hidden.

## Closing (10-15 seconds) — outside the notebook, live Cline demo

And this whole pipeline is now wired up so Cline, an AI coding assistant, can call it directly, talking to a model we're hosting ourselves. No dashboard to build. You just ask it to check your repo, and it reads your lockfile, runs the scan, and hands back a triaged answer.

---

**Rough timing:** opening 10s, Section 1 about 25-30s, Sections 2/3 combined about 40-45s, Section 4 about 20s, Sections 5/6 combined about 25-30s, Section 9 about 35-40s, closing 10-15s. That lands around 2:55 to 3:15. If you're running long, trim Sections 2/3's last sentence (the risk-weighting detail) or Section 1's SBOM-generation aside, those are the least load-bearing lines. Don't cut Section 9 short, it's the strongest part of the talk.

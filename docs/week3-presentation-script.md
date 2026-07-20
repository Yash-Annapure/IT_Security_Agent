# Week 3 presentation script

Written to be read aloud in about 3 minutes at a normal pace (roughly 140-150 words a minute). Each section has a one-line cue for your own reference, then the actual paragraph to say. Practice it once out loud before presenting, the timing below assumes you don't stop mid-sentence.

---

## Opening (10 seconds)

Week 2 gave us a matching engine and a first classifier, but it only worked off one hardcoded file and nothing acted on what it found. This week we turned that prototype into a real pipeline, so we'll walk through it as five problems we ran into, and what we built to fix each one.

## 1. What goes in (cue: only read one file format, now reads anything)

First problem: we could only read `uv.lock`. A real project might hand you an SBOM, a container image, or nothing at all. So now there are three ways in. Parse an existing SBOM. Scan a container image with Syft. Or just read the repo's own lockfile directly, `uv.lock`, `package-lock.json`, or `requirements.txt`. And if none of those exist, we generate a real SBOM ourselves, straight from the lockfile, no external tool needed.

## 2. Telling real matches from name collisions (cue: naive name search, now a real vendor check)

Second, matching used to just search the vulnerability database for the package name and trust whatever came back. That's a problem, because names collide. npm's `babel` and Python's own `babel` package can return the exact same CVE, for two completely unrelated projects. When we tested this properly, out of around 17,000 candidate vendor matches, only about 12 percent turned out to actually be the same project. So we added a real vendor-resolution step against NVD's CPE dictionary: fuzzy string matching to score how close the package name is to each candidate vendor's product name, plus a check on whether that vendor's reference link actually shares a domain with the package's real PyPI or npm page. Anything that can't be tied to the correct vendor that way gets rejected outright instead of silently confirmed.

## 3. A model trained on real evidence (cue: 28 hand-labeled pairs, now automatic labels at scale)

Third, last week's classifier was trained on 28 pairs we labeled ourselves, which meant we were grading our own homework. Labels now come automatically, from whether a candidate vendor's registry link actually points at the package's real homepage, no manual judgment call involved. We trained two models on that, logistic regression and a random forest, and picked the winner using a cost that counts missing a real vulnerability as ten times worse than raising a false alarm.

## 4. Explaining the uncertain calls (cue: bare confidence score, now a reason attached)

Fourth, a confidence score by itself isn't something a person can act on. So any finding the model isn't sure about now comes with an explanation attached, which specific signals pushed the score up or down, so whoever reviews it sees a reason, not just a number.

## 5. From score to action (cue: pipeline stopped at a score, now a full triage policy)

Finally, none of this used to lead anywhere, it just produced a score and stopped. Now there's an actual policy behind it. Anything on CISA's actively-exploited list gets escalated to the top. Confirmed findings and anything sent for human review are separated automatically. And everything, including what got rejected, is written out to a report, so nothing is ever silently dropped. All of it is backed by over a hundred passing tests.

## Closing (10-15 seconds)

And this week, that whole pipeline got wired up so it can be called straight from Cline, an AI coding assistant, talking to a model we're hosting ourselves. No dashboard to build. You just ask it to check your repo, and it reads your lockfile, runs the scan, and hands back a triaged answer.

---

**Rough timing:** opening 10s, sections 1, 3, and 4 at about 30-35 seconds each, section 2 closer to 40-45s now that it names the actual technique, section 5 about 35s, closing 10-15s. That lands around 3:00 to 3:20. If you're running long, section 3 and section 5 are the safest to trim, they're the only ones with a sentence that isn't load-bearing for the "before/now" contrast.

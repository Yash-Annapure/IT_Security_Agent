# Omnic — 10-Minute Presentation Script (2 speakers)

**Deck:** `omnic-deck.html` (5 slides) — advance with → or spacebar, animations play automatically on entry.
**Speakers:** labeled **A** and **B** below — swap in your real names before presenting.
**Pacing:** the time ranges assume a natural, unhurried pace and include a few seconds of silence where an animation is doing the talking (e.g. the Cline demo on Slide 2, the storybox sequence on Slide 5). Do one full read-through with the deck open to calibrate — everyone's pace differs slightly.

Ethics/regulatory content is woven into the pitch itself, not bolted on as a separate section, since that's how the project actually treats it. A quick-reference summary of where each regulation is covered is at the very bottom for your own prep.

---

## [0:00 – 1:30] SLIDE 1 — The Problem
**Speaker A** · *visual: collision cards animate in, then the caption line*

> Good [morning/afternoon]. We're presenting **Omnic** — a vulnerability scanner that doesn't just tell you what it found, it tells you how sure it is, and why.
>
> Here's the problem it exists to solve. *(gesture to the two cards)* Say your project depends on a Python package called `jupyter`. A vulnerability database also has a record for something called `jupyter` — except that one's Microsoft's Jupyter extension for VS Code. Completely different software. Same name. Most scanners would flag your project as critical and move on. That's a false alarm, and chasing it wastes a security team's time.
>
> And this isn't a rare edge case. *(gesture to caption text)* Only about half — 52.6%, to be precise — of all vulnerability records even carry enough information to be matched reliably in the first place. The rest is guesswork. So the real question was never "can we find string matches." Any tool can do that. The question is: can we tell you which matches are *actually real*.

**Handoff:** "That's the problem. Let's show you what it's actually like to use." → **B**

---

## [1:30 – 3:00] SLIDE 2 — Meet Omnic
**Speaker B** · *visual: Cline panel types the task, runs, completes — let it play, don't talk over the typing*

> Omnic doesn't ask anyone to learn a new tool. *(gesture to panel)* It lives inside Cline, a coding assistant already sitting in your editor. You just type what you want in plain English — "scan repo for vulnerabilities" — and Omnic does the rest.
>
> One detail worth pointing out, because it's a privacy choice, not an accident: the dependency file itself is never read by the AI model. It goes straight from your disk to the scanning server as a simple file upload — the model only ever sees the short command and the final report, never your actual codebase. And that scanning server, and the language model behind it, both run on infrastructure we control — not a third-party API somewhere else. Nothing about your project ever leaves your own machines. That's a deliberate data-minimization decision.

**Handoff:** "So that's how you *ask*. Now — what actually happens after you hit enter?" → **A**

---

## [3:00 – 5:00] SLIDE 3 — How It Works
**Speaker A** · *visual: six pipeline nodes stagger in left to right*

> Every scan goes through six stages. *(gesture across the row as each node lands)*
>
> **One** — it reads your repo: your lockfile, or if you don't have a formal inventory, it builds one from scratch. That inventory matters more than it sounds — it's exactly the kind of documentation the EU's Cyber Resilience Act now requires software makers to keep. And Omnic doesn't trust a pre-made one if you hand it one; it rebuilds a fresh copy every single scan.
>
> **Two** — it checks that against a fully-downloaded vulnerability database sitting locally. No live internet calls mid-scan, so it's fast, and nothing can rate-limit it.
>
> **Three** — this is a trust checkpoint, and it's the one that fixes our `jupyter` problem from a minute ago. It cross-checks the vendor against the package's *own* registry page, so a same-name collision gets caught here, before it ever becomes a finding.
>
> **Four** — a trained model scores how confident it is in what's left.
>
> **Five** — another trust checkpoint. Everything lands in one of four buckets: escalated, confirmed, review, or rejected. Nothing just quietly disappears.
>
> **Six** — it writes the report in plain English.

**Handoff:** "So every scan leaves a real paper trail. Let's talk about why that trail is the whole point." → **B**

---

## [5:00 – 7:30] SLIDE 4 — The Receipts
**Speaker B** · *visual: three stats count up, then the four-bucket breakdown reveals underneath*

> We called this slide "the receipts" because every number on it came from a real run — not a claim we're asking you to take on faith. *(gesture to stats as they count)* A full scan — checking your dependencies against a database of over 368,000 known vulnerabilities — finishes in about three and a half seconds, entirely offline. The whole system is backed by 240 automated tests at 95% coverage.
>
> *(gesture to the four-bucket breakdown)* And here's the part that actually matters for trust: those four outcomes from the pipeline aren't a black box. Rejected findings never even reach the AI model at all — they're filtered out by simple, deterministic checks, like a version number that just doesn't match. Confirmed and escalated findings both need real evidence behind them. And anything genuinely ambiguous goes to a human review queue — with an explanation attached, using a technique called SHAP, that shows exactly which signals made the model hesitate.
>
> This isn't only good engineering — it's also, frankly, close to what regulation already expects. Omnic ships exactly one AI component: a small classifier deciding whether a vulnerability match is real. Under the EU AI Act, that's not a high-risk system, but Omnic still builds in the two things *any* AI system is expected to have — transparency, and a mandatory human check on anything it's not sure about — instead of adding them after the fact. And under GDPR, since the tool only ever touches package names and version numbers, never personal data, there's very little exposure to begin with.

**Handoff:** "So it's fast, it's tested, and it explains itself. Let's show you how little it takes to actually get it running." → **A**

---

## [7:30 – 10:00] SLIDE 5 — Get Started (and close)
**Speaker A**, then **Speaker B** for the close · *visual: the three-part sequence — faces, then repo cards, then the settings/MCP walkthrough — let each beat play before speaking over it*

> **A:** So who is this for, and what does it actually take to set up?
>
> *(gesture to the cycling avatars)* **Any analyst** — security engineer, SRE, backend developer, doesn't matter. Nobody needs special training, because you're just talking to it in plain English.
>
> *(gesture to the cycling repo cards)* **Any repo** — point it at a codebase it's never seen before, and it writes its own onboarding rules on the very first run, automatically.
>
> *(gesture to the settings walkthrough)* And setup really is **minimal** — three steps. Point Cline at the model, paste in one configuration block to connect the scanning server, and that's genuinely the whole install.

> **B:** To close — *(gesture to close-line)* we didn't set out to build a compliance tool. We set out to build a scanner that doesn't cry wolf, and doesn't miss the real thing. But it turns out those are largely the same goals regulators care about too: an auditable trail, a human always in the loop, nothing hidden. The engineering and the compliance ended up being the same design decisions.
>
> Security tooling should disappear into the workflow you already have. Omnic does.
>
> Thank you — we're happy to take questions.

---

## Quick-reference: where the regulatory content lands

*(For your prep only — not meant to be read aloud as a list.)*

| Regulation | Where it's covered | The one-line hook |
|---|---|---|
| **Cyber Resilience Act (CRA)** | Slide 3, stage 1 (Parse) | Omnic generates a fresh SBOM every scan — never trusts a supplied one. |
| **NIS2 Directive** | Slide 3, stage 3 (Identify) / Slide 4 close | The vendor-collision check cuts false positives that would otherwise clog incident response. |
| **GDPR** | Slide 2 (Meet Omnic) | Only package names/versions are processed; the lockfile never reaches the model; self-hosted, not a third-party API. |
| **EU AI Act** | Slide 4 (The Receipts) | Minimal/limited-risk AI component, but built with transparency (SHAP) and mandatory human oversight (review queue) anyway. |

Source for all four: `Project_Documentation/project-documentation.md`, "Regulatory analysis (EU-focused)" section — pull that up if the professor asks for more depth than the script covers.

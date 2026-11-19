# Capstone — Build, Attack, Harden, Report

---

## The arc

> Build a small AI-integrated application. Threat-model it. Attack it — yours and
> another team's. Harden it. Report the before and after, with evidence.

This is the whole course in one project: the CIA goals (wk 1), a real threat model
(wk 1), web and systems hardening (wk 6–8), AI-specific attack and defense
(wk 9–13), and the privacy/governance analysis (wk 11–12) — measured on the
Control Scorecard throughout.

## Deliverables

| # | Artifact | Weight |
|---|---|---|
| 1 | **The app** — small, real, AI-integrated, in the lab sandbox | 4 % |
| 2 | **Threat model** — STRIDE + the AI extension, with trust boundaries | 4 % |
| 3 | **Attack report** — your findings on your app AND on your assigned peer's | 6 % |
| 4 | **Hardening** — controls added, with before/after Control Scorecards | 6 % |
| 5 | **Measured comparison** — where you used AI to attack or defend, scored against a baseline | 4 % |
| 6 | **Governance & ethics section** — the Perlroth-thread analysis, evidence-backed | 2 % |
| 7 | **Demo** — 10 min live in week 14 | 2 % |

## What "AI-integrated" must mean

The app must have a **model in a position where it matters** — an LLM that reads
untrusted input, calls a tool, or touches sensitive data. Examples that qualify:

- A support chatbot with access to a (synthetic) customer database
- A document-QA / RAG app over a corpus you can poison
- A code-review or log-triage assistant wired to act on its output
- An agent that calls tools (send email, run a query, fetch a URL)

An app where the model only paraphrases static text does **not** qualify — there
is nothing to attack. The interesting security lives where the model has **agency
or access**.

## The peer red-team (why #3 has two targets)

In week 11 each team is assigned another team's app. You attack it with the same
rigor you attack your own, file findings through the responsible-disclosure ritual
(wk 6–10), and the target team responds. **Both directions are graded:**

- As attacker: quality and confirmation of findings (sound oracles, reliability).
- As defender: how you triaged, fixed, and measured the fixes reported against you.

This is the closest thing to a real security engagement the course can offer, and
it makes the disclosure norms muscle memory rather than a lecture.

## ⚠️ Scope, restated

Everything runs in the sandbox. You attack **your own app** and the **one peer app
you are assigned**, which is running on shared course infrastructure or exchanged
as a container — never a live external service. The
[`../resources/ethics-and-scope.md`](../resources/ethics-and-scope.md) rule is
absolute here too.

## Required report sections

1. **What we built and why it is realistic** (1 paragraph)
2. **Threat model** — diagram, boundaries, STRIDE + AI-extension table
3. **Attacks we landed** — each with payload, sound-oracle confirmation, and
   reliability; separate subsections for our-app and peer-app
4. **Hardening** — each control with a before/after Control Scorecard including a
   bypass attempt and false-positive cost
5. **AI, measured** — the one place you used AI as attacker or defender, scored
   against a classical baseline with `seclab.scan` or `seclab.attack`
6. **Governance & ethics** — connect one thread from Perlroth (zero-day markets,
   state actors, the human element) to a concrete decision in your app: what would
   you disclose, hoard, or refuse to build, and why. Evidence, not opinion.
7. **Where we may have been unfair, and what we did not test** — the honesty clause

## Grading stance

Same as every scorecard in the course: **we grade the engineering, not the
verdict.** A team that reports "our hardening reduced the attack success rate from
90 % to 55 %, and here is the bypass that still works and the two false positives
it introduced" scores higher than a team claiming "our app is now secure." The
first sentence is what a security engineer writes; the second is what gets a
company breached.

## Timeline

| Week | Milestone |
|---|---|
| 8 | App concept + initial threat model (checkpoint, ungraded feedback) |
| 11 | App running in sandbox; peer red-team assignments made (this IS Duel 3) |
| 13 | Hardening + measured comparison done |
| 14 | Demo + full report due |

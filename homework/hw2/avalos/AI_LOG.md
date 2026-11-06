# AI_LOG — Homework 2 (Web Attack & Defend)

**Team:** Gabriel Avalos · Keoma Quiroga · David Bucheli
**Tool:** Claude (Opus), via Claude Code, as a coding/writing pair-programmer and —
in Part C only — as the LLM reviewer under test.

Per [`../../resources/ethics-and-scope.md`](../../resources/ethics-and-scope.md) and
`resources/ai-policy.md`: AI use is allowed and must be disclosed; we are responsible
for everything submitted. No real secrets, client data, or private lab details were
pasted into any hosted model — all work is against the local `vuln-web` app and the
course's own fixtures. Before submitting we read every script and every result file
ourselves so we can defend the reasoning in the closed-book peer review.

## What we asked AI to do

- Scaffold `homework/hw2/avalos/` to the assignment structure and wire the in-process
  `vuln-web` harness with a per-field defense layer and the three `seclab` oracles.
- Part A: send each baseline **through** the Medium filter and find three
  oracle-confirmed bypasses per class (case / comment / nesting / alternate vector).
- Part B: build the blocklist WAF, search for same-intent bypasses, implement the
  parameterized fix, and measure coverage / bypass / false-positives.
- Part C: run real `semgrep` and `bandit`, write the line-oriented scanner, and score
  everything against the hand-built ground truth, including the non-determinism run.
- Draft the README, honesty section, and this log.

## What we kept

- All runnable code. **Every number in the README comes from `python run_all.py`
  against the real in-process app**, not from prose: Part A 3/3 per class (baselines
  0/3, benign controls 0/3, `/safe` 0/3); B1 coverage 4/4 + 5/5 oracle-confirmed
  bypasses + 6/21 (28.6%) FP; B2 vulnerable 9/9 vs parameterized 0/9 with a legit
  login still working; Part C the full scorecard and the 11/14/15 non-determinism.
- The oracle-first discipline: a finding counts only when an oracle confirms a
  security effect; we applied the **same bar to our own bypasses** (WAF-passed **and**
  canary-leaked).

## Entry 4 — Part C: acting as the LLM arm (read this one carefully)

The grading sandbox has no Ollama model and no API key, so `seclab.LLM`'s only working
backend is `manual` ("paste prompts into a chat interface and paste answers back").
**The assistant that built this homework is that chat interface.** For the duel we
therefore produced **three independent reviews of `vulnweb_app.py`**, each generated
in a *separate, isolated context that saw only the source file* (no shared memory
between runs, no sight of the ground truth or of each other), to stand in for three
sampled completions. They are committed verbatim as `duel/llm_review_run{1,2,3}.txt`.

**This is not identical to one model API sampled three times at temperature>0.** It is
variation between three independent cold reviews by the same assistant — a real and
relevant thing to measure (a reviewer re-reading code *does* notice different things),
but we do not claim it is strictly "model sampling non-determinism." We also keep the
week-6 studio's canned small-model text as `llm_mock.py` and score it alongside, so
the contrast is explicit: the small-model mock makes the Broken-Access-Control
hallucination *every* run and flags the fixed `/safe` endpoint, while the real runs
make BAC in only 1 of 3 and never flag `/safe`.

## What AI got wrong (and we corrected)

- **Overclaimed scanner lesson.** An earlier draft concluded "the scanner can't see
  the SQLi because it spans two lines." That is only true of a *single-line* rule. We
  added a real `semgrep` **multiline** rule that **does** catch the two-line query (and
  `bandit` catches it via data-flow), and rewrote the finding as "the miss is a
  rule-design choice, not a law of scanners." Caught by actually running the tools.
- **First WAF-bypass set was wrong.** Initial SQLi bypasses relied on the `OR`
  keyword, which our own WAF blocks (`\bor\b`); others broke SQL syntax and leaked
  nothing. We kept only the five that pass the WAF **and** leak the canary on the real
  sink — the "an LLM invents a bypass that doesn't work" failure the ethics doc warns
  about, caught only because we insisted on oracle confirmation.
- **Free-text parser over-matched.** The Part-C parser first counted any line
  mentioning "XSS"/"SQL" anywhere (e.g. a security-headers finding that *references*
  XSS) as that class. We anchored it on the declared `[SEV] <class> in <function>`
  structure so each finding is scored by its real class — itself the "parsing model
  output is error-prone" lesson.

## What we rejected

- Reporting the LLM arm as a live production model. It is disclosed above as
  independent assistant reviews + a documented mock; `honesty.md` §3 states the duel
  measures a cold off-the-shelf review, not a tuned ceiling.
- Any claim that the WAF is "secure." It is reported as bypassable (5/5) and noisy
  (28.6% FP); the guarantee belongs only to the positive model.
- Counting the LLM's out-of-scope but *real* findings as false positives to make the
  duel's story cleaner. `honesty.md` §2 explains the scoring-scope choice and gives the
  stricter numbers.

## Human verification before submission

- [ ] Confirm the group members and the submission path with the team (this folder is
      the single group PR; Quiroga and Bucheli should not also submit separately).
- [ ] Run `python run_all.py` in your own environment and confirm `[PASS]` on all four.
- [ ] (Optional) With Ollama: `ollama pull qwen2.5:3b` and compare a real local-model
      run against our committed transcripts.
- [ ] Re-read every payload and rule so you can defend them in the peer review.

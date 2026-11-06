# AI_LOG — Homework 2 (Web Attack & Defend)

**Team:** Gabriel Avalos · Keoma Quiroga · David Bucheli
**Primary tool:** Claude (via Claude Code), used as a coding/writing pair-programmer and, in Part C only, as the LLM reviewer under test.

Per `resources/ai-policy.md` and `resources/ethics-and-scope.md`: AI use is allowed and logged here, and we are responsible for everything we submit. No real secrets, client data, or private lab details were pasted into any hosted model. All work is against the local `vuln-web` app and the course's own fixtures (synthetic data only).

---

## Entry 1 — Scaffolding and test harness

**Tool:** Claude (via Claude Code)
**What I asked:** "Scaffold `homework/hw2/avalos/` to the assignment structure and wire an in-process `vuln-web` harness with a per-field defense layer and the three `seclab` oracles."
**What I got:** The directory layout, `common/paths.py`, `common/app_harness.py`, `common/medium_filter.py` and `run_all.py` (driver plus an HTTP smoke test).
**What I did with it:** Kept all of it. I ran `python run_all.py` and confirmed `[PASS]` on all four stages. Every number in the README comes from that run, not from prose. I also documented that `vuln-web` has no difficulty levels, so `medium_filter.py` is our own reproduction of DVWA-Medium.
**Did I understand it?** Yes. I read every script and can explain how the harness places the filter in front of each sink and how the oracles decide a finding is confirmed.

## Entry 2 — Part A: oracle-confirmed bypasses

**Tool:** Claude (via Claude Code)
**What I asked:** "Send each baseline payload through the Medium filter, then find three bypasses per class (SQLi, XSS, cmdi) that an oracle confirms."
**What I got:** Case, comment, nesting and alternate-vector payloads for each class (uppercase `OR`, `/**/`, `<ScRiPt>`, `<scr<script>ipt>`, `<svg onload=>`, `|`, `&`, `$(…)`).
**What I did with it:** Kept only payloads where the oracle confirmed 3/3 trials. I kept the blocked baselines (0/3), the benign controls (0/3) and the `/safe` true negative (0/3) as evidence that each bypass was necessary and not a strawman.
**Did I understand it?** Yes. I can say why each payload evades the case-sensitive `str_replace`/strip rules. I also know the limits of the XSS and cmdi oracles (no browser, and `do_ping` does not execute a command). These are in `honesty.md` §4 and §7.

## Entry 3 — Part B: WAF, bypasses and the positive fix

**Tool:** Claude (via Claude Code)
**What I asked:** "Build a blocklist WAF for the SQLi sink, find same-intent bypasses, implement a parameterized fix, and measure coverage / bypass / false positives."
**What I got:** `common/waf.py` (six rules), `common/positive_fix.py` (`login_fixed` with bound parameters) and a first list of bypass candidates.
**What I did with it:** **Rejected the first bypass set.** It relied on the `OR` keyword, which our own WAF blocks (`\bor\b`). Other candidates broke the SQL syntax and leaked nothing, which is the "model invents a bypass that doesn't work" failure the ethics doc warns about. I kept only the five candidates that pass the WAF **and** leak the canary on the real sink. I also rejected any wording that called the WAF "secure." It is reported as bypassable (5/5) and noisy (6/21 = 28.6% FP).
**Did I understand it?** Yes. I can explain the `/* … :: … */` trick across the `user` and `pw` fields. I can also explain why parameterization gives a guarantee conditional on every code path using bound parameters, which a blocklist cannot give.

## Entry 4 — Part C: scanners and an overclaimed lesson

**Tool:** Claude (via Claude Code)
**What I asked:** "Run real `semgrep` and `bandit`, write a line-oriented regex scanner, and score everything against `ground_truth.json`."
**What I got:** The scanners, our own semgrep rules, the scoring script, and an initial conclusion that "the scanner can't see the SQLi because it spans two lines."
**What I did with it:** **Corrected the conclusion.** It is only true of a single-line rule. We added a multiline semgrep rule that catches the two-line query (bandit catches it through data flow), and rewrote the finding as "the miss is a rule-design choice, not a law of scanners." The free-text parser also over-matched (any line mentioning "XSS"/"SQL" counted as that class), so we anchored it on the `[SEV] <class> in <function>` structure.
**Did I understand it?** Yes. I re-ran the tools myself, and the committed semgrep/bandit rows reproduce when both tools are installed.

## Entry 5 — Part C: the LLM arm (read this one carefully)

**Tool:** Claude (via Claude Code), acting as the LLM reviewer under test
**What I asked:** Three separate reviews of `vulnweb_app.py`, each in an isolated context that saw only the source file (no ground truth, no other run), with the same generic prompt.
**What I got:** `duel/llm_review_run{1,2,3}.txt` with 11, 14 and 15 findings. Runs 1 and 3 score 1.00. Run 2 adds a Broken Access Control hallucination at `do_POST` (F1 0.86).
**What I did with it:** Committed the transcripts verbatim and scored them against the hand-built ground truth. The environment had no Ollama model and no API key, so `seclab.LLM` could only use the `manual` backend, and the assistant acted as that chat interface. **This is not one model API sampled three times at temperature > 0.** It is three independent cold reviews by the same assistant, and we do not claim it is strict sampling non-determinism. The isolation of the contexts cannot be verified from the transcripts alone. We also score the week-6 small-model text (`llm_mock.py`) as a contrast baseline. I rejected two framings: calling the LLM arm a live production model, and counting the LLM's real out-of-scope findings (plaintext passwords, missing rate limiting, …) as false positives to make the story cleaner. `honesty.md` §2 and §3 give the stricter numbers and the effort asymmetry.
**Did I understand it?** Yes. I can explain why the perfect scores of runs 1 and 3 are weak evidence given the scoring scope and the cold prompt. I can also explain why the BAC claim is a hallucination: the app has no auth, session or role code.

## Entry 6 — README and honesty drafting

**Tool:** Claude (via Claude Code)
**What I asked:** "Draft the README, `honesty.md` and this log from our actual results."
**What I got:** First drafts of all three documents.
**What I did with it:** Checked every number against the files in `*/results/` and the output of `python run_all.py`, and edited the prose so each claim is backed by a committed result. Kept the seven self-critiques in `honesty.md`.
**Did I understand it?** Yes. I read everything and can defend the reasoning in the peer review.
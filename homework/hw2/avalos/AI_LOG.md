# AI_LOG — Homework 2

**Team:** Gabriel Avalos · Keoma Quiroga · David Bucheli
**Model used:** Claude (Opus) via Claude Code, as a coding/writing assistant.

Per [`../../resources/ethics-and-scope.md`](../../resources/ethics-and-scope.md):
AI use is allowed; we are responsible for everything submitted. No real secrets,
client data, or private lab details were pasted into any hosted model — all work
is against the local `vuln-web` app and the course's own fixtures.

## What we asked AI to do

- Scaffold the `homework/hw2/avalos/` deliverable to the assignment's structure
  (`attack/`, `defend/`, `duel/`, `honesty.md`, `AI_LOG.md`, `README.md`).
- Wire the in-process `vuln-web` harness and the three `seclab` oracles (SQLi
  canary, unescaped-markup XSS, cmdi metacharacter) for Part A.
- Build the WAF blocklist and search for same-intent SQLi bypasses for Part B, and
  implement the parameterized-query positive fix.
- Set up the scanner-vs-LLM scoring against the provided ground truth for Part C,
  including the two-run non-determinism measurement.
- Draft the README, honesty section, and this log.

## What we kept

- All runnable code. Every number in the README comes from actually running the
  scripts against the real in-process app (`python run_all.py`), not from prose:
  Part A 3/3 per class, B1 coverage 4/4 + bypass 4/4 + FP 2/26, B2 0/6, Part C
  scores and Jaccard 0.50.
- The oracle-first discipline: a finding counts only when an oracle confirms a
  security effect. We applied the **same bar to our own bypasses** — a candidate
  bypass counts only if the WAF passes it *and* the real sink leaks the canary.

## What AI got wrong (and we corrected)

- **First bypass set was wrong.** AI initially proposed SQLi bypasses like
  `admin' OR 1` and `admin' OR 2>1`. Running them against the real sink showed
  they produced a **SQL syntax error** (the stray closing quote from the
  `'{user}'` template), so they leaked nothing — only 1 of 4 was genuine. We
  replaced them with `LIKE`, `<>`, and `/**/`-comment variants that the sink
  *proved* leak the canary (now 4/4). This is logged because it is exactly the
  "an LLM invents a bypass that doesn't work" failure the ethics doc warns about —
  caught here only because we insisted on oracle confirmation.
- We verified the `/safe` endpoint is a true negative (0/3) rather than trusting
  that it was fixed.

## What we rejected

- Reporting the LLM mock as if it were a live model. It is a **documented mock**
  (no model pulled, no API key); `honesty.md` §2 states plainly that this makes the
  duel measure "a plausible off-the-shelf model," not a prompt-tuned one, so the
  precision comparison must not be read as "LLMs lose."
- Any claim that the WAF is "secure." The deliverable reports it as bypassable
  (4/4) and noisy (7.7% FP); the guarantee belongs only to the positive model.

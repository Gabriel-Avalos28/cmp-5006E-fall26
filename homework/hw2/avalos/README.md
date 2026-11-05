# Homework 2 — Web Attack & Defend

**Team:** Gabriel Avalos · Keoma Quiroga · David Bucheli
**Course:** CMP-5006E (Fall 2026) — Homework 2 (graded version of the week 6/7 studios)
**Target:** `vuln-web` (`labs/vuln-web/app/vulnweb_app.py`), run **in-process on 127.0.0.1** — laptop-only.
**Scope/ethics:** we attack only the app we run ourselves; synthetic data only. See [`../../resources/ethics-and-scope.md`](../../resources/ethics-and-scope.md).

> **The bar we aimed for:** not "we blocked the attacks" but *"here is the attack
> confirmed by an oracle, here is our defence, here is the bypass that still works,
> and here is the false-positive cost we measured."*

## How to reproduce everything

```bash
cd homework/hw2/avalos
python run_all.py          # runs Parts A, B, C; regenerates every CSV + transcript
# or individually:
python attack/attack.py    # Part A
python defend/defend.py    # Part B
python duel/duel.py        # Part C
```

No Docker, no Ollama, no API key required. The harness (`_harness.py`) brings the
course `vuln-web` app up in-process, exactly like the GIVEN week-6/7 harnesses.

## Layout

```
avalos/
  _harness.py                 in-process vuln-web + senders + fixture loaders
  attack/   medium.py         a "Medium"-level filter (DVWA-Medium stand-in)
            attack.py         Part A: 3 classes, each confirmed through a bypass
            results/attack_findings.csv
  defend/   waf.py            Part B engine: WAF blocklist + parameterized sink
            defend.py         Part B: coverage, bypass (axis 4), FP (axis 5), positive fix
            results/*.csv
  duel/     llm_backend.py    the documented LLM mock (two differing runs)
            duel.py           Part C: scanner vs LLM vs hand-built ground truth
            llm_review_run{1,2}.txt, results/*.csv
  honesty.md                  Part D — where our work might be unfair
  AI_LOG.md                   required AI-use log
```

---

## Part A — Attack (3 classes, each oracle-confirmed through a filter bypass)

`vuln-web` ships no difficulty levels, so `attack/medium.py` is an explicit
stand-in for **DVWA's Medium** filter: a per-sink blocklist that stops the obvious
week-6 payload. For each class we show the naive payload **blocked**, a one-line
**bypass** that the filter **passes**, and a **sound oracle** confirming the effect
on the real sink — fired `trials=3` so a flaky confirmation can't pass as reliable.

| Class | OWASP 2021 | Naive payload (blocked by Medium) | Bypass (passes Medium) | Oracle | Confirmed |
|---|---|---|---|---|---|
| **SQLi** @ `do_login` | A03 Injection | `admin' OR 1=1--` | `admin' OR 'a'='a'--` | admin canary `FLAG-sqli-9f2c-…` returned | **3/3** |
| **XSS** @ `do_reflect` | A03 Injection | `<script>alert('XSS-7f3a')</script>` | `<img src=x onerror=alert('XSS-7f3a')>` | injected markup survives **unescaped** | **3/3** |
| **cmdi** @ `do_ping` | A03 Injection | `127.0.0.1; whoami` | `127.0.0.1 \| whoami` | shell metachar reached command context | **3/3** |

Controls that **must stay clean**, and do (0/3 each):

- SQLi benign `alice` + wrong password → no canary.
- XSS benign `Keoma O'Brien` (legit apostrophe) → no live marker.
- XSS **true negative** `/safe` (same `<img>` bypass) → escaped by `html.escape`, 0/3.
- cmdi benign `api.internal.example` → no metacharacter.

**Oracle discipline (axis 3):** each oracle checks a *security-relevant effect*
(exfiltrated canary / live unescaped element / metacharacter reaching the command),
never a reflected string. Evidence: [`attack/results/attack_findings.csv`](attack/results/attack_findings.csv).

**Broken Access Control (#1) — reachable here?** No. `vuln-web` has **no**
auth, session, or role code at all: `do_login` leaks the secret on *any* matching
row and there is no privileged operation gated by identity. Access control is an
*application-semantics* property; with no notion of "who may do what," there is no
access-control boundary to break. (This is the exact lesson Part C makes the LLM
fail on — it hallucinates a BAC finding anyway.)

---

## Part B — Defend the SQLi finding, then bypass our own defence

### B1 — Negative model (WAF blocklist) — `defend/waf.py`

Five ModSecurity-CRS-style rules (numeric tautology, string tautology, `UNION
SELECT`, `DROP TABLE`, `--`).

| Blade | Result | Evidence |
|---|---|---|
| **Coverage** on known attacks (axis 3) | **4/4 blocked** | [`defend/results/waf_coverage.csv`](defend/results/waf_coverage.csv) |
| **Bypass** (axis 4) — *mandatory* | **4/4 genuine** bypasses (WAF-passed **and** canary-leaked on the real sink) | [`defend/results/waf_bypasses.csv`](defend/results/waf_bypasses.csv) |
| **False positives** (axis 5) — *mandatory* | **2/26 = 7.7%** legit inputs blocked | [`defend/results/waf_false_positives.csv`](defend/results/waf_false_positives.csv) |

The four bypasses (all same intent = leak the admin canary):

1. `admin' OR 'a' LIKE 'a ` — `LIKE` tautology, no `=`, no `--`.
2. `admin' OR 'x'<>'y` — `<>` inequality is always true; evades the `=` rules.
3. `admin'/**/OR/**/'a'='a` — inline `/**/` comment defeats the rule's `\bor\b\s+` whitespace anchor.
4. `admin'/**/oR/**/'1'='1` — mixed case + `/**/`: the classic tautology still slips through.

Each is **oracle-confirmed**: the WAF passed it *and* the real `do_login`
returned the canary `FLAG-sqli-9f2c-admin-session`.

The two false positives are genuinely benign requests the blocklist wrongly blocks:

- `"drop table tennis lessons for beginners"` → fired **SQLi DROP TABLE**.
- `"reserve the drop table at the makerspace friday"` → fired **SQLi DROP TABLE**.

### B2 — Positive model (parameterization) — the real fix

`parameterized_login` binds `user`/`pw` as **values** (`?` placeholders) against the
same canary DB. We re-ran **all** Part-A SQLi payloads **and** the four B1 bypasses
(6 hostile inputs) through both sinks:

| Sink | Canary leaked |
|---|---|
| Vulnerable `do_login` (string-formatted) | **6/6** |
| Parameterized `do_login` (bound params) | **0/6** |

Evidence: [`defend/results/positive_fix.csv`](defend/results/positive_fix.csv).

**The guarantee (axis 2), stated as a conditional:** *for any input string, the
parameterized query's structure is fixed at parse time, so no input can change
which rows are selected — injection cannot succeed, for any input.* The WAF cannot
make this claim: it enumerates *known bad* (open-ended), so bypass #5 always exists;
the positive model enumerates the *good path* structurally. **Headline:** the
blocklist raised cost (bypassable 4/4 + 7.7% noise); parameterization gave a
guarantee (0/6, for any input).

---

## Part C — The duel: LLM vs. scanner

Both arms point at the same `vulnweb_app.py` and are scored against a **hand-built
ground truth** (`homework/hw2/duel-2-web/ground_truth.json`, built by reading the
source — *not* by running a tool). `sqlmap`/`semgrep` are not installed and Ollama
has no model pulled, so — as the assignment permits — the classical arm is the
course's line-oriented regex scanner (a Semgrep/CodeQL stand-in) and the LLM arm is
the **documented mock** (`duel/llm_backend.py`), run twice.

| Tool | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| regex-scanner | 2 | 0 | 1 | **100%** | 67% | 0.80 |
| llm-run1 | 3 | 2 | 0 | 60% | **100%** | 0.75 |
| llm-run2 | 3 | 1 | 0 | 75% | **100%** | 0.86 |

Evidence: [`duel/results/duel_scores.csv`](duel/results/duel_scores.csv), [`duel/results/llm_findings.csv`](duel/results/llm_findings.csv).

1. **Scores.** Classic shape: the scanner is precise but **misses the SQLi**; the
   LLM finds everything but **cries wolf**.
2. **Scanner's worst miss:** `sqli @ do_login`. The rule needs the interpolation on
   the same line as `SELECT`, but the query spans two lines — a real failure mode of
   single-line rules, not a contrivance.
   **LLM's best hallucination:** **Broken Access Control** — confidently reported in
   an app with *zero* auth/session/role code (ground truth lists it as *not present*).
3. **Non-determinism (axis 9):** over two runs the LLM's finding **set changed**
   (Jaccard = 0.50). Run 1 also flagged the fixed `do_reflect_safe` (a false
   positive) and put BAC on `do_login`; run 2 dropped the `/safe` flag and moved BAC
   to `do_ping`. A review you can't reproduce isn't evidence — the two raw
   transcripts are committed ([`duel/llm_review_run1.txt`](duel/llm_review_run1.txt), [`duel/llm_review_run2.txt`](duel/llm_review_run2.txt)).
4. **Did either tool find an access-control issue?** No *real* one exists. The
   scanner correctly stayed silent; the LLM **hallucinated** one on both runs (just
   at different locations). This is the week-6 lesson: OWASP #1 needs application
   context that neither a pattern rule nor a context-free LLM review has.

---

## Part D — Honesty

See [`honesty.md`](honesty.md): where our attack, defence, or comparison might be unfair
(ground-truth independence, effort asymmetry, benign-corpus realism, least-reproducible finding).

## AI use

See [`AI_LOG.md`](AI_LOG.md).

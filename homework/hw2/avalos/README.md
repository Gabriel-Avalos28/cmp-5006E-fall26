# Homework 2 — Web Attack & Defend

**Team:** Gabriel Avalos · Keoma Quiroga · David Bucheli
**Course:** CMP-5006E (Fall 2026) — HW2 (graded version of the week 6/7 studios)
**Target:** `vuln-web` (`labs/vuln-web/app/vulnweb_app.py`), run **in-process on 127.0.0.1** — laptop-only.
**Scope/ethics:** we attack only the app we run ourselves; synthetic data only. See [`../../../resources/ethics-and-scope.md`](../../../resources/ethics-and-scope.md).

> **The bar we aimed for:** not "we blocked the attacks" but *"here is the attack
> confirmed by an oracle, here is our defence, here is the bypass that still works,
> and here is the false-positive cost we measured."*

## How to reproduce everything

```bash
cd homework/hw2/avalos
python run_all.py          # Parts A, B, C + a real HTTP smoke test; regenerates every CSV/JSON
# or individually:
python attack/attack.py    # Part A
python defend/defend.py    # Part B
python duel/duel.py        # Part C
python duel/scanners.py    # see each classical scanner's raw output
```

No Docker, no Ollama, no API key required to reproduce the committed numbers. The
duel's classical arm uses **real `semgrep` and real `bandit`** when they are
installed (`pip install semgrep bandit`); if they are absent the duel skips them and
notes it — the always-runnable `regex-naive` scanner still runs. The LLM arm uses
three committed cold-review transcripts — an assistant serving as `seclab.LLM`'s
`manual` backend, not an API sampled 3× (see `AI_LOG.md` Entry 4 and Part C †).

**Reproducibility notes.** Runs on CPython 3.9+ with the standard library only
(plus `seclab`, already in the repo); all paths are resolved relative to the repo
root (`common/paths.py`), so the suite runs unchanged on Windows, macOS, or Linux,
and every fixture is read as UTF-8 explicitly. Two caveats a grader should know:

1. **The committed `duel/results/duel_scores.csv` and `duel_report.json` include the
   `semgrep` and `bandit` rows**, because those tools were installed when the
   evidence was generated. On a machine **without** them, re-running `duel.py`
   reproduces the `regex-naive` and the three `llm-run*` rows identically but
   **omits** the two real-scanner rows (the duel prints a note saying so). That is
   graceful degradation, not a discrepancy — install `semgrep` + `bandit` to
   regenerate those two rows.
2. The LLM arm is deterministic on re-run (it replays the three committed
   transcripts), so the precision/recall/F1 and the non-determinism measured
   *across* the three runs reproduce exactly.

## Layout

```
avalos/
  common/     paths.py          repo-root locator (portable; no absolute paths)
              app_harness.py    in-process vuln-web + per-field defense layer + seclab oracles
              medium_filter.py  the DVWA-Medium filter Part A bypasses (wired in front of each sink)
              waf.py            Part B1 blocklist WAF (negative model)
              positive_fix.py   Part B2 structural fixes (parameterize / escape / allowlist)
  attack/     attack.py         Part A: 3 classes, baseline-through-filter + 3 bypasses each
              results/attack_findings.csv · .json
  defend/     defend.py         Part B: coverage, bypass (axis 4), FP by field (axis 5), positive fix
              results/*.csv · defend_summary.json
  duel/       scanners.py       regex-naive + real semgrep + real bandit
              semgrep_rules.yaml  our own rules (naive single-line AND a multiline SQLi rule)
              llm_mock.py       the documented small-model mock (contrast baseline)
              llm_review_run{1,2,3}.txt  three independent REAL-model reviews (verbatim)
              duel.py           scores everything vs the hand-built ground truth
              results/*.csv · duel_report.json
  honesty.md                    Part D — where our work might be unfair (7 points)
  AI_LOG.md                     required AI-use log
  run_all.py                    driver + real HTTP smoke test
```

---

## Part A — Attack (3 classes, each oracle-confirmed through a filter bypass)

`vuln-web` ships no difficulty levels, so `common/medium_filter.py` is an explicit,
documented stand-in for **DVWA's Medium** filter, wired **in front of each sink** by
the harness. For every class we send a **baseline** payload through the filter and
show the oracle does **not** confirm (proof the bypass was necessary, not a
strawman), then **three bypasses** that the filter passes and a **sound oracle**
confirms on the real sink — each fired `trials=3`.

| Class | OWASP 2021 | Baseline (blocked, 0/3) | Bypasses (all 3/3) | Oracle |
|---|---|---|---|---|
| **SQLi** @ `do_login` | A03 Injection | `admin' or '1'='1` | uppercase `OR` · `/**/` comment+case · inline `-- ` | admin canary `FLAG-sqli-9f2c-…` exfiltrated |
| **XSS** @ `do_reflect` | A03 Injection | `<script>…</script>` | mixed-case `<ScRiPt>` · nested `<scr<script>ipt>` · `<svg onload=>` | injected markup survives **unescaped** |
| **cmdi** @ `do_ping` | A03 Injection | `127.0.0.1; whoami` | pipe `\|` · single `&` · `$(…)` | shell metacharacter reached the command context |

Controls that must stay clean, and do (**0/3** each): SQLi benign `alice`; XSS benign
`Keoma O'Brien`; cmdi benign `api.internal.example`; and the XSS **true negative** —
the same `<svg>` bypass at the fixed `/safe` endpoint (escaped by `html.escape`).
Evidence: [`attack/results/attack_findings.csv`](attack/results/attack_findings.csv).

**Broken Access Control (#1) — reachable here?** No. `vuln-web` has no auth, session
or role code: there is no access-control boundary to break. The SQLi reads the admin
row, but that is a confidentiality failure **via Injection (A03)**, not a broken
A01 decision — matching `ground_truth.json`'s explicit `not_present`. (Part C makes
the LLM fail on exactly this.)

---

## Part B — Defend the SQLi finding, then bypass our own defence

### B1 — Negative model (WAF blocklist) — `common/waf.py`

Six case-insensitive, word-boundary rules (`\bor\b`, `union`, `select`, `drop`, `--`,
`1=1`). It deliberately does **not** block the apostrophe — real usernames contain
one (`O'Brien`) — which is the FP trade-off axis 5 measures.

| Blade | Result | Evidence |
|---|---|---|
| **Coverage** (axis 3) | **17/22 = 77%** blocked on a 22-payload SQLi corpus (incl. all 4 Part-A payloads) | [`waf_coverage.csv`](defend/results/waf_coverage.csv) |
| **Bypass** (axis 4) — *mandatory* | **5/5** candidates pass the WAF **and** leak the canary | [`waf_bypasses.csv`](defend/results/waf_bypasses.csv) |
| **False positives** (axis 5) — *mandatory* | **6/21 = 28.6%** benign blocked | [`waf_false_positives.csv`](defend/results/waf_false_positives.csv) |

Coverage is measured on **22 distinct payloads** (a cross-section of the SQLi class —
tautologies, UNION, stacked DROP, order-by, blind/time-based), per the Control
Scorecard's axis-3 rule of *"≥ 20 distinct payloads"* ([`control-scorecard.md`](../../../resources/control-scorecard.md)).
The **5 it misses** are honest and telling: `admin' #` (alt comment), `admin' || '1'='1`
(`||` operator), quoted `AND '1'='1'`, `LIKE '%` and `GLOB '*` — the exact shapes the
axis-4 bypasses below exploit. A blocklist blocks only the shapes it imagined.

The five bypasses all use the `"<user> :: <pw>"` trick: a `/*` block comment opened in
the `user` field closes in the `pw` field, swallowing the `' AND pw = '` the app
concatenates between them — leaving a tautology. None contains a word the rules name:
quoted `'1'='1'`, `GLOB '*`, inequality `2>1`, quoted `'a'='a'`, and `LIKE '%`. Each is
**oracle-confirmed** (WAF passed **and** `do_login` returned the canary).

The FP rate is reported **per field**, because the number depends on the denominator:
**login_username 0/9** (word boundaries save `select_committee_chair`,
`unionrep_delegate`), **search_or_name 6/12** (free text like *"select the union
option on the benefits form"* and *"my order number is 1=1-2024"* trips it). 28.6% is
the honest blended number over the two guarded fields.

### B2 — Positive model (parameterization) — the real fix

`login_fixed` binds `user`/`pw` as values (`?` placeholders) against the app's **own**
DB (`vulnweb_app.make_db`). Re-running **all** Part-A SQLi payloads **and** the five
B1 bypasses (9 hostile inputs):

| Sink | Canary leaked |
|---|---|
| Vulnerable `do_login` (string-formatted) | **9/9** |
| Parameterized `login_fixed` (bound params) | **0/9** |

A legitimate login (`admin`/`s3cr3t`) **still works** under the fix, so this is a real
fix, not "reject everything." Evidence: [`positive_fix.csv`](defend/results/positive_fix.csv).

**Guarantee (axis 2), as a conditional:** *for any string value of `user`/`pw`, the
parameterized query's structure is fixed at parse time, so no input can change which
rows are selected — provided every code path that reaches this table uses bound
parameters (one remaining string-built query would void it).* The WAF cannot state
this: it enumerates known-bad, so a sixth bypass always exists (we found five in
minutes). **Headline:** the blocklist **raised cost** (bypassable 5/5 + 28.6% noise);
parameterization **gave a guarantee** (0/9, for any input).

### Control Scorecard — the WAF (negative model) vs. parameterization (positive model)

The course rubric ([`control-scorecard.md`](../../../resources/control-scorecard.md)) asks every duel report to fill all
eight axes. Scored on **evidence quality, not whether the control won**:

| # | Axis | WAF blocklist (negative) | Parameterization (positive) | Evidence |
|---|---|---|---|---|
| 1 | **Threat model** | unauthenticated remote attacker, no creds, controls the login/search inputs | same adversary | Part A |
| 2 | **Guarantee** | *none* — blocks only patterns the ruleset already names; no claim about the next payload | *for any input string, query structure is fixed at parse time* — **provided every path to the table binds parameters** | `defend_summary.json` |
| 3 | **Coverage** | **17/22 (77%)** of a distinct SQLi corpus | n/a — not pattern-based; 0/9 hostile inputs alter the query | [`waf_coverage.csv`](defend/results/waf_coverage.csv), [`positive_fix.csv`](defend/results/positive_fix.csv) |
| 4 | **Bypass** | **found: 5/5** (block-comment + GLOB/LIKE/inequality/quoted-tautology) leak the canary | none found: 0/9 payloads + bypasses leak | [`waf_bypasses.csv`](defend/results/waf_bypasses.csv) |
| 5 | **FP cost** | **28.6%** of benign blocked (search_or_name 6/12; login_username 0/9) | **0%** — legit `admin`/`s3cr3t` login still works | [`waf_false_positives.csv`](defend/results/waf_false_positives.csv) |
| 6 | **Op cost** | one regex pass per request (µs, stdlib `re`); tuning is unbounded — each bypass needs a new rule | one-line code change; no runtime infra, no tuning | `common/waf.py`, `common/positive_fix.py` |
| 7 | **Observability** | `first_rule_hit` returns the rule that fired → loggable per request | the DB driver rejects nothing — nothing to alert on; failure would be a *missed* parameterization in code review | `common/waf.py` |
| 8 | **Failure mode** | **fails open**: any input the rules don't name reaches the vulnerable sink | **fails closed by construction** at this sink; the only failure is a *different* code path that string-builds a query (out of scope here) | `honesty.md` §2 |

---

## Part C — The duel: LLM vs. scanner

Both arms point at the same `vulnweb_app.py`, scored against the hand-built
`ground_truth.json`. Each tool is scored on the **canonical class set**
{`sqli`, `xss`, `cmdi`, `broken-access-control`} the ground truth can adjudicate;
real-but-unscored findings (plaintext passwords, missing rate limiting, …) are
reported separately rather than counted as false positives (see `honesty.md` §2).

| Tool | TP | FP | FN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| `regex-naive` (line-oriented) | 2 | 0 | 1 | **100%** | 67% | 0.80 |
| `semgrep` (real, our rules) | 3 | 1 | 0 | 75% | **100%** | 0.86 |
| `bandit` (real) | 1 | 0 | 2 | **100%** | 33% | 0.50 |
| LLM run 1 (cold review †) | 3 | 0 | 0 | **100%** | **100%** | **1.00** |
| LLM run 2 (cold review †) | 3 | 1 | 0 | 75% | **100%** | 0.86 |
| LLM run 3 (cold review †) | 3 | 0 | 0 | **100%** | **100%** | **1.00** |
| LLM mock (small-model baseline) | 3 | 2 | 0 | 60% | **100%** | 0.75 |

> **† What the LLM arm actually is — read with care.** The grading sandbox has no
> Ollama model and no API key, so `seclab.LLM`'s only working backend is `manual`
> (paste prompts into a chat interface). **The assistant that helped build this
> homework served as that backend**, producing three reviews of `vulnweb_app.py`,
> each in a *separate isolated context that saw only the source* (no shared memory,
> no sight of the ground truth). **This is not an API sampled 3× at temperature > 0**,
> and the two 100%/100% runs are **not** evidence that "an LLM reviewer is reliable" —
> a capable assistant doing a careful cold read of a 90-line file is close to best
> case. We keep the small-model `llm_mock` row precisely as the honest contrast (it
> hallucinates BAC *every* run and flags the fixed `/safe`). Full disclosure:
> [`AI_LOG.md`](AI_LOG.md) Entry 4.

Evidence: [`duel_scores.csv`](duel/results/duel_scores.csv), [`nondeterminism.csv`](duel/results/nondeterminism.csv), [`duel_report.json`](duel/results/duel_report.json).

1. **Scanner's worst miss:** `regex-naive` misses `sqli @ do_login` because the query
   spans two physical lines (verb on one, `{user}` on the next). **But our `semgrep`
   multiline rule catches it** — so the miss is a **rule-design choice, not a law of
   scanners** (the point Avalos's earlier draft overstated, now corrected in the same
   submission). `bandit`'s data-flow B608 also catches that SQLi but misses the
   XSS/cmdi shapes — a different precision/recall trade.
2. **LLM's best hallucination:** `broken-access-control @ do_post` — confidently
   asserted in an app with **zero** auth/session/role code (ground truth:
   `not_present`). The small-model mock makes the same BAC claim *every* run and also
   flags the fixed `/safe` endpoint.
3. **Non-determinism (axis 9), 3 cold-review runs:** recall is **stable at 100%** (all three
   real sinks every run); raw finding counts vary **11 / 14 / 15**; the only scored
   finding that changes is the **BAC hallucination**, present in **1 of 3** runs
   (mean pairwise Jaccard 0.83). What moves between runs is the *noise*, not the real
   findings — and a strong model's noise is smaller and less consistent than the small
   model's, which is itself the lesson about which model you trust.
4. **Access control:** no real A01 exists; no scanner reports it; the LLM cold-review invents
   it in 1/3 runs and the mock in every run — a hallucination, not a finding.

---

## Part D — Honesty

See [`honesty.md`](honesty.md): seven self-critiques — ground-truth independence, the
scoring-scope decision, effort asymmetry, the self-authored Medium filter and WAF,
benign-corpus realism, our least-reproducible finding (XSS), and the cmdi simulation.

## AI use

See [`AI_LOG.md`](AI_LOG.md).

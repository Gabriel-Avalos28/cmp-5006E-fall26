---
marp: true
theme: default
paginate: true
header: 'CMP-5006 · Week 13 · AI for Defense, Measured'
---

<!--
Week 13. Beats: triage task (5) · precision/recall vs accuracy (7) · automation
paradox (8) · non-determinism (3) · where AI helps (2). Checkpoint 2.
Lesson plan: ../../weeks/week-13.md
-->

# AI for Defense, Measured

## Did it actually help?

**CMP-5006** · Week 13 — *Checkpoint 2*

---

# Accuracy lies at low base rates

SOC triage: most alerts are false alarms. A model that says "benign" to everything
is ~90% accurate and catches **zero** attacks.

> Precision and recall against **honest ground truth** are the only real numbers.
> And building that ground truth is itself hard — "whatever the old tool flagged"
> rigs the comparison.

---

# The scores look close — hold that thought

```
tool         precision  recall   F1
rule@0.7        87%       59%    0.70   ← precise, quiet
LLM             44%       95%    0.60   ← high recall, noisy
```

On these numbers you might pick the LLM: 95% recall sounds great.

Recall is half the story — the half everyone quotes.

---

# ⚠️ The automation paradox

Analysts have **finite capacity** — a shift reviews maybe 25 alerts. A tool that
flags 48 to catch one more real attack **floods the queue**; real alerts sit
unreviewed and are missed anyway.

```
                 flagged   caught (capacity = 25)
precise rule       15         13     ← within capacity
"90% recall" LLM   48         12     ← OVER capacity, catches FEWER
flag everything   200          3
```

> A tool that was right 90% of the time made the team **worse** — being right
> produced more work than the team could do.

<!--
8 min. The metric was never raw recall — it was real attacks caught per analyst-
hour, and PRECISION drives that. This is the week's headline.
-->

---

# ⚠️ And it's non-deterministic (axis 9)

```
LLM triage, 3 runs:  recall 95% / 86% / 91%,  precision 44% / 40% / 45%
```

A classical rule gives the identical answer every time. Any LLM number from a
**single run is not a measurement.** Report mean and spread.

---

# Where AI *does* help defenders

Not nowhere — where its profile fits and a **human is cheaply in the loop**:

| Task | Why it fits | The catch |
|---|---|---|
| summarizing an incident | speed; human verifies | invents details |
| explaining an unfamiliar log | breadth | hallucinates fields |
| first-pass code review (wk6) | recall over many files | high FP → human filters |
| drafting a detection rule | fast start | test before trusting |

> A high-recall, low-precision **assistant** — great with a human filter,
> dangerous driving a volume decision automatically.

---

# Studio

1. **Score both tools** with `seclab.scan` — precision, recall, F1, and the
   specific FPs and misses. Not accuracy.
2. **Non-determinism** — run the LLM ≥ 5×; report mean and spread.
3. **The automation paradox** — pick a capacity; report *attacks caught under
   capacity*, not raw recall. The headline result.
4. Scorecard: does AI help *this* task? Guarantee (usually "none, an assistant"),
   FP cost in analyst-hours, where you would and wouldn't deploy it.

> **Checkpoint 2 (weeks 8–13) is this week.**

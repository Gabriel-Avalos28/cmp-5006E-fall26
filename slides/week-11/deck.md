---
marp: true
theme: default
paginate: true
header: 'CMP-5006 · Week 11 · Privacy: PII, Anonymity & DP'
---

<!--
Week 11. Beats: re-identification by linkage (6) · k-anonymity + homogeneity (7)
· differential privacy (8) · membership inference (4). Duel 3 due.
Lesson plan: ../../weeks/week-11.md
-->

# Privacy: PII, Anonymity & Differential Privacy

## The one control with a *statable* guarantee

**CMP-5006** · Week 11 — *Duel 3 due*

---

# "Anonymized" almost never means anonymous

Drop the name, keep ZIP + birth year + sex. Sweeney: that triple uniquely
identifies **~87% of Americans.**

```
released medical record  ⋈  public voter roll   (on zip, yob, sex)
      75% uniquely identified  →  linked to a NAME + diagnosis
```

> Nobody hacked anything. The release was policy-compliant. The quasi-identifiers
> that felt harmless are a fingerprint (week 1: name the assumption).

---

# k-anonymity — hide in a crowd of k

Generalize (ZIP → prefix, year → decade) until every quasi-identifier group has
≥ k people. No single record can be singled out.

```
after generalization: every group has k ≥ 3
```

...so identity is protected. But there's a gap.

---

# ⚠️ k-anonymity protects *identity*, not the *secret*

If a whole group shares one sensitive value, you learn it without singling anyone
out — the **homogeneity attack**.

```
group (021xx, 1960s), k=5:  every member's diagnosis = "hiv"
→ attacker knows the victim is in the group → learns "hiv" with certainty
```

> k-anonymity: **no guarantee** about what the attacker learns. It raises cost.
> (l-diversity patches this; it too has gaps.)

---

# Differential privacy — a guarantee you can state

Answer queries with calibrated noise so the output is nearly identical whether or
not any one person is in the data.

# for budget ε: any one person changes any output by at most a factor of e^ε

| ε | mean error | privacy |
|---|---|---|
| 0.1 | ±10 | very strong |
| 1.0 | ±1 | moderate |
| 5.0 | ±0.2 | weak |

> A **statable guarantee** (axis 2), against **any** side information — the first
> since week 10. The cost is accuracy, and the budget **composes** across queries.

<!--
8 min. Contrast EXPLICITLY with week 9 (no guarantee) and week 10 (guarantee in
code). DP's guarantee is literally a number.
-->

---

# Membership inference — privacy attacks reach *models*

An overfit model is more confident (lower loss) on data it memorized. Threshold
that and you infer whether a record was in **training**.

```
loss-threshold attack:  80% accuracy   (random guess = 50%)
```

> If the training set is "patients with diabetes," membership **is** the sensitive
> fact. Defense: DP training (DP-SGD) — the same ε guarantee, applied to the model.

---

# Scorecard — two kinds of privacy defense

| Defense | Guarantee? | Failure |
|---|---|---|
| drop the name | **none** | linkage |
| k-anonymity | **none** — identity only | homogeneity |
| l-diversity | weak | skew / closeness |
| **differential privacy** | **yes — e^ε, any side info** | accuracy; budget composes |

> Most controls **raise cost**; a rare few give a **statable guarantee**. Week 9:
> none. Week 10: one (least privilege). Week 11: the strongest — **a number.**

---

# Studio

1. **Re-identify** — link the dataset to a voter roll; % uniquely identified; name
   one.
2. **k-anonymize, then break it** — homogeneity attack that learns a secret.
3. **Differential privacy** — noise a query at ≥ 4 ε values; plot accuracy vs. ε;
   write the guarantee each ε buys; show composition eroding it.
4. **Membership inference** — beat the 50% baseline.
5. Scorecard each: *guarantee* or *raises cost*, with your numbers.

> **Duel 3 (AI red team) is due; capstone peer-red-team assignments are made.**

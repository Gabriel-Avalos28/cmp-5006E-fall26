---
marp: true
theme: default
paginate: true
header: 'CMP-5006 · Week 12 · AI Governance & the LOPDP'
---

<!--
Week 12. Beats: LOPDP principles + automated-decision right (7) · proxy
discrimination (7) · memorization as legal harm (7) · DPIA (4).
Lesson plan: ../../weeks/week-12.md
-->

# AI Governance & the LOPDP

## A right you can't measure is a right you can't defend

**CMP-5006** · Week 12

---

# The LOPDP, mapped to measurable harms

Ecuador's Ley Orgánica de Protección de Datos Personales:

| Provision | The technical harm behind it |
|---|---|
| right vs. **solely-automated decisions** | a model deciding with no human review |
| **proportionality** / non-discrimination | an automated valuation with disparate impact |
| **purpose limitation** + subject rights | a model that memorizes & re-emits personal data |

> This week turns each legal clause into a **measurement**. The studio writes the
> DPIA; the notebook produces the evidence it must cite.

---

# ⚠️ "We don't use the protected attribute" is not a defense

A loan model with a **facially neutral** rule (income > threshold) on a feature
correlated with a protected group:

```
approval rate — group A: 73%,  group B: 39%
impact ratio (B/A): 0.53   →  FAILS the four-fifths (80%) rule
```

The rule never mentions the group. It discriminates anyway, through a **proxy**.

> A DPIA claiming fairness because "we dropped the sensitive column" is *wrong* —
> and you can prove it in five lines.

<!--
7 min. This is the mind-changer: engineers believe "don't collect race = fair."
The four-fifths rule on a proxy feature shows otherwise.
-->

---

# ⚠️ Model memorization — the PHI leak, made real

A model trained on clinic docs (incl. one PHI record) reconstructs it from a short
prompt:

```
prompt "patient maria" → "...ssn 171 55 0199 diagnosis hiv positive"
```

Under the LOPDP: unlawful disclosure of sensitive data + violated subject rights.

- **Detect**: scan for long *deterministic* spans (high recall, needs review).
- **Bound**: DP training (DP-SGD, week 11) — a guarantee, not a filter.

---

# The DPIA — every claim backed by a number

A Data Protection Impact Assessment ties it together. The week's standard:

> **Every risk claim is backed by a measurement.**

An unmeasured DPIA is week 9's system prompt — a *request*, not a control. "Our
model is fair / private / safe" earns nothing without the number.

---

# Scorecard — governance controls

| Control | Guarantee? |
|---|---|
| "removed the protected attribute" | **none** — proxies re-encode it |
| memorization span-scan | detection only (high recall, review) |
| **human-in-the-loop review** | **procedural guarantee** (the LOPDP right) |
| **DP training (DP-SGD)** | **statable ε bound** (week 11) |
| a *measured* DPIA | only as good as its evidence |

> The LOPDP names the rights; **measurement makes them enforceable.**

---

# Studio

1. **Memorization** — reproduce the PHI extraction; run the span-scan; name the
   LOPDP right violated; explain how DP-SGD bounds it.
2. **Disparate impact** — compute the impact ratio; show dropping the attribute
   doesn't fix it; propose and measure a real control.
3. **Write the DPIA** — automated-decision analysis + memorization risk +
   mitigations, each backed by a number. The graded artifact.
4. Scorecard each mitigation: guarantee / procedural guarantee / detection only.

> Keep the LOPDP framing — it's what makes this course specific to *its* students.

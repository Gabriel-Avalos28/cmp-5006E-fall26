---
marp: true
theme: default
paginate: true
header: 'CMP-5006 · Week 14 · AI-Enabled Offense & Wrap-Up'
---

<!--
Week 14. Beats: detect structure not content (9) · symmetric vuln discovery (5)
· course synthesis (11). 14B = capstone demos. Strictest ethics rules.
Lesson plan: ../../weeks/week-14.md
-->

# AI-Enabled Offense & Course Synthesis

## The deliverable is always the defense

**CMP-5006** · Week 14

---

# AI didn't invent new attacks — it cheapened old ones

Flawless phishing at scale, cloned voices, automated vuln discovery. The attack
*classes* are old; AI removed the **cost** and the **tells**.

> ⚠️ We study offense to build defense. No attack content is generated in this
> course — we work from labeled samples to build **detectors**.

---

# ⚠️ Grammar-based phishing filters are dead

For 20 years, "poor grammar" was a top phishing signal. An LLM writes flawless
prose for free.

```
                     recall: OLD phish   recall: AI phish
grammar detector          100%                 0%    ← collapses
behavioral detector       100%                98%    ← holds
```

The behavioral detector keys on **structure** — sender spoofing, lookalike
domains — the *mechanics* AI didn't touch.

> Stop detecting what AI **fixed** (bad grammar); detect what it **can't change**
> (the mechanics).

---

# The general principle for AI-era defense

| Signal you key on | Survives AI? |
|---|---|
| attacker sloppiness (typos, grammar) | ❌ AI removes it |
| content plausibility | ❌ that's what AI optimizes |
| **structure / provenance** (sender auth, signing, behavior) | ✅ |

> Deepfake voice → verify via a **channel** (call back a known number), not "does
> it sound right." AI malware → detect **behavior**, not signatures. Move the
> detector from content to structure.

---

# Automated vuln discovery is symmetric

AI-assisted fuzzing helps attackers *and* defenders find bugs first (weeks 6, 13).
The defense isn't out-fuzzing — it's the boring infrastructure:

> **SBOM** (know what to check, wk8) + **pinning** (can't swap the fix, wk8) +
> **least privilege** (bound the blast radius, wk10).

AI changes discovery *speed*, not defense *shape*.

---

# ⚠️ Course synthesis — which controls gave a guarantee?

Tally every control by scorecard axis 2:

```
classical controls (weeks ≤ 8):  6/8 give a statable guarantee
AI-era controls    (weeks ≥ 9):  2/6
```

And the two AI-era exceptions — **least privilege** and **differential privacy** —
enforce the guarantee **outside the model**, in code or math, never in a prompt.

> When a system depends on AI, ask **where the guarantee is enforced.** If it's
> "in the model's cooperation," you have a **cost**, not a **control.**

<!--
11 min. The emotional close. Reopen the week-1 poll — the operative word was always
"unbreakable." Almost nothing is; the skill is telling guarantee from cost.
-->

---

# Session 14B — Capstone demos & red-team showcase

Entirely demos. Each team: their hardened AI-integrated app, the attacks they and
their peer red team landed, before/after Control Scorecards.

> The bar: not "our app is secure" but *"here is what we measured — this attack
> still works at this rate, this control gives this guarantee under this condition,
> and here is where we might be wrong."*

⚠️ **Strictest ethics rules**: no live targets, no real people, no functional
malware. Every offensive technique is shown *with its defense*.

---

# Finish this sentence

> ## "When a system depends on AI, the security question to ask first is ___."

Fourteen weeks of evidence. You built the skill: tell a **guarantee** (with its
condition) from a **cost** (with its bypass), and demand evidence for which one
you're being sold.

That skill is the course. Everything else was practice.

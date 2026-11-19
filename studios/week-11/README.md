# Week 11 Studio — Privacy: Re-identification, k-Anonymity & a *Statable* Guarantee

**Companion to** [`../../weeks/week-11.md`](../../weeks/week-11.md) — Session 11B.
**Time budget:** Recap 5 · Lab 45 · Demos 20 · Debrief 10 (75 min total).
**Deliverables:** all provided tests pass, and a filled Control Scorecard row for
each privacy defense — with your numbers as evidence.

> **Recap (5 min).** *k-anonymity hid every identity and still leaked the diagnosis.
> How?*

Every week you have sorted controls into two piles: those that **raise the
attacker's cost** (with a bypass) and the rare few that give a **guarantee you can
state**. This studio is the cleanest example of both, side by side. "Anonymizing" by
dropping the name and k-anonymity are cost-raisers — you will re-identify a named
patient and leak a diagnosis anyway. **Differential privacy** is the peak of the
course's positive thread: a guarantee stated as a *number* (e^ε), against **any**
side information. Telling the two kinds apart is the whole grade.

Pure Python, stdlib only — no `seclab` import, no lab target, no Docker (a
`seclab`-adjacent week). **All data is synthetic; there is no real personal data in
this studio — that is the week's ethics rule, not an accident.**

## Files in this folder

| File | Purpose | You edit it? |
|---|---|---|
| [`privacy.py`](privacy.py) | Given: the engine — `quasi_id`, `generalize`, `laplace_noise`, `epsilon_guarantee`, `membership_guess`, verbatim from the notebook | no |
| [`data.py`](data.py) | Given: loads the synthetic data + the notebook's expected values; defines the constructed `HOMOGENEOUS_GROUP` | no |
| [`medical.json`](medical.json) | Given: the 'anonymized' released medical table (120 rows, no names) | no |
| [`voter_roll.json`](voter_roll.json) | Given: the public voter roll (name + quasi-identifiers) | no |
| [`model.json`](model.json) | Given: the **simulated model's** per-record losses (200 rows) — the membership-inference target | no |
| [`starter.py`](starter.py) | **Tasks 1–4** — the four attacks/measurements | yes |
| [`test_privacy.py`](test_privacy.py) | Provided tests, incl. the two paired guarantee tests | no |
| [`_generate_data.py`](_generate_data.py) | Regenerates the three JSON files from the seed (only if you rotate it) | no |

> **Why the data is in files.** The synthetic datasets and the "simulated model"
> used to live only inside the Session-A notebook. They are now concrete artifacts
> (`medical.json`, `voter_roll.json`, `model.json`), regenerated bit-for-bit from the
> notebook's seed by `_generate_data.py`, so every pair attacks identical, real files.

## Task 1 — Re-identify by linkage (10 min)

Implement `reidentify(released, voter_roll)` in `starter.py`. Link the 'anonymized'
medical table to the public voter roll on the quasi-identifier **{zip, yob, sex}**.
Report the fraction of records **unique** on the quasi-id (~**75%** here) and
**name one victim**. The oracle is a successful **name link** — not "this row looks
unique". Nobody hacked anything; the release was policy-compliant. This is week 1's
move — *name the assumption ("these fields aren't identifying") — false.*

## Task 2 — k-anonymize, then break it (12 min)

`generalize` (given) coarsens the quasi-id (3-digit ZIP, 20-year band) until every
group has ≥ k members, so **no row is unique** — identity is hidden in a crowd.
Then implement `homogeneity_attack(group)`: on the provided `HOMOGENEOUS_GROUP`
(k = 5, nobody unique, all HIV), learn the diagnosis **without singling anyone
out**. State exactly what k-anonymity **did** protect (identity) and **did not**
(the attribute). This is why *l*-diversity exists — and it, too, has gaps.

## Task 3 — Differential privacy (13 min)

Implement `noisy_count(true_count, eps, rng)` — a count query has sensitivity 1, so
the Laplace scale is 1/ε. Measure mean |error| at ε ∈ {0.1, 0.5, 1, 5}; you will see
it track **1/ε** (±10 at ε=0.1, ±0.2 at ε=5). For two ε values, **write the
guarantee sentence** ε buys (below). Then, for the demo: answer *ten* queries on the
same budget and show the privacy degrade — **ε composes**, every query spends budget.

> *For privacy budget ε, no adversary — with ANY side information — can determine
> whether a given individual is in the dataset with advantage beyond a factor of
> e^ε.*

## Task 4 — Membership inference (10 min)

Implement `membership_inference(probe, thresholds)` on the simulated model in
`model.json`. An overfit model is more confident (lower loss) on data it memorized;
threshold that confidence to guess membership. Report accuracy above the **50%**
baseline (~**80%** here). State what a positive result means for a real patient: if
the training set is "patients with diabetes," **membership *is* the sensitive fact.**
The defense is DP again (DP-SGD), bounding one record's influence by the same ε.

## Task 5 — Control Scorecard (the whole grade)

For each defense, fill one scorecard row — does it give a **guarantee** (axis 2) or
only **raise cost**? Back it with your numbers. This distinction is the point.

| Defense | Guarantee (axis 2)? | Its failure / condition | Your evidence |
|---|---|---|---|
| Drop the name | **none** | linkage on quasi-identifiers | Task 1: 75% re-identified, a named victim |
| k-anonymity | **none** — protects identity, not the attribute | homogeneity / background knowledge | Task 2: k=5 group leaks `hiv` |
| l-diversity | weak | skewness, semantic closeness | a diverse group does not leak (Task 2) |
| **Differential privacy** | **yes — e^ε bound, against any side information** | accuracy cost (mean \|error\| = 1/ε); budget composes | Task 3: ±10 at ε=0.1 → ±0.2 at ε=5 |

> The through-line of the course: most controls **raise cost**; a rare few give a
> **statable guarantee**. Week 9 had none (prompt-injection filters). Week 10 had one
> (least privilege, enforced in code). Week 11 has the strongest: **differential
> privacy, a guarantee stated as a number.** "We think this is safer" vs. "here is
> what we can prove."

The full rubric (all 8 axes, scoring, honesty clause) lives in
[`../../resources/control-scorecard.md`](../../resources/control-scorecard.md).

## Run the tests

```bash
python3 starter.py        # smoke test: prints re-id %, the leak, the DP curve, MI accuracy
python3 test_privacy.py   # all four must pass
```

The two paired tests are the point of the week and are pinned **against each other**:

- `test_dp_gives_a_statable_epsilon_guarantee` — DP's error is a bound you can
  **write down** (mean |error| = 1/ε: ±10 → ±0.2) and the adversary's advantage is
  capped at e^ε. A guarantee is a number.
- `test_kanonymity_only_raises_cost_and_leaks` — k-anonymity hides identity (k=5, no
  unique row) yet the homogeneity attack **learns the diagnosis**. Watching a
  guarantee *that was never made* fail is how you know the difference.

## Demos (20 min)

- Prioritize a pair whose homogeneity attack used realistic **background knowledge**,
  and a pair who showed **composition** eroding the DP guarantee across ten queries —
  the subtlety most people miss.
- Solicit: *did anyone's DP answer come out negative or absurd?* Noise can do that at
  small ε — a live moment on why the accuracy cost is real, and stated.

## Debrief (10 min)

- "Anonymized" is a property of your data **plus all auxiliary data**, so syntactic
  anonymization keeps failing to linkage.
- k-anonymity / l-diversity **raise cost, no guarantee** — they protect identity, not
  the attribute.
- ⚠️ **Differential privacy is the one control here with a *statable guarantee*** —
  e^ε, against any side information — at a measured accuracy cost, and the budget
  **composes** across queries.
- Privacy attacks reach **models** via membership inference; DP-SGD is the same
  guarantee applied to training.

## Links

- Session 11A notebook — [`../../notebooks/week-11-privacy.ipynb`](../../notebooks/week-11-privacy.ipynb)
- Control Scorecard — [`../../resources/control-scorecard.md`](../../resources/control-scorecard.md)
- Ethics & scope — [`../../resources/ethics-and-scope.md`](../../resources/ethics-and-scope.md)
- **Duel 3 (AI Application Red Team) is DUE this week** — [`../../projects/duel-3-ai-redteam.md`](../../projects/duel-3-ai-redteam.md). It red-teams the `vuln-llm` app (weeks 9–10), not this privacy material — but bring the same measurement rigor you brought to re-identifying a dataset here. Capstone peer-red-team assignments are made this week too.
- Reading — Narayanan & Shmatikov (2008), *Robust De-anonymization of Large Sparse Datasets* (the Netflix Prize paper)

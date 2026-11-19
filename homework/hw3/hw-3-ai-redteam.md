# Homework 3 — AI Application Red Team

**15 % · due end of week 12**

Red-team a vulnerable AI-integrated application: **prompt injection** (direct and
indirect), **RAG poisoning**, and **tool abuse** — every finding oracle-confirmed
and **reliability-measured**, because a model-based system is non-deterministic.
Then **contain** what you cannot prevent, and state exactly what your containment
guarantees. 

> **The bar:** not "we made it leak" but *"here is the leak confirmed by a canary,
> here is its reliability over 5 runs, here is why no filter fixes it, and here is
> the least-privilege boundary that contains it — enforced in code, not a prompt."*

---

## Learning objectives assessed

1. Execute direct **and** indirect prompt injection, confirmed by a canary oracle.
2. **Measure reliability** (scorecard axis 9) — a model attack that works 3/5 times
   is a different finding from one that works 5/5.
3. Show that model-level defenses (filters, system prompts) **raise cost without a
   guarantee**, and demonstrate a bypass.
4. **Contain** the damage with least privilege and state the guarantee it gives —
   and articulate the **coverage-vs-containment** distinction.

---

## The targets

Two apps, both the `vuln-llm` architecture from weeks 9–10:

- **T1 — the course `vuln-llm`** (`python -m seclab.targets --up vuln-llm`): the
  known target, for the core attack set.

All targets run locally, with a local model or the deterministic mock. See ethics.

---

## Part A — Attack 

Against **T1**, land and confirm **all four**

| # | Attack | Confirm it by | Surface |
|---|---|---|---|
| 1 | **Direct prompt injection** | canary in the reply (`seclab.attack`) | `/chat` |
| 2 | **Indirect injection** | a poisoned local page makes the agent obey it | `/summarize` |
| 3 | **RAG exfiltration + poisoning** | pull a `private-*` doc; trigger a poisoned doc | `/rag` |
| 4 | **Confused-deputy tool abuse** | secret exfiltrated via the agent's tools (`sent` list) | `/agent` |

For each finding:

- The payload and the **canary-confirmed** effect (not "it looked like it leaked").
- ⚠️ **Reliability over ≥ 5 trials.** Report `k/5`. On the deterministic mock you
  cannot measure this — say so and *reason* about what a real model would do.
- For indirect injection: **name who the victim is vs. who the attacker is** (the
  trust boundary crossed).

---

## Part B — Defend and bypass

### B1 — Model-level defense (raises cost, no guarantee)
1. Turn on an output filter / delimiter defense (T1's `/defense` levels).
2. Re-run your attacks; report the block rate.
3. ⚠️ **Bypass it (axis 4):** make the model spell/encode the secret past the
   literal filter. Report the bypass reliability.
4. State honestly: **can you write an axis-2 guarantee for this defense?** (No —
   explain why "no bypass-proof filter exists" is the honest answer.)

### B2 — Architectural containment (a real guarantee)
5. Apply **least privilege**: narrow the agent's tool allow-list (T1's `/policy`)
   to the minimum a benign task needs.
6. Re-run the confused-deputy attack; show `sent = []` — the exfil is contained.
7. State the guarantee (axis 2): *"the agent cannot invoke a tool outside its
   allow-list, regardless of what the model is convinced to do — enforced in the
   dispatcher, not a prompt."*
8. ⚠️ **The headline result:** report **coverage vs. containment** — the injection
   still fires **every time** (0 % coverage), yet the damage is contained **every
   time** (100 % containment). Explain why that's a *stronger* result than a filter.

---

## Part C — Honesty section

Titled **"Where our red team might be unfair."** Address ≥ 3:

- Which findings are reliability-limited (worked k/5) and might not reproduce for
  the grader?
- Did the deterministic mock let you *demonstrate* logic you couldn't *measure*?
  Say where.
- Is your least-privilege policy so narrow it breaks a legitimate task (an axis-5
  false-positive cost on the containment)?

---

## Logistics

- **Pairs.** Submit by pull request to `/homework/hw3/<lastname>/`.
- **PR review:** Submit a pull request
- **`AI_LOG.md`** required. **Ethics:** local targets only; the peer app runs in
  your sandbox. See [`../resources/ethics-and-scope.md`](../resources/ethics-and-scope.md).


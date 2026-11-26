---
marp: true
theme: default
paginate: true
header: 'CMP-5006 · Week 8 · Systems, Auth & Supply Chain'
---

<!--
Week 8. Beats: dependency confusion (7) · SBOM/transitive risk (6) · auth token
forgery (8) · unifying pattern (4). Checkpoint 1 + Duel 2 due.
Lesson plan: ../../weeks/week-08.md
-->

# Systems, Auth & Supply Chain

## Trust the artifact, not the name

**CMP-5006** · Week 8
---

# ⚠️ Dependency confusion

Your build installs `acme-auth` (internal). The resolver checks **both** your
registry and public PyPI, and picks the **highest version**.

```
internal: acme-auth 1.4.2      public: acme-auth 9.9.9  ← attacker squatted the name
resolver picks → PUBLIC 9.9.9
```

Your internal name, the attacker's code, installed by your own CI. Birsan (2021)
breached Apple, Microsoft, dozens more this way.

<!--
7 min. Nobody typo'd anything. The resolver trusted the NAME and picked by version.
-->

---

# The fix — pin the artifact

Don't resolve by name+version. Pin against a **lockfile**: exact hash + vetted
source.

```
acme-auth → {version: 1.4.2, sha256: aa11bb.., source: internal}

attacker's public pkg → REJECTED (source mismatch)
```

> The pin makes the name irrelevant: only the artifact you approved installs.
> `pip --require-hashes`, `package-lock.json`, scoped internal registries.

---

# SBOM — you can't pin what you can't see

Pinning needs an inventory, including **transitive** deps you never chose.

```
our-app → acme-auth → pyjwt
                    → xz-utils   ← the 2024 backdoor lived HERE, 2 levels deep
```

When a CVE drops, "are we affected?" is a **query**, not a week of grep.

> `xz-utils` is transitive — nobody chose it, everybody had it. You can't pin,
> patch, or panic about what you can't enumerate.

---

# ⚠️ Auth: the alg=none token forgery

A JWT carries a header saying which algorithm signed it. Many verifiers **trust
that header** — including `"none"` (no signature).

```
forge:  header {alg: none}  .  payload {role: admin}  .  (empty sig)
verifier trusts the header → logs you in as admin, no key needed
```

## Fix — pin the algorithm server-side

```python
if header["alg"] != EXPECTED_ALG: reject()   # never trust the token's self-description
```

<!--
8 min. Also mention weak-HMAC-secret brute force and hardcoded secrets (#1 in
leaked repos). Same disease as dependency confusion.
-->

---

# One pattern behind all three

| Attack | trusted **name** | substituted **artifact** | the **pin** |
|---|---|---|---|
| Dependency confusion | package name | attacker's package | lockfile + hash |
| Transitive backdoor | "just a dependency" | compromised upstream | SBOM + provenance |
| alg=none JWT | the token's header | an unsigned token | server-side alg pin |

> Software trusts **names**; attackers put a different **artifact** behind them.
> The fix is monotonous and it works: pin the artifact, verify under a key **you**
> control. (Returns in wk10: least privilege for model tools.)

---

# Studio — and two assessments

1. **Dependency confusion** — naive resolver, public wins; defeat with a pin.
2. **SBOM** — build the transitive list; answer "affected by CVE-X?".
3. **alg=none forgery** — forge an admin token; fix with algorithm pinning.
   (Bonus: brute-force a weak HMAC secret.)
4. Scorecard each: trusted name, substituted artifact, the pin that closes it.


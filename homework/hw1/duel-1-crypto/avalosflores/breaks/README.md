# Part A — Breaks (all six deployments)

We broke **all six** targets in `duel1_targets.py` (3 in Tier 1, 3 in Tier 2; the minimum was four with
one per tier). Each script uses only the public functions of the targets (never `_PAD_KEY`, `_CTR_KEY`,
`_MAC_SECRET`, `_TIMING_SECRET` or the plaintexts in the source), prints the recovered artifact, and
ends with a confirmation. The exact output of our run is saved in `output/`.

```bash
cd breaks
python3 break1_reused_pad.py        # ...and so on for break2..break5
python3 break6_timing.py            # ~1.5 min (statistical, see reliability table)
```

`duel1_targets.py` in this folder is an **unmodified copy** of the starter file (sha256
`f463099722a7…ab8c35`), included only so the scripts run standalone.

| # | Deployment | Tier | Recovered artifact | Confirmed by | Reliability |
|---|---|---|---|---|---|
| 1 | `reused_pad` | 1 | TARGET = `the launch authorization code will be delivered by separate courier ok` | pad recovered from the *other* 3 messages decrypts the target; 69/69 pad bytes cross-checked by ≥ 2 messages | deterministic; 1 char (`k`) is a context guess |
| 2 | `ecb_store` | 1 | `carl`'s role block = `alic`'s role block → `carl` is also `admn`; `bob0`/`dave` share a role but not a department | identical ciphertext blocks printed side by side | deterministic; needs one external anchor for the *value* of a field |
| 3 | `ctr_log` | 1 | `2025-03-01 12:09 user=admin action=export result=success from=10.0.0.?` | keystream from our own known entry also decrypts entry 0 into a sane log line | deterministic; last byte (1 digit) not recoverable |
| 4 | `token_mac` | 2 | forged `data = user=alice&role=user\x00\x00\x00&role=admin`, `tag = 4024164909` | `verify_token(data, tag) → True`, secret never used | deterministic |
| 5 | `keygen_fleet` | 2 | shared prime `p = 14723961130838400979`; private keys `d` of device0 and device2 | `decrypt(encrypt(m)) == m` and a forged signature verifies under the public key | deterministic |
| 6 | `timing_compare` | 2 | secret = `83fabf35` (bytes 131, 250, 191, 53) | `timing_compare(secret) → True` | **statistical**: see below |

---

## 1 · `reused_pad` — two-time (n-time) pad
- **Assumption:** the designer assumed a pad stays unbreakable however many messages it encrypts, i.e. that "one-time" is a property of the algorithm and not a rule about never reusing the key.
- **Break:** `C_i ⊕ C_j = P_i ⊕ P_j` – the pad cancels. Crib-dragging in rounds: two ciphertexts start with identical bytes → identical plaintext start (`the `); a statistical column vote (letters+space) gives noisy text that suggests words; we use those words as cribs and check that the *other* messages turn into English. The target is never guessed: it is read out with a pad recovered from msg0–msg2.
- **Primitive or misuse?** **Misuse.** A one-time pad is perfectly secret (Shannon) *provided* the pad is uniformly random, as long as the message and used once. The primitive is fine; the deployment violated the "used once" condition.
- **Reliability:** deterministic (same output on every run). Weak spots: the cribs of rounds 1–3 come from reading the noisy statistical output, i.e. human judgment (with only 4 messages the vote alone does not give clean text), and the last character of the target is covered by no other message, so `k` comes from context (`… courier ok`).

## 2 · `ecb_store` — ECB structure leakage
- **Assumption:** the designer assumed that encrypting each block separately hides the record, ignoring that equal plaintext blocks give equal ciphertext blocks.
- **Break:** with 4-byte blocks the records `name:role:dept` split as `name | :rol | e:de | pt` (last block zero-padded), so fields straddle block borders but repeated content still repeats. `rec0` and `rec2` share blocks 1–3 (same role *and* department), `rec1`/`rec3` share only block 1 (same role, different department), and block 0 (the name) is unique. One piece of outside knowledge (alice is an admin) then gives carl's role, with no key.
- **Primitive or misuse?** **Misuse.** ECB is a *mode*, not a broken block cipher: it is deterministic by construction, so it is not semantically secure on structured data. The block cipher itself is never attacked.
- **Reliability:** deterministic. Limitation: ciphertext equality reveals *which* records share a field, not its value; the value needs an anchor (known record) or a chosen-plaintext oracle, which this target does not provide.

## 3 · `ctr_log` — CTR nonce reuse
- **Assumption:** the designer assumed CTR confidentiality does not depend on using a fresh nonce for every entry.
- **Break:** same key+nonce → same keystream. Stage A (ciphertext only): `C0 ⊕ C1` is zero over the shared header and differs only in user, result, minute and IP digit; a name-list crib over the user field has a unique consistent triple `alice / bob00 / admin`. Stage B (known plaintext): the attacker, `bob00`, knows his own failed-login entry, so `KS = C1 ⊕ P1` decrypts every other entry.
- **Primitive or misuse?** **Misuse.** CTR is secure *provided (key, nonce) never repeats*; here it repeats for every entry. (Same failure as break 1: a stream cipher turned into a pad reused many times.)
- **Reliability:** deterministic. Stage B assumes the attacker knows one plaintext (own login) – realistic but an assumption. The final byte of the target exists only in the longest entry, so it stays unknown.

## 4 · `token_mac` — `H(secret ‖ data)` length extension
- **Assumption:** the designer assumed that without the secret nobody can compute the tag of any message other than the issued one, i.e. that `H(secret‖data)` behaves like a MAC.
- **Break:** the tag *is* the hash's internal state; we restart the hash from it (`iv = tag`) and append `&role=admin` after the hash's own padding. We do not trust the "secret length is 9" hint: trying lengths 1–32 against `verify_token`, the server accepts 1, 5, 9, … 29 and all give the **same** forgery, because this toy hash's padding depends only on length mod 4.
- **Primitive or misuse?** **Misuse of a hash as a MAC.** The hash itself keeps its properties; what fails is the construction. The fix is HMAC (or a real MAC / AEAD).
- **Reliability:** deterministic. Caveat: the target's hash is a 32-bit toy MD function, not SHA-256, and it also requires the server to read the *last* `role=` (see `honesty.md`).

## 5 · `keygen_fleet` — shared RSA prime (batch-GCD)
- **Assumption:** the designer assumed each device draws its primes from enough randomness at first boot, so two devices never produce the same prime.
- **Break:** `gcd(n0, n2) = 14723961130838400979`; the batch-GCD formula `gcd(nᵢ, (∏n mod nᵢ²)/nᵢ)` flags exactly devices 0 and 2. From `p` we get `q = n/p`, `φ`, `d`, and prove it by decrypting and by signing. Devices 1 and 3 are not affected by this attack.
- **Primitive or misuse?** **Misuse** (a deployment/entropy failure). RSA is not broken; the *key generation* violated the assumption that primes are independent random draws. This is the 2012 "Mining your Ps and Qs" scenario (Heninger et al.).
- **Reliability:** deterministic and instant (4 keys). With millions of keys one uses the product/remainder-tree version for speed.

## 6 · `timing_compare` — early-exit comparison
- **Assumption:** the designer assumed an attacker only sees the boolean result, not how long the comparison took.
- **Break:** time grows ≈ 72 µs per correct leading byte (0.4 → 72 → 144 → 216 µs). Per position we time all 256 candidate bytes (interleaved), keep the highest score and extend the known prefix: 4 × 256 guesses instead of 2³².
- **Primitive or misuse?** **Misuse** (implementation side channel). No cryptographic primitive is attacked; the fix is a constant-time comparison (`hmac.compare_digest`).
- **Reliability — how many trials the signal needed.** The attack is repeated 20× for each N (N = timings per candidate; one attack = 4 × 256 × N timed calls). Our saved run (`output/break6_timing.txt`):

| N | calls / attack | success with **median** | success with **minimum** |
|---|---|---|---|
| 1 | 1 024 | 0/20 (0 %) | 0/20 (0 %) |
| 2 | 2 048 | 1/20 (5 %) | 7/20 (35 %) |
| 3 | 3 072 | 5/20 (25 %) | 14/20 (70 %) |
| 5 | 5 120 | 12/20 (60 %) | 19/20 (95 %) |
| 8 | 8 192 | 18/20 (90 %) | 20/20 (100 %) |

  The signal is large, yet single-sample attacks fail: scheduler/CPU noise only *adds* time, so with few samples some wrong candidate looks slow by chance. The **minimum** is the better statistic because a wrong candidate only looks slow if *all* its N samples were hit. **We needed N ≈ 8 (≈ 8 000 timed calls) for ≥ 95–100 % reliability**, and the script runs the final recovery with 2× the smallest N that had 20/20. Numbers vary from run to run (another run of the same script gave 20/20 at N = 5 for the minimum; the median results move by ±15 points), so we report them as "about", not as constants.

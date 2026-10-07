# Where our breaks or design might be unfair

(And what we did not test. The task asks for at least three points; we list the ones we think matter most,
grouped by the four questions in the assignment. We would rather lose a point of "confidence" than hide a hole.)

---

## 1. Did a break rely on an assumption the deployment didn't actually make?

**Yes, in several places.**

1. **Break 4 (`token_mac`): we did not break what the assignment describes.** The task text says
   `SHA256(secret‖data)`, but the target uses a 32-bit toy Merkle–Damgård function (`_md_hash`) with zero-padding
   to a multiple of 4 and no length field. The *idea* (the tag is the internal state, so you can continue from it)
   transfers to SHA-256, but the exact steps we wrote do not: real SHA-256 pads with `0x80`, zeros and the 64-bit
   message length, so we would need the exact secret length (about 64 guesses against the oracle), not just
   `length mod 4`. We did **not** implement a real SHA-256 length extension. Also, "role escalation" assumes the
   server's parser takes the **last** `role=` value; the deployment never says that, and a parser that rejects
   duplicate keys or `\x00` bytes would stop the forged token even though the tag verifies.
2. **Break 3 (`ctr_log`), stage B, assumes a known plaintext.** We gave the attacker his own log line (`bob00`'s
   failed login). That is realistic, but it is an assumption we added: the deployment does not grant it. Without
   it (stage A, ciphertext only) we only got the user name triple `alice/bob00/admin` and the *pair*
   {success, failure}, not the whole target entry.
3. **Break 1 (`reused_pad`) used a hint and some human judgment.** The docstring tells us "all are English", and
   the cribs of rounds 1–3 came from reading noisy statistical output. A fully automatic ciphertext-only attack on
   only 4 messages would probably leave errors; we did not measure how often. The last character is a guess.
4. **Break 2 (`ecb_store`) does not recover any plaintext.** It recovers *equalities*; the value of a field needs
   an outside anchor ("alice is admin"). Calling that a "break" is fair for ECB's leakage, but weaker than the
   other five.
5. **Break 5 (`keygen_fleet`): the toy moduli are only 128 bits.** They could be factored directly in seconds, so the
   shared prime is not what makes this deployment breakable in practice; it is what makes the *scenario* realistic.
   With 2048-bit moduli the shared prime would be the only way in, but we did not test that size.
6. **Break 6 (`timing_compare`) is far easier than a real timing attack.** The target loops 4000 times per matching
   byte "to amplify the signal", i.e. about 72 µs per byte instead of the ~1 ns of a real `memcmp`; attacker and victim
   are in the same Python process (no network jitter); and we disabled the garbage collector while measuring.
   Our reliability numbers describe *this setting* only; a remote attacker would need orders of magnitude more
   trials, and we did not test that.
7. **We read the source.** Every flaw in `duel1_targets.py` is labelled `# FLAW`. Our scripts never use the keys or the
   plaintexts, but we did not have to *discover* the flaws, which a real assessor would. The breaks show the flaws are
   exploitable, not that we could have found them blind.
8. The assignment text and the starter module disagree on names (`verify_login`, `ctr_log(entries)`, `ecb_store(record)`
   vs `timing_compare`, `ctr_log_entries()`, `ecb_store_records()`) and on the submission path (`/homework/hw1/…` vs
   `/projects/duel-1-crypto/…`). We followed the starter module and its README.

## 2. Is SECS conditional on something we hand-waved?

**Yes.** The guarantees in `secs-design.md` §4 list their conditions, but some of those conditions hide the hard part:

* **The Notary is a single point of trust and failure.** We needed it (we believe fair exchange without a third party can't be done deterministically, but we did not verify that
  result against a primary source), and we only *assumed* it is honest, available and has a resilient channel to both parties. We did not
  design how N's own key is protected or rotated, how its clock is kept honest, or what happens if N is bought by one
  party. Attempts 12 and 13 in the scorecard table are "not blocked" for exactly this reason.
* **"Deemed delivery" is a legal convention, not cryptography.** NRR of receipt in the strong sense (the human got
  and read the final copy) cannot be proven by any signature; we defined receipt so that it is provable
  ("made available + k logged attempts"). Whether a court accepts that definition is outside the design.
* **How do the parties learn the CA root and each other's identities?** We wrote "pinned root CA", "out-of-band
  enrolment". That is exactly the "secure channel for key distribution" this question warns about: we assumed it.
* **What-you-see-is-what-you-sign.** A signature on `h` proves the device signed `h`. If the device is compromised
  it can show `C` and sign `C′` (attempt 14). We listed it as a condition, not a mitigation.
* **Entropy at key generation.** Break 5 is about this, and our answer ("refuse to generate keys before the pool is
  initialised, use an HSM") reduces the risk but does not prove the keys are good.
* **No formal verification.** The protocol was reasoned about on paper by the people who designed it. Protocols often
  have subtle flaws that only a tool (Tamarin, ProVerif) or an outside reviewer finds. The 10 "blocked" attempts are
  arguments, not tests, and 15 attempts is below the scorecard's ≥ 20 threshold for coverage.
* **Unequal effort between attacker and defender.** The design and the list of 15 attacks were written by the same
  people in the same working session, with the design already in mind, so the attacker side is weaker than a
  genuinely hostile reviewer. We also did not try to make the attacks hurt: no attempt was run.

## 3. Which breaks are we least confident are reproducible, and why?

* **Break 6 (timing)** is the least reproducible: it is statistical and depends on the CPU. We ran the whole study
  three times in a shared 2-core cloud container (the first run predates the minimum score, so it only has median numbers). With the *median* score the success rate at N = 5 was 60 %, 55 % and 60 %,
  and at N = 8 it was 95 %, 80 % and 90 %; with the *minimum* score N = 5 gave 100 % and 95 %, N = 8 gave 100 %.
  A different laptop, a loaded machine, frequency scaling or a different Python build can move these numbers.
  The script prints its own table so a grader can see the numbers of *their* machine; the claim we stand behind is
  "the minimum score works reliably from about N = 5–8", not any specific percentage.
* **Break 1** depends on a human-judgment step (which cribs to try). It is deterministic once the cribs are chosen,
  but another reader may need more rounds.
* The other four (2, 3, 4, 5) are deterministic functions of fixed public data (the module uses a fixed seed), and
  their scripts print the same artifact on every run.

## 4. Does SECS trade one goal for another?

* **Confidentiality vs. auditability / evidence.** N never sees the contract text, which protects confidentiality
  but means N can only attest to the hash. In a dispute the parties must produce `C` and the salt `r` themselves.
  If both lose `r` (or one refuses to reveal), the notarization proves *that something* was signed, not *what*.
  Also, N still learns metadata: who contracted with whom, and when.
* **Forward secrecy vs. later review.** Session keys are erased, so nobody, not even the parties, can decrypt
  the recorded traffic afterwards. That is the point, but it means each party has to store `C` at rest, and
  we scoped that storage out ("confidentiality in transit" only).
* **Fairness vs. decentralisation/availability.** To get fair NRR we added a TTP. We traded a peer-to-peer
  protocol for a dependency: if N is down, no contract can be formed (it fails closed, which is safe but not available).
* **A free option for Bob.** Alice signs `S` in step 1; until `valid_until`, Bob can hold `σ_A` and decide later whether
  to sign and deposit, i.e. he can wait and see how the market moves. Alice has no way, in our design, to withdraw
  an offer before expiry (she would need a revocation message to N, which we did not specify and which would create
  race conditions). A shorter `valid_until` reduces the problem but costs usability (false rejections).

## What we did not test (and would try with more time)

* A real SHA-256 length extension (break 4) and a real 2048-bit shared-prime scan (break 5).
* A timing attack over a network, or against a constant-time comparison to confirm that the fix really closes the leak.
* An implementation of SECS and a run of the 15 paper attacks against it, plus a benign corpus (to measure the
  false-positive rate: legitimate contracts rejected by expiry, clock skew or revocation) and a benchmark of the
  operational cost. Those cells of the scorecard say "not measured" because they are.
* A formal-methods check of the protocol, and a review by someone who did not design it.
* AI-specific axes (non-determinism, "would a larger model change the result?") do not apply: no model is under test.

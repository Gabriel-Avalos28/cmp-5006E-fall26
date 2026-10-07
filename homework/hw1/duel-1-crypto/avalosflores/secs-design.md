# Part B — SECS: Secure Electronic Contract Signing

Design document (no implementation). Alice = provider, Bob = client. Goals: non-repudiation of
**origin** (NRO), non-repudiation of **receipt** (NRR), **integrity**, **confidentiality** of the
terms in transit.

**One-paragraph summary.** Alice and Bob authenticate each other with certificates, agree on fresh
session keys with an ephemeral Diffie-Hellman exchange that is *signed*, and exchange the contract inside
an AEAD channel. Each of them signs the same canonical statement `S` (which contains the hash of the
contract, not the contract). A **Notary N** (a trusted third party) checks both signatures, timestamps
them and publishes the executed contract to both parties; both then sign a receipt for it. The contract
becomes binding at one well-defined moment, N's notarization, and only if both signatures exist; an offer
that is not notarized before `valid_until` simply expires.
N is there because, as far as we know from the fair-exchange literature, two mutually distrusting parties
cannot exchange signatures fairly with a deterministic protocol and no third party. We could not check a primary
source for that result while writing this, so we treat it as an **assumption behind the design** (why N exists),
not as a cited fact; it shows up as a condition in section 4.

---

## 1. Threat model (scorecard axis 1)

| Actor | What it can do | Trusted for | NOT trusted for |
|---|---|---|---|
| **Network attacker** (Dolev-Yao) | read, drop, replay, reorder, modify and inject any message between A, B and N | nothing | everything |
| **Alice / Bob** (each is the other's potential adversary) | deny having signed or received, sign something different from what they showed, abort mid-protocol, replay old messages | their own device and key (each trusts *itself*) | honesty towards the other party |
| **Notary N** | sees all deposits, timestamps, keeps the log | ordering/time, publishing evidence, delivery log | seeing the contract text, or binding a party (it cannot forge σ_A or σ_B) |
| **CA** | issues certificates Cert_A, Cert_B, Cert_N; publishes revocations | binding a public key to an identity | being online in the protocol; it is a root of trust, so if it mis-issues, G1 fails (stated below) |

Attacker has **no** access to the private signing keys, the session keys or the memory of the endpoints
unless a condition below says "key not compromised". Compute is bounded: no break of Curve25519, SHA-256 or AES.

---

## 2. Primitives and why each one (weeks 2–5)

| Need | Primitive | Why this one | Where it comes from in the course |
|---|---|---|---|
| Non-repudiation of origin | **Ed25519 signatures** (RFC 8032) | Non-repudiation needs a key that *only the signer* holds. A MAC (shared key) can never give it: either side could have produced the tag. Ed25519 uses **deterministic nonces**, so a bad RNG at signing time cannot leak the key. | weeks 4–5: signatures, key misuse |
| Bind signature to the contract | **SHA-256** over a canonical encoding, `h = SHA-256(r ‖ C)` with a random 128-bit salt `r` | Collision resistance means a signature on `h` binds exactly one contract. The salt makes `h` hiding, so N can hold `h` without being able to guess a low-entropy contract by dictionary. The hash is **never** used as a MAC. | week 3: hashing |
| Key agreement | **X25519**, ephemeral on both sides, authenticated by a signature over the transcript | Forward secrecy: leaking a long-term signing key later does not reveal past sessions. An *unsigned* DH is man-in-the-middle-able, so each side signs the transcript that contains both DH shares and both nonces. | weeks 4–5: DH, authenticated key exchange |
| Key derivation | **HKDF-SHA256** (HMAC-based) with transcript hash as context | Separate keys per direction (`K_AB`, `K_BA`), bound to this handshake. | week 3: HMAC vs `H(k‖m)` |
| Confidentiality + integrity in transit | **AES-256-GCM** (AEAD), nonce = 32-bit per-direction prefix ‖ 64-bit message counter, AAD = transcript hash ‖ cid ‖ seq | AEAD gives confidentiality and tag-based integrity in one primitive. No ECB, no hand-built stream cipher. Counter nonces (not random) and fresh keys per session make reuse impossible by construction. | weeks 2–3: modes, CTR/ECB misuse |
| Identity | **X.509 PKI**: pinned root CA, chain validation, validity period, `keyUsage = digitalSignature`, revocation (OCSP/CRL) | A signature proves "the holder of this key", the certificate says *who* the holder is. | week 5: PKI |
| Fairness, time, delivery | **Notary / TTP N**: signs `EXECUTED` with a trusted timestamp and keeps an append-only, hash-chained log | Needed for fairness (impossibility without a TTP), for a trusted time (a signature is judged against revocation *as of the time it was made*), and for delivery evidence. | week 5: protocols, TTPs |
| Randomness | OS CSPRNG (`getrandom`), refuse to generate keys until the entropy pool is initialised; HSM/secure element for long-term keys | All keys, salts and ids come from here. | duel break #5 |
| Comparison | constant-time compare for every tag/digest/token; uniform error responses | No timing or error oracle. | duel break #6 |
| Encoding | one canonical, length-prefixed binary encoding with **domain-separation labels** (`SECS1/CONTRACT`, `SECS1/RECEIPT`, `SECS1/HS-A`, …) | A signature made in one context can't be replayed in another; signer and verifier hash the same bytes. | week 1: unstated assumptions |

Key lifetimes: signing keys 1–2 years (in an HSM or OS keystore), DH keys one session, session keys
erased at session end.

---

## 3. Protocol and message flow

### 3.1 The signed statement

Both parties sign **the same** byte string

`S = enc( "SECS1/CONTRACT", cid, h, id_A, id_B, id_N, valid_until, h_terms )`

* `cid`: 128-bit random contract id chosen by Alice. `h = SHA-256(r ‖ C)`. `valid_until`: expiry.
* `h_terms`: hash of the fixed "SECS terms" text, which says two things everyone consents to by signing:
  **(i)** *the contract is binding only when N publishes `EXECUTED` for it before `valid_until`*, and
  **(ii)** *a party is deemed to have received the final copy once N has made it available to that party's
  mailbox and logged k delivery attempts, Δ = 72 h after the notarization*.
* `σ_A = Sig_A(S)`, `σ_B = Sig_B(S)`.

### 3.2 Diagram with trust boundaries

```
 TRUST ZONE A             UNTRUSTED NETWORK (Dolev-Yao attacker)             TRUST ZONE B
 (Alice trusts herself)       reads, drops, replays, modifies, injects anything        (Bob trusts himself)

 ┌─────────────────────┐                                         ┌─────────────────────┐
 │   ALICE (provider)  │                                         │     BOB (client)    │
 │ sk_A in HSM/keystore│                                         │ sk_B in HSM/keystore│
 └──────────┬──────────┘                                         └──────────┬──────────┘
            │                                                               │
            │─ H1  g^x, n_A ───────────────────────────────────────────────►│
            │◄─ H2  g^y, n_B, Cert_B, Sig_B(transcript) ────────────────────│
            │─ H3  Cert_A, Sig_A(transcript) ──────────────────────────────►│
            │  K_AB, K_BA = HKDF(g^xy, transcript)   signed DH => no MITM   │
            │─ 1  AEAD{ C, r, cid, S, σ_A } ───────────────────────────────►│  Bob checks h = H(r‖C)
            │◄─ 2  AEAD{ σ_B } ─────────────────────────────────────────────│  then signs σ_B
            │                                                               │
════════════╪═════ trust boundary: A and B -> Notary N (mutual TLS 1.3) ════╪══════
            │ 3  Deposit(S, σ_A, σ_B), no text of C; either party may       │
            ▼                                                               ▼
      ┌───────────────────────────────────────────────────────────────────────────┐
      │ TRUST ZONE N: NOTARY / TTP (trusted for time, order, delivery log only)   │
      │ cannot forge σ_A or σ_B; never sees the contract text C                   │
      │ checks certs + signatures + revocation + fresh cid + t < valid_until      │
      │ E = Sig_N("EXECUTED", H(S), H(σ_A‖σ_B), t, log-head) -> hash-chained log  │
      └───────────────────────────────────────────────────────────────────────────┘

 4  N -> A, B : F_N = (S, σ_A, σ_B, E), the final signed copy (same bytes for both)
 5  A, B -> N : receipts ρ_P = Sig_P("RECEIPT", H(F_N))
 6  N -> A, B : Z = Sig_N("COMPLETE", H(F_N), ρ_A, ρ_B | DEEMED-DELIVERED)

 CA (offline root): issues Cert_A, Cert_B, Cert_N, publishes revocations; not in the protocol run
```

Trust boundaries: A↔network, B↔network, N↔network (every arrow crossing a boundary is authenticated
and, between A and B, also encrypted); **A↔B is a boundary of mutual distrust** (each is the other's
possible repudiator); **N is trusted for time/order/delivery but not for the contract text**; the CA is
trusted only for the key↔identity binding.

### 3.3 Messages

| # | Direction | Content | Protection | Purpose |
|---|---|---|---|---|
| H1–H3 | A↔B | DH shares, nonces, certificates, signatures over the transcript | signatures | authenticated, forward-secret key exchange; fixed suite `SECS1`, so no negotiation to downgrade |
| 1 | A→B | `C, r, cid, S, σ_A` | AEAD `K_AB` | offer; **NRO(A)**; confidentiality |
| 2 | B→A | `σ_B` (only after Bob re-computed `h = H(r‖C)` from the text he read and compared it to `S` in constant time) | AEAD `K_BA` | acceptance; **NRO(B)** |
| 3 | A or B→N | `S, σ_A, σ_B` (no `C`) | mutual TLS 1.3 with Cert_N | formation of the contract; trusted time |
| 4 | N→A, B | `F_N = (S, σ_A, σ_B, E)` = the **final signed copy** | `Sig_N`, TLS | both get the same final copy |
| 5 | A, B→N | `ρ_P = Sig_P("RECEIPT", H(F_N))` | signature | **NRR** |
| 6 | N→A, B | `Z` completion certificate | `Sig_N` | evidence package |

Rules that make the flow fair:
* Once Bob has sent σ_B he holds **both** signatures, so he can deposit at once; Alice cannot stop the
  contract from coming into being by going silent (she signed in step 1). If Bob never sends σ_B, nothing
  is binding and the offer expires at `valid_until`. (Side effect: until then Bob holds a free option; see `honesty.md`.)
* Nobody is bound before `E` exists (clause (i)); **fails closed** if N is down or the offer expires.
* After `E`, refusing to acknowledge does not help: after Δ N logs `DEEMED-DELIVERED` (clause (ii)).
* Any verification failure ⇒ abort the session and log the reason code; no partial state is acted on.

### 3.4 Evidence package for a dispute
`C`, `r` (revealed by the parties to the judge), `S`, `σ_A`, `σ_B`, `Cert_A`, `Cert_B`, `E`, `ρ_A`/`ρ_B` or
the deemed-delivery record, the revocation status of both certificates *as of the time in `E`*.
Anyone can re-check: `H(r‖C)` equals `h` in `S`; both signatures verify on `S`; the certs chain to the CA
and were valid and unrevoked at `t`; N's signature on `E` verifies.

---

## 4. The four guarantees as scorecard axis-2 statements

Each is a **conditional**. "Not claimed" lists what we deliberately do *not* promise.

### G1 — Non-repudiation of origin
> Neither Alice nor Bob can deny having signed the contract statement `S` (and therefore the contract
> text that hashes to `h`), **provided** (a) the signer's private key was not compromised before the
> time `t` in N's `EXECUTED` statement; (b) the CA did not mis-issue the certificate that binds that
> key to that identity, and the certificate was valid and unrevoked at `t`; (c) Ed25519 is unforgeable
> and SHA-256 is collision-resistant; (d) N's timestamp `t` is honest; and (e) the signer's device showed
> the text it actually signed (what-you-see-is-what-you-sign).

Not claimed: that the signer *read* or *understood* `C` (a signature on `h` proves they signed `h`);
anything if a key was stolen before `t` (cryptography cannot distinguish the thief from the owner).

### G2 — Non-repudiation of receipt of the final signed copy
> Neither party can deny having received the final signed copy `F_N`, **provided** (a) N is honest and
> available: it signs only true statements, does not collude with one party, and keeps its log;
> (b) the receipt key of the party was not compromised, or, when no receipt arrives, the party accepted the
> deemed-delivery clause (ii) by signing `S` and N's delivery attempts were really made to the party's
> registered mailbox; and (c) the signature and hash assumptions of G1 hold.

Not claimed: that a human *read* `F_N`; delivery if the party's registered mailbox is unreachable
(it is then deemed delivered by contract, which is a legal convention, not a cryptographic fact);
fairness without N (we believe it can't be had deterministically, see summary).

### G3 — Integrity
> Any change to the contract after signing, or to any protocol message in transit, is detected,
> **provided** (a) SHA-256 is second-preimage/collision resistant and the signature scheme is unforgeable;
> (b) the AEAD tag is always checked before any plaintext is used, and **AES-GCM's nonce is never reused
> under the same key** (reuse would let an attacker forge tags and learn plaintext relationships —
> ours are per-direction counters under keys that are fresh for every session, and a restart means a new
> handshake, never a reset counter); and (c) signer and verifier hash the *same* canonical bytes.

Not claimed: prevention (only detection); that the *original* contract was what a party intended.

### G4 — Confidentiality of the terms in transit
> The text `C` is hidden from a network attacker (passive or active) between Alice and Bob,
> **provided** (a) the DH exchange is authenticated (certificates valid, signatures verify), so there
> is no man in the middle; (b) the endpoints and the session keys are not compromised during the session;
> (c) ephemeral DH keys and the salt `r` come from a CSPRNG; (d) AES-GCM nonces are not reused (same
> condition as G3); and (e) X25519 and AES-256 are not broken. Long-term key compromise *later* does not
> reveal this session (forward secrecy).

Not claimed: confidentiality **from the other party** (Bob can leak `C`); from N beyond `h`+metadata (N sees
who contracted with whom, when, and the size of the signatures; it cannot read `C` because it never receives
it and `h` is salted); against traffic analysis (message lengths and timing).

---

## 5. Which of the six broken deployments' mistakes does SECS avoid, and how?

| # | Mistake in the deployment | How SECS avoids it | Condition / what is left |
|---|---|---|---|
| 1 `reused_pad` — same pad under many messages | No hand-made pads or stream constructions. Confidentiality is an AEAD whose key is **fresh per session** and per direction; the (key, nonce) pair is never repeated. | the counter is never reset under a live key; a crash ⇒ new handshake, new keys |
| 2 `ecb_store` — equal blocks ⇒ equal ciphertext | No ECB. AES-GCM with a unique nonce hides repeated content; the same contract text sent twice yields different ciphertext. At N the digest is salted (`r`), so equal contracts give different `h`. | metadata (lengths, who/when) still leaks |
| 3 `ctr_log` — CTR nonce reused | GCM is CTR-based, so the same rule applies: nonce = per-direction prefix ‖ 64-bit counter, incremented *before* each encryption, never random, never persisted across sessions. (Hardening option: AES-GCM-SIV or XChaCha20-Poly1305, which tolerate misuse.) | depends on correct counter handling in the implementation (G3(b)) |
| 4 `token_mac` — `H(secret‖data)` | The design never uses a bare hash as a MAC. In-transit integrity is AEAD; evidence is a **signature** (a MAC could never be evidence); key derivation uses HMAC (HKDF). Length extension does not apply to `Sig(S)` because there is no secret prefix and `S` has a length-prefixed canonical form. | none beyond library correctness |
| 5 `keygen_fleet` — shared RSA prime from low entropy | Keys come from the OS CSPRNG on a device that refuses to generate keys before its entropy pool is initialised; Ed25519 has no "shared prime" structure; its signing nonce is deterministic (RFC 8032), so even a weak RNG at signing time does not leak the key. The CA rejects a certificate request whose public key already exists in its database. | a device whose RNG is broken *at key generation* still produces a weak key; the entropy check is the mitigation, not a proof |
| 6 `timing_compare` — early-exit comparison | All comparisons of tags, digests (`h`), receipt hashes and session/capability tokens are constant-time; AEAD/signature libraries do their own constant-time checks; N answers all failed verifications with one uniform error and rate-limits. | the platform's constant-time implementation must really be constant-time |

General lesson applied from week 1: every guarantee in section 4 states its assumption instead of hiding it.

---

## 6. Control Scorecard

"Before" = the same SECS goals built on the **six flawed deployments as given**. "After" = this design.
Everything under *After* is **design-level**: nothing was implemented or run, which is why several
"Evidence" cells say so.

| Axis | Before | After control | Evidence |
|---|---|---|---|
| Threat model | network attacker able to read public artifacts, no credentials | **Dolev-Yao attacker + malicious counterparty + honest-but-curious Notary**; endpoints, CA assumed uncompromised | §1 |
| Guarantee | none stated ("it's encrypted") | four **conditional** guarantees G1–G4, each with named conditions and non-claims | §4 |
| Coverage | **0/6** deployments resisted: all six broken | all **6/6** mistake classes addressed *by argument*; **15 paper attack attempts: 10 blocked, 5 not blocked** (table below). **0 executed against an implementation** | `breaks/output/*.txt` (before), §5 and table below (after) |
| **Bypass** | **6 working bypasses** (the breaks) | no running bypass attempted. Paper attempts found 5 residual paths: stolen key before `t`, Notary collusion, Notary outage, malware at the signing device, CA mis-issuance | table below; `breaks/README.md` |
| FP cost | n/a (nothing was blocked) | **not measured.** Legitimate signings could be rejected by: expired offer, clock skew, expired/revoked cert, N outage. No benign corpus was run | — |
| Op cost | — | **not measured.** Per contract: ~3 signatures, ~3 verifications, one X25519 exchange per session, one TLS session to N: small next to network round-trips (by design, not by benchmark). Real cost is operational: running a CA, revocation and a Notary with an on-call owner and key backups | — |
| Observability | none | N's append-only hash-chained log (every `EXECUTED`, receipt, deemed delivery); each party logs every verification failure with a reason code and `cid` (never keys or plaintext); alerts on duplicate `cid`, failed signature, missed receipt deadline. Parties keep `E` to detect log rewrites | §3.2, §3.4 |
| Failure mode | **fails open / silently**: forged tokens accepted, plaintext recovered, wrong keys accepted | designed to **fail closed**: verification failure ⇒ abort, nothing binding; N down ⇒ no contract. **Fails open** only if a key is stolen and revocation is not yet published (it *silently degrades* until someone watches the revocation list) | §3.3, table below |

### Attack attempts on the design (paper, not executed)

| # | Attempt | Result | Why |
|---|---|---|---|
| 1 | MITM at the handshake (swap DH shares) | blocked | signatures cover both shares and both nonces |
| 2 | Replay an old offer/signed pair in a new session | blocked | random `cid`, `valid_until`, N rejects duplicate `cid`, session nonces |
| 3 | Counterparty shows text `C` but signed hash is of `C′` | blocked | Bob recomputes `H(r‖C)` and compares to `S` before signing |
| 4 | Reuse a signature from another context (e.g. a receipt as an offer) | blocked | domain-separation label inside every signed structure |
| 5 | Reflection: send A's message back to A | blocked | per-direction keys; roles inside the signed data |
| 6 | Bob refuses to acknowledge the final copy | blocked | deemed-delivery clause + N's log after Δ |
| 7 | Alice withholds the deposit after receiving σ_B | blocked | Bob holds both signatures and can deposit himself |
| 8 | Force AEAD nonce reuse (drop connection, make a party restart a counter) | blocked | session keys are ephemeral: restart ⇒ new handshake ⇒ new keys |
| 9 | Downgrade the cipher suite | blocked | one fixed suite, version label inside the transcript |
| 10 | Notary alone rewrites or backdates its log | blocked (detected) | hash chain; parties keep `E` and can show the fork |
| 11 | Signer claims "my key was stolen" after signing | **not blocked** | N's `t` limits the window, but a theft *before* `t` can't be disproved |
| 12 | Notary colludes with one party (backdating) | **not blocked** | explicit trust assumption (G1(d), G2(a)); mitigation: several notaries or public anchoring of the log head |
| 13 | Denial of service against N | **not blocked** | availability is not promised; the system fails closed |
| 14 | Malware on the signer's device shows `C`, signs `C′` | **not blocked** | WYSIWYS is a condition (G1(e)); mitigation: hardware signing with on-device display |
| 15 | CA mis-issues a certificate to an attacker (impersonate Bob) | **not blocked** | explicit trust assumption (G1(b)); mitigation: certificate transparency, pinning of the counterparty |

**Self-assessment on the 0–4 evidence scale** (honest, because this is a design not a tested control):
threat model 3, guarantee 3 (conditions stated, not tested), coverage 1 (argued only, 15 < 20 attempts and none run),
bypass 2 (documented attempts on paper, no execution), FP cost 0, op cost 1, observability 2, failure mode 2.
See `honesty.md` for what this does not show.

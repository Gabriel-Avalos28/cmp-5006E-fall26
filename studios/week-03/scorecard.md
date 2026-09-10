# Week 3 Studio: Control Scorecard Responses

This document contains our responses for Task 4 of the Week 3 Studio. We evaluated each cryptographic construction we covered, focusing on what guarantees they actually provide and under what specific conditions those guarantees hold (Axis 2 of the scorecard).

A key takeaway from this week's lab is that the underlying primitives (AES, SHA-256) were never broken in our tests. Every single exploit we successfully implemented was due to a **misuse of the mode or construction**, rather than a flaw in the cryptographic primitive itself.

## Constructions Evaluation Table

| Construction | Guarantee (Axis 2) | Condition for the Guarantee / Failure Mode | Classification |
|---|---|---|---|
| **ECB Mode** | Provides confidentiality for individual blocks only. | **Failure (Leaks structure):** Since it's deterministic per block, identical plaintext blocks always encrypt to identical ciphertext blocks. We saw this when we recovered the 2 distinct regions of the image. | Misuse |
| **CBC / CTR Mode** | Provides confidentiality for the entire message. | **Condition (CTR):** The `nonce` must NEVER repeat for a given key. If a nonce is reused, the keystreams cancel out (`c1 ⊕ c2 = m1 ⊕ m2`), reducing the mode to a trivial two-time pad vulnerability, as we demonstrated in Task 2. | Misuse |
| **`H(secret‖msg)` MAC** | Appears to provide authentication and message integrity. | **Failure (Length Extension Attack):** The state of a Merkle-Damgård hash is entirely exposed in its output tag. We were able to forge a valid tag for an extended message just by resuming the hash from the observed tag and adding the appropriate glue padding, without ever needing the secret key. | Misuse |
| **HMAC** | Provides strong authentication and is immune to length-extension attacks. | **Condition:** Relies strictly on the key remaining secret. By nesting the hash operations, the internal state is never fully exposed, completely preventing the length extension attack we exploited earlier. | N/A (Secure if condition holds) |

## Extra Question

**Question:** *If the CTR nonce were unique but the KEY were reused across a million messages, is CTR still safe? State the condition precisely.*

**Our Answer:**
Yes, CTR mode remains perfectly safe under these circumstances. The strict condition for CTR's security is that the **`(Key, Nonce)` pair must be unique** for every encryption operation.

Even if we reuse the exact same key for a million different messages, as long as we use a unique, never-before-seen nonce for each of those messages, the generated keystream will always be unique. Since the keystreams never overlap, the two-time pad vulnerability is completely avoided, and the confidentiality of the messages remains intact.

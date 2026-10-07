# AI_LOG.md — Homework 1 (Crypto & Protocols)

**Disclosure up front.** Keoma Quiroga, David Bucheli, and I (Gabriel Avalos) did all the reasoning, vulnerability analysis, and algorithm design for this homework. We used Claude and Gemini as technical assistants to help with Python syntax, debugging small issues in our scripts, and formatting our Markdown files. The AI did not solve the assignment for us. We provided the logic and made all design decisions, and we take full responsibility for what is submitted here.

**Data policy (rule 1).** Everything attacked here is the course's synthetic sandbox (`duel1_targets.py`). No real secrets, credentials, or personal data were pasted into the assistant.

---

## Entry 0 — Setup and decisions

**Tool:** Claude / Gemini
**What I asked:** "Help us set up the folder structure and give us templates for the markdown deliverables based on our notes."
**What I got:** The AI gave us the folder layout and markdown templates.
**What I did with it:** We organized the `bucheli/` and `avalosflores/` folders, put our scripts inside `breaks/`, and filled the markdown files with our own work.
**Did I understand it?** Yes. We understand how the assignment is structured and what goes where.

## Entry 1 — Break 1, `reused_pad` (code, crib-dragging)

**Tool:** Claude / Gemini
**What I asked:** "How can we do character frequency analysis in Python to filter noise before crib-dragging?"
**What I got:** The AI suggested doing a frequency vote per column using a hardcoded dictionary of English letter frequencies, taking `max()` over the 256 possible bytes.
**What I did with it:** We used this as a "Round 0b" in our `break1_reused_pad.py` script. It gave us noisy but readable hints (like `tee qyarterle remenue numbees`). Then we manually crib-dragged the real words until we recovered the target message: `the launch authorization code will be delivered by separate courier ok`.
**Did I understand it?** Yes. The frequency analysis was just a hint. The real break relies on the fact that `C₁⊕C₂ = P₁⊕P₂`. Since the pad is reused, XORing two ciphertexts completely removes the key. This isn't breaking the math of the one-time pad; it's exploiting the fact that the pad was used more than once, which turns it into a simple Vigenère cipher.

## Entry 2 — Break 2, `ecb_store`

**Tool:** Claude / Gemini
**What I asked:** "How to slice a hex string into 4-byte chunks in Python?"
**What I got:** A quick list comprehension using python slices.
**What I did with it:** We used it in `break2_ecb.py` to print the encrypted blocks side by side. We saw that `rec0` (alice) and `rec2` (carl) had identical blocks for the role and department.
**Did I understand it?** Yes. Even though the fields like `name:role:dept` aren't exactly 4 bytes (the name is 4, but role is 4 and a colon, etc), ECB mode encrypts identical plaintext blocks into identical ciphertext blocks. Since Alice and Carl have the exact same role and dept, their data lined up across the block boundaries in the exact same way, creating a visible pattern we could spot.

## Entry 3 — Break 3, `ctr_log`

**Tool:** Claude / Gemini
**What I asked:** "Why did our target text come out missing the last character?"
**What I got:** The AI pointed out that our target ciphertext is 70 bytes, but the `log1` entry we used as our known plaintext was only 69 bytes long.
**What I did with it:** We left the script as is, but we added a note in our honesty file about this limitation. We can only recover 69 bytes.
**Did I understand it?** Yes. In CTR mode, you are just XORing the plaintext with a keystream. If we know 69 bytes of plaintext, we can only recover 69 bytes of the keystream. That keystream can decrypt exactly 69 bytes of any other message encrypted with the same nonce. The 70th byte remains safe because we don't know the 70th byte of the keystream.

## Entry 4 — Break 4, `token_mac` (length extension) — an error caught

**Tool:** Claude / Gemini
**What I asked:** "Our script forges the token perfectly for lengths 1, 5, 9, 13... why are there multiple valid lengths instead of just one?"
**What I got:** The AI noticed that the `_md_hash` in the target file is a toy hash that pads the message to a multiple of 4 bytes.
**What I did with it:** We realized that because of this toy padding, `length mod 4` is what really matters. We updated our script output to report that accepted lengths are `≡ 1 (mod 4)`.
**Did I understand it?** Yes. The length extension works because `H(secret || data)` exposes the internal state of the Merkle-Damgård hash. We can take the hash output, use it as the IV for the next block, and append `&role=admin`. A real MAC like HMAC uses nested hashes (`H(K1 || H(K2 || data))`) to hide the internal state.

## Entry 5 — Break 5, `keygen_fleet` (batch GCD) — fact verified

**Tool:** Claude / Gemini
**What I asked:** "What is the Batch GCD formula to check if public keys share primes?"
**What I got:** The AI gave us the formula `gcd(Nᵢ, (P mod Nᵢ²)/Nᵢ)` and cited a 2012 paper "Mining your Ps and Qs".
**What I did with it:** We checked the paper to verify the fact. However, since we only had 4 devices in `break5_batch_gcd.py`, we just used Python's `math.gcd` in a nested loop to compare them pairwise. We found that device 0 and device 2 shared a prime.
**Did I understand it?** Yes. If two RSA moduli `N₀` and `N₂` share a prime `p`, `gcd(N₀, N₂)` will output `p`. Once we have `p`, we just divide `N` by `p` to get `q`. With both `p` and `q`, we can compute the private key `d`. The other devices generated unique primes, so their GCD with anyone else is just 1.

## Entry 6 — Break 6, `timing_compare` — a failure that changed the method

**Tool:** Claude / Gemini
**What I asked:** "We are doing a timing attack locally, but using the median time is failing almost half the time. What's wrong?"
**What I got:** The AI explained that OS noise (background processes, context switches) only *adds* time to the execution. Therefore, taking the minimum time across many samples is much better than the median for local attacks.
**What I did with it:** We changed `break6_timing.py` to test 256 candidates interleaved, taking both the median and the minimum over `N` rounds using `time.perf_counter_ns()`. The results clearly showed the minimum score was 100% reliable, while the median failed frequently.
**Did I understand it?** Yes. Because the target loop exits early on a bad byte, the right byte takes longer to process. But since the OS scheduler randomly adds delays, a wrong byte might look slow by pure chance. The minimum statistic works locally because the fastest a function can run is its true execution time without OS interruptions. If we were doing this over a network, latency can fluctuate both ways, so we would have to use averages or medians over much larger sample sizes instead.

## Entry 7 — SECS design (Part B) — architecture, diagram, citations

**Tool:** Claude / Gemini
**What I asked:** "Can you help me format the Mermaid sequence diagram for our SECS protocol?"
**What I got:** The AI fixed my markdown syntax so the arrows and boxes lined up correctly.
**What I did with it:** We used the fixed syntax in `secs-design.md`. The actual trust boundaries, actors, and protocol steps were our own design.
**Verification of facts I would otherwise have cited (rule 2):**
- Ed25519 deterministic nonce: Verified against RFC 8032.
- GCM nonce reuse forgery: Verified against standard NIST SP 800-38D docs.

**Did I understand it?** Yes. For instance, we didn't use a simple MAC because a MAC relies on a shared symmetric key, meaning either party could have created the tag. That means no non-repudiation. In our design, the contract only binds when the Notary stamps it, because Alice needs a trusted third party to ensure Bob can't abort the deal after getting her signature but withholding his own. 

## Entry 8 — Honesty section and README prose

**Tool:** Claude / Gemini
**What I asked:** "Check our `honesty.md` for grammar mistakes."
**What I got:** A few minor typo corrections.
**What I did with it:** We applied the fixes. All the self-critiques and weaknesses we pointed out came from our own group discussions.
**Did I understand it?** Yes. If the professor asks us what the weakest part of our SECS design is, I'd say it's the fact that we rely completely on a trusted Notary. If the Notary gets compromised, the whole system fails. Also, our design gives Bob a "free option", meaning Bob can wait and decide whether to sign or not after seeing Alice's commitment.

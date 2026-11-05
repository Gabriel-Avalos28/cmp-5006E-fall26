# Where our attack, defence, or comparison might be unfair

**Team:** Gabriel Avalos · Keoma Quiroga · David Bucheli — Homework 2

We address five points; the first four are the ones the assignment names.

### 1. Was the ground-truth set built independently of the tools we scored?

Mostly yes, but with one honest caveat. The ground truth
(`homework/hw2/duel-2-web/ground_truth.json`) was built by **reading
`vulnweb_app.py`**, not by running any scanner — the three real sinks are visible
in source and each carries a `# VULN` comment. Neither the regex scanner nor the
LLM mock contributed a single entry. **Caveat:** we did *not* build it blind — we
wrote the scanner and the mock *and* the ground truth, so we knew the scanner's
single-line rule would miss the two-line SQLi before we scored it. We did not
tune the ground truth to flatter either tool (the scanner still scores higher F1
on run 1 than the LLM), but a genuinely independent grader would have built the
truth set without having seen either tool. We flag this rather than hide it.

### 2. Did we tune one side and leave the other on defaults (effort asymmetry)?

**Yes, and this is the biggest threat to the duel's fairness.** The LLM arm is a
*mock*, not a live model we prompt-engineered. We spent real effort shaping the
WAF rules and the four bypasses (Part B), but we did **not** iterate on an LLM
prompt — we froze two canned reviews that reproduce the small-local-model
behaviour observed in the week-6 studio (high recall + a BAC hallucination). So
the duel measures *a plausible LLM*, not *the best LLM a careful analyst could
coax*. A frontier model at temperature 0 with a good prompt would very likely drop
the `do_reflect_safe` false positive and might suppress the BAC hallucination
entirely — which would flip the precision story. Our numbers should be read as
"this is how an off-the-shelf small model behaves," not "LLMs lose."

### 3. Is the benign corpus realistic, or does it dodge our rules by luck?

The benign corpus is the **provided** `benign_traffic.json` (26 inputs), not one
we curated to make our WAF look good — and we did not get to choose it, which cuts
both ways. It is realistic in that it contains attack-adjacent English
("drop table tennis", "reserve the drop table") that a broad blocklist trips on,
which is exactly why our FP rate is 7.7% and not 0%. But 26 inputs is tiny, and it
is dominated by short search/login/ping strings; a real production corpus (long
free-text comments, URLs, code snippets pasted into a form) would almost certainly
push the false-positive rate **higher**, because our `--` and `DROP TABLE` rules
are blunt. So 7.7% is a **floor**, not a representative production number.

### 4. Which Part-A finding are we least sure reproduces, and why?

The **XSS** finding. Our oracle confirms a *sound necessary condition* — the
injected `<img onerror=...>` markup survives **unescaped** in the response — but it
does **not** prove script execution, because we have no browser/DOM in the
harness. A payload that reflects unescaped is a strong signal, yet a real page
might still neutralise it via Content-Security-Policy, a sanitiser further down, or
a context where `<img onerror>` doesn't fire. SQLi (canary exfiltrated) and cmdi
(the app reports the metacharacter reached the command) are closer to end-to-end
proof; XSS is the one where "confirmed by our oracle" is furthest from "exploitable
in a real browser."

### 5. The "Medium filter" in Part A is our own stand-in.

`vuln-web` has no difficulty levels, so we wrote `attack/medium.py` to model
DVWA-Medium. We chose rules that we *knew* our planned bypasses would evade. That
is honest as a demonstration of the bypass technique, but it is not the same as
defeating a filter someone else hardened against us. The genuinely adversarial
bypass work — against a blocklist, measured on both blades — is Part B, where the
bypasses had to both pass the WAF *and* leak the canary on the real sink to count
(1 of our first 4 candidates failed that bar and was replaced only after the sink
disproved it).

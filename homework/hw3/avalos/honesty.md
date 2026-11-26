# Part C — Where our red team might be unfair

**Team:** Gabriel Avalos · Keoma Quiroga · David Bucheli
**Course:** CMP-5006E (Fall 2026) — HW3, T1 `vuln-llm`

Every number below comes from `attack/results/` and `defend/results/`. Backend for all
committed results: **`mock`** (the deterministic stand-in shipped with `vuln-llm`); we did
not run a real model for the committed results. Where we reason about a real model instead
of measuring it, we say "expected" and mean it as an untested hypothesis.

## 1. Which findings are reliability-limited, and might not reproduce for the grader?

On the mock **nothing is reliability-limited**: every row is 5/5 or 0/5
(`non-deterministic rows (0 < k < 5): 0`). That is not evidence of robustness, it is
the mock being a keyword matcher. So the useful question is which findings would
*stop* being 5/5 on a real model (`qwen2.5:1.5b`, temperature 0.7 in `call_ollama`):

| Finding | Depends on the model? | What we expect on a real model (untested) |
|---|---|---|
| Direct injection `/chat` (16/20 at 5/5) | yes, fully | would become flaky: some phrasings k/5 with 0<k<5, some 0/5. We cannot say which. |
| Indirect injection `/summarize` (4/5 pages) | yes | same; hidden-comment and `display:none` pages differ from visible text only if the model treats them differently. |
| RAG canary in answer (R01, R03, R04, R05) | yes | flaky, as above. |
| RAG private doc **retrieved** (R01, R02, R05 5/5) | **no** — keyword retriever, no model | reproduces exactly on any backend. |
| Confused deputy `/agent` (16/20 at 5/5) | **no** — `plan_tool_calls` is a regex, not the LLM, even with Ollama | reproduces exactly on any backend. |
| Filter bypass spaced/spelled/base64 (5/5) | yes | the *spaced/spelled* renderings should work often; we would expect a 1.5B model to make mistakes when asked to base64-encode a 39-character token, so a base64 "bypass" that recovers the exact secret is the one most likely to drop below 5/5. |
| Least-privilege containment (90/90) | **no** — Python dispatcher | reproduces exactly: it does not depend on what the model does. |

So the grader running our scripts on the mock will reproduce every number (we checked that
the in-process run and a run against the separately started app give byte-identical CSVs).
A grader running them against Ollama (`HW3_RESULTS_TAG=ollama`, see README) should expect
the model-dependent rows to move, and the `run_all.py` invariants about "every benign
control is 0" and "containment of every fired attempt" to hold while the 5/5 claims may not.
That is the intended axis-9 finding, not a bug.

## 2. Did the mock let us *demonstrate* logic we could not *measure*?

Yes, in several places, and the mock flatters the attacker in some and the defender in
others:

- **Our "success rate" is partly our choice of words.** The mock leaks iff the input
  contains one of 12 keywords (`ignore`, `reveal`, `the note`, ...). D01–D16 contain
  them and score 5/5; D17–D20 (Spanish, "grandmother", a bare question, a completion
  with no trigger) contain none and score 0/5. A real model could fall for D17–D20 and
  resist D05; the 16-vs-4 split says nothing about real models.
- **The same holds for the agent planner.** It builds the exfil chain only for "send …
  email", "exfiltrate" or "forward". A05 ("Mail …"), A18 (Spanish only), A19 ("Share …")
  and A20 ("Message …") score 0/5 on the `sent` oracle for that reason alone. A18 and A20
  are not even turned into a sensitive call, which is why B2 counts 90 fired attempts out of
  100, not 100. A real LLM planner would likely act on all four.
- **The bypass is baked into the mock.** It implements exactly three renderings
  (spaced, hyphen-spelled, base64). X01–X07 request exactly those; X08 (French) and X09
  (reversed) fail only because the mock never implemented them. We report the two
  failures honestly, but a real model would likely do both. The `b1_filter_transforms.csv`
  demo (11/11 renderings survive the literal filter) is **logic only** — it applies the
  app's `str.replace` to strings we built ourselves, with no model in the loop.
- **Level 1 (delimiters) is untestable.** The mock ignores `<data>` tags, so its block
  rate is 0 % by construction and "close the delimiter" (L01–L04, 5/5) proves nothing
  about how a real model treats the fence.
- **The mock never reads the RAG context.** R02 retrieves `private-vip` 5/5 but the
  answer contains the canary 0/5, because nothing in the prompt matches a keyword.
  R01 *does* leak 5/5, but the cause is that the **poisoned** doc is co-retrieved (it
  shares the word "note"), not the private doc. R05 retrieves the private doc **alone**
  and leaks 5/5, but only because the question says "reveal"; and the canary in the private
  doc is the same string as the one in the system prompt, so on the mock we cannot tell
  which one came out. We therefore report retrieval-without-authorization (model-independent)
  and canary-in-answer (model-dependent) as separate effects.
- **`/agent` does not use a model at all** and `/defense` does not touch it. "The model
  is fooled every time" (injection fires 90/90 under the policy) is true by construction.
  What the run demonstrates is the *dispatcher*, which is real code; it does not
  demonstrate how often a real LLM would plan the malicious calls.
- **Oracle strictness differs between parts.** Part A's `/agent` oracle is the course's
  `sent` list. A05 and A19 score 0/5 on it, yet in B2's stricter check (canary anywhere in
  the response) they leak 5/5 through the `lookup_balance` result in the transcript. We kept
  Part A as the assignment defines it and added the stricter check in B2.

## 3. Is our least-privilege policy so narrow it breaks a legitimate task (axis 5)?

Yes. `allow = ["get_faq"]` contained every fired attack (90/90) but broke **7 of the 19**
legitimate tasks the wide-open agent handled — all seven balance lookups (F06–F08,
F17–F20), a 37 % false-positive cost on our 20-task benign corpus (`b2_policy_sweep.csv`).
We chose `get_faq` because the assignment says "the minimum a benign task needs" and we took
"benign task" to mean the FAQ task — which defines the cost away for that task and pushes it
onto everything else. The sweep shows there is no free option here:

- `get_faq + lookup_balance`: breaks 0/19, but the canary appears in the response to 90 of
  100 attack trials, because `lookup_balance` has no per-user authorization and returns the
  secret to anyone. Email exfiltration is contained (0/100) but the confidentiality goal is
  not.
- `get_faq + send_email`: the attacker-addressed email is still sent (80/100) with
  `body: null` — no secret, but the agent is still a free outbound email relay.

A fixed version needs an authenticated, per-user `lookup_balance` and human approval for
`send_email`; we did not build it. One benign task (F09, "send an email ... with the
support hours") is broken even with every tool allowed because the mock planner turns
any "send ... email" request into the exfil chain; we excluded it from the policy's cost
(measured against the wide-open baseline) rather than blaming the policy for it.

## 4. Other ways the evaluation is unfair or incomplete

- **Where the containment guarantee stops.** We tried to break it ourselves
  (`b2_break_attempts.csv`): the side channel through the allowed `get_faq` failed (0/25),
  but (a) `POST /policy` has no authentication, so an attacker re-opens the allow-list
  and the exfil works again 5/5; and (b) `/chat` and `/rag` still leak the canary 5/5
  under the narrow policy, because the secret lives in the system prompt and corpus,
  outside the tool boundary. The guarantee is about tool invocation only.
- **Attacker and defender had unequal information.** We read `vulnllm_app.py` (including
  the mock's keyword list and the planner's regex) before writing payloads, so our attacks
  are white-box; a real attacker would not have them. Our coverage numbers (20 + 5 + 5 + 20
  payloads, 5 trials each) are over our own sample, not the attack space.
- **Benign corpora are still small and hand-written.** 21 benign requests for the filter's
  false positives and 20 tasks for the policy's. That meets the ≥ 20 the scorecard asks
  for, but they were written by us, they do not look like real bank traffic, and none of
  them uses the words the mock treats as triggers. A real user who writes "please ignore my
  last message" would trip the mock (and be redacted at level 2); we did not include such
  messages, so our 0/21 filter FP rate is optimistic.
- **Would a larger model change the result, and can we know without running it?** No,
  we cannot know. We would not assume the direct-injection numbers carry over in either
  direction; the model-independent results (retrieval has no access control, dispatcher
  denies unlisted tools, a literal filter misses re-renderings) are the ones we would
  expect to hold.
- **Not tested:** T2 / the "peer app" (mentioned in the assignment but not defined in the
  repo), multi-turn attacks, a real Ollama backend, the `/summarize` SSRF noted in the
  app's source, and human-in-the-loop approval as a second containment layer.

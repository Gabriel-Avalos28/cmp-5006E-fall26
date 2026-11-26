# AI_LOG — Homework 3 (AI Application Red Team)

**Team:** Gabriel Avalos · Keoma Quiroga · David Bucheli
**Course:** CMP-5006E (Fall 2026) — HW3, T1 `vuln-llm`

**Tools:** Claude (Claude Sonnet 5.5) for entries 1–4 and Claude (Claude Opus 5.5) for
entries 5–6, both used in agent sessions that read the course
repo, wrote and ran the code, and drafted the documents. They were used as a coding/writing
pair-programmer, **not** as the system under test: the target's "model" in the official
results is the course's deterministic mock. Entry 6 adds one run against a real local model
(Ollama `qwen2.5:1.5b`), reported separately in `results_ollama/`.

Per `resources/ai-policy.md` and `resources/ethics-and-scope.md`: AI use is allowed and
logged here, and we are responsible for everything we submit. No real secrets, client data
or private lab details were pasted anywhere; all data is the lab's synthetic canary and
corpus. Everything ran against the local `vuln-llm` app on loopback.

> **To be completed by each team member before submitting.** Every "Did I understand it?"
> field below is deliberately left for each of us to answer, in our own words, after reading
> the code. The policy grades this field and the week 14 checkpoint is closed-book; we only
> write "yes" where we can defend it, and "no" is allowed.

---

## Entry 1 — Reading the assignment and the repo

**Tool:** Claude

**What I asked:** "Complete HW3 as a student would, meeting every requirement; if the
instructions are inconsistent, tell me instead of inventing anything."

**What I got:** A list of inconsistencies in the assignment text, which we then resolved
with the team: (1) "Two apps" but only T1 is defined, the "peer app" is never specified;
(2) "Pairs" while our hw2 team has three members; (3) "PR review: Submit a pull request"
says nothing about a reviewer; (4) the mock is deterministic, so k/5 reliability cannot be
measured; (5) `/agent` does not use the model or `/defense`, so B1.2 cannot apply to it;
(6) the delimiter defense does nothing on the mock.

**What I did with it:** Decisions: T1 only; mock backend with reasoning about a real model
(allowed by the assignment); keep the three-person team and flag it. Items 5 and 6 became
results and honesty points instead of being hidden.

**Did I understand it?**
- Gabriel Avalos: _(fill in)_
- Keoma Quiroga: _(fill in)_
- David Bucheli: _(fill in)_

## Entry 2 — Harness and Part A

**Tool:** Claude

**What I asked:** "Build the harness and the four attacks with canary oracles, 5 trials
each, with benign controls."

**What I got:** `common/` (in-process target, HTTP client, local attacker page server,
oracles), a 20-payload `/chat` corpus, 5 indirect pages, 4 RAG questions, 5 agent requests,
and `attack/attack.py`.

**What I did with it:** Kept the design; the benign controls (7 controls, 11 oracle rows, 0 confirmed) are
what justify trusting the oracle. Payloads that contain none of the mock's trigger words
(D17–D20, I05, A05) were kept on purpose to show that the mock's 0/5 says nothing about a
real model. We split RAG into retrieval-without-authz vs canary-in-answer after checking
that R01's leak is actually caused by the co-retrieved poisoned doc.

**Did I understand it?**
- Gabriel Avalos: _(fill in)_
- Keoma Quiroga: _(fill in)_
- David Bucheli: _(fill in)_

## Entry 3 — Part B (defend, bypass, contain)

**Tool:** Claude

**What I asked:** "Run levels 1–3, find a bypass of the output filter, apply least
privilege, report coverage vs containment, and try to break our own containment."

**What I got:** `defend/defend.py` with block rates, spaced/spelled/base64 bypasses through
all three model-routed surfaces, a filter-logic demo, the allow-list sweep, and attempts to
break the containment.

**What I did with it:** Three corrections during the run, kept as evidence of checking:
(a) the first "percent-encoded" transform left `-` and letters unescaped, so it was **not**
a bypass — replaced with a per-byte encoding; (b) the script crashed when `send_email` ran
without `lookup_balance` (`body` is `None` in the app) — handled, and noted that the agent
still emails the attacker with `body: null`; (c) one benign task (F09) fails even with all
tools allowed because the mock planner treats any "send ... email" as the exfil chain, so
the policy's false-positive cost is measured against the wide-open baseline, not against 9/9.
We also kept the two attempts that fail on the mock (X08 French, X09 reversed) and the one
that succeeds against our own containment (`POST /policy` has no authentication).

**Did I understand it?**
- Gabriel Avalos: _(fill in)_
- Keoma Quiroga: _(fill in)_
- David Bucheli: _(fill in)_

## Entry 4 — Documents

**Tool:** Claude

**What I asked:** "Write README, the honesty section (≥ 3 points) and run_all.py."

**What I got:** `README.md` with both Control Scorecards, `honesty.md`, `run_all.py` (14
invariants, all passing on the mock).

**What I did with it:** Kept the structure. Wording that would overclaim was constrained to
what the mock can show (e.g. "expected on a real model, untested"). We verified numbers
against `results/*.csv` rather than trusting the prose.

**Did I understand it?**
- Gabriel Avalos: _(fill in)_
- Keoma Quiroga: _(fill in)_
- David Bucheli: _(fill in)_

## Entry 5 — Review against the assignment and extension of the corpora

**Tool:** Claude (Claude Opus 5.5)

**What I asked:** "Review the professor's HW3 statement and every folder it references,
run everything, and tell us what to change, delete or improve." Then: "Apply the
recommendations, update the README, make sure every deliverable is complete and carries all
team members' names."

**What I got:** A review that re-ran the submission inside a fresh clone of the course repo
(results byte-identical to the committed ones, also against the app started separately and
on Python 3.9). It found: a broken link to `resources/ethics-and-scope.md`; a latent crash in
`oracle_agent_exfil` when `send_email` runs with `body: null`; the wording "empty body" (the
app sends `null`); the benign-control count; only 5 attack payloads on `/agent` and 5/9
benign requests, below the scorecard's ≥ 20; no canary excerpt in the README; and no
private-doc-only RAG case. It then implemented the fixes: 20 `/agent` attacks (A06–A20,
including four paraphrases the mock planner does not parse), 21 benign requests for the
filter, 20 legitimate agent tasks, R05 (private doc retrieved alone), a headline that counts
only attempts that actually fired, `HW3_RESULTS_TAG` so a real-model run does not overwrite
the mock results, 3 new invariants in `run_all.py` (17 total), evidence excerpts and a
requirement-to-section table in the README, and the team names in every document and script.

**What I did with it:** _(each of us: what we checked, kept or changed)_. The numbers in the
README and `honesty.md` were checked against the regenerated CSV/JSON. A real-model run was
attempted from the assistant's environment and was not possible (no access to the model
download), so it remains open.

**Did I understand it?**
- Gabriel Avalos: _(fill in)_
- Keoma Quiroga: _(fill in)_
- David Bucheli: _(fill in)_

## Entry 6 — Real-model run (Ollama qwen2.5:1.5b)

**Tool:** Claude (Claude Opus 5.5), in an agent session on our own laptop

**What I asked:** "Run an additional pass of HW3 against a real model through Ollama
(`qwen2.5:1.5b`) without touching the official mock results: Part A, and B1 if there is
time. Validate the run (backend must say `ollama`, look for `[backend error` fallbacks,
benign controls must stay at 0/5), then update the README, `honesty.md` and this log with the
real numbers, without inflating anything."

**What I got:** Ollama installed and the model pulled; the course app started on
`127.0.0.1:8000` with `/health` reporting `"backend": "ollama"`; Part A (4 min 57 s) and B1
(21 min 32 s) written to `attack/results_ollama/` and `defend/results_ollama/`, with
`results/` unchanged. Part A on the real model: 15 of 50 attack rows non-deterministic,
`/chat` 41/100 trials (only 3 payloads at 5/5), R02 leaks 5/5 (0/5 on the mock), `/agent`
and retrieval identical to the mock, 0/37 benign rows confirmed. During validation it found
that the app silently falls back to the mock on a 60 s timeout, that this happened 5 times
in B1 (0 in Part A, per the Ollama server log), and that two recorded "bypasses" were such
fallbacks. It wrote `defend/validate_bypass_ollama.py` to re-run the bypass set checking
every trial (9 fallbacks excluded): spaced/spelled bypass is real but ≤ 3/5, base64 never
works on this model. It also reported one benign reply redacted at level 3 that it could
not explain. It then updated the README (mock vs Ollama tables, B1 on a real model,
reproduction), `honesty.md` §1 and this entry, and checked that `run_all.py` still passes
17/17 on the mock.

**What I did with it:** _(each of us: what we checked, kept or changed)_

**Did I understand it?**
- Gabriel Avalos: _(fill in)_
- Keoma Quiroga: _(fill in)_
- David Bucheli: _(fill in)_

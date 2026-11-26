# AI_LOG — Homework 3 (AI Application Red Team)

**Team:** Gabriel Avalos · Keoma Quiroga · David Bucheli
**Course:** CMP-5006E (Fall 2026) — HW3, T1 `vuln-llm`

**AI tools:** Claude Sonnet 5.5 helped with entries 1–4. Claude Opus 5.5 helped with
entries 5–6. We used Claude to clarify requirements, get feedback on our writing, and
understand how to plan some tests. Our team made the decisions, updated the submission, and
ran the checks. Claude was not the system under test: the official results are from the
course's deterministic mock. Entry 6 reports a separate test that our team ran against
Ollama `qwen2.5:1.5b`.

AI use is allowed for this assignment and is recorded here. We are responsible for what we
submit and for checking the results. We used only the lab's synthetic canary and sample
data; no real secrets, client data, or private lab details were shared. All tests were run
against the local `vuln-llm` app.

> **Before submitting:** The "Did I understand it?" responses below are shared team
> summaries. Before submitting, make sure each of us can explain the ideas in our own words
> after reviewing the code.

---

## Entry 1 — Understanding the assignment

**Tool:** Claude

**What I asked:** I asked Claude to walk us through the HW3 requirements in plain language,
identify conflicts or unclear instructions, and explain which parts the provided mock could
and could not help us test. We used that guidance to decide the scope as a team rather than
guessing what the assignment meant. As we worked through the requirements, I also asked
Claude to review our interpretation and point out if a new question or inconsistency came up.

**What I got:** Claude gave us a requirements summary and highlighted the main ambiguities:
the assignment mentions two apps but defines only T1; and it asks for a pull request without naming a reviewer. It
also explained that the deterministic mock cannot show how consistently an attack works
across repeated trials, that `/agent` does not use the model or `/defense`, and that the
delimiter defense has no effect on the mock.

**What we decided:** We focused on T1, and made the limits of
the mock clear instead of presenting guesses as results. We reported the `/agent` and
delimiter limitations honestly.

**Did I understand it?**
Yes. We understand the main requirements and why some parts needed a team decision. We chose
to focus on T1 and to report what the mock can and cannot show, rather than treating its
results as proof of how a real model would behave.

## Entry 2 — Test harness and Part A

**Tool:** Claude

**What I asked:** I asked Claude to guide us through planning the Part A test harness:
how to organize the four attack groups, repeat each test five times, use canary checks to
spot leaks, and include benign controls. We also asked for help understanding what each
part of the harness was meant to check. As we developed the test plan, we asked Claude to
review our progress and suggest changes if a case or control seemed to be missing.

**What I got:** Claude helped us organize the test cases for chat, indirect prompts, RAG,
and the agent, and clarify how the harness and canary checks fit together. Our team used
that guidance to build and run the tests.

**What we checked and kept:** We kept examples that do not contain the mock's trigger
words (D17–D20, I05, and A05) to show why a zero result on this mock does not tell us how a
real model would behave. We also kept the benign controls: 7 controls produced 11 oracle
results checked by our leak detectors, with 0 confirmed leaks. For RAG, we checked that the
leak in R01 came from a poisoned document retrieved alongside the private document.

**Did I understand it?**
Yes. We understand that the harness runs the attacks in a repeatable way and that the
canary checks help identify possible leaks. The benign controls give us a way to check
whether those checks flag normal responses by mistake; the results still apply only to the
mock we tested.

## Entry 3 — Part B: defenses and containment

**Tool:** Claude

**What I asked:** I asked Claude to explain how we could test the defense levels, try
different ways of getting past the output filter, and check the agent's tool permissions.
We also asked how to tell the difference between blocking an attack and limiting its
impact if it gets through. As we worked on the defenses, we asked Claude to review our
approach and help us think through corrections or follow-up tests.

**What I got:** Claude helped us understand how to test the output filter, the tools the
agent could use, and possible ways around our containment rules. Our team prepared and ran
the tests.

**What we checked and changed:** We caught that the first percent-encoding example still
left some characters unchanged, so it was not a real bypass. We replaced it with a version
that encodes each byte. We also fixed a test-script crash when `send_email` ran without a
message body, and recorded that the app still sends the email with `body: null`.

One benign task (F09) fails even when all tools are allowed: the mock treats any request to
send an email as the exfiltration chain. We therefore compared the policy's false-positive
cost with the wide-open baseline, not with an assumed perfect score. We kept two attempts
that did not work against the mock (X08 in French and X09 reversed), and recorded that
`POST /policy` can change the policy without authentication.

**Did I understand it?**
Yes. We understand that the output filter and tool permissions address different risks, and
neither one is a complete guarantee. The tests also showed why we need to report failures
and limits, not just the cases the defenses caught.

## Entry 4 — Project documents and checks

**Tool:** Claude

**What I asked:** I asked Claude to review the grammar and clarity of our `README.md` and
`honesty.md`, point out explanations or claims that might confuse a reader, and suggest
specific edits while leaving the final wording and decisions to our team. We also asked for
feedback on updated drafts as we revised them, so we could make further improvements where
needed.

**What I got:** Claude gave us feedback on wording and clarity, especially where a claim
needed to match what the mock actually showed. We used that feedback while revising the
documents; Claude's role here was mainly to review and explain, not to write the final
documents for us.

**What we checked:** Our team checked that the claims stayed within what the mock can show
and compared the README numbers with the results files. We also ran `run_all.py` ourselves:
all 14 checks passed on the mock.

**Did I understand it?**
Yes. We understand that the README should explain our results clearly without claiming more
than the tests can show. We checked the numbers against the result files ourselves, and we
know that passing checks on the mock does not prove that a real model is safe.

## Entry 5 — Reviewing the requirements and adding tests

**Tool:** Claude Opus 5.5

**What I asked:** I asked Claude to help us compare each HW3 requirement with the files and
tests we had prepared, explain any gaps it noticed, and suggest what our team should check
or improve before submitting. As we worked through those changes, we asked Claude to look
over our progress and flag any remaining gaps or useful follow-up checks.

**What I got:** Claude pointed out items for us to review, including a broken link, a test
that could fail when an email body was `null`, and areas where we needed more test cases or
clearer evidence in the README. It also explained why the wording should say `null` rather
than "empty."

The review found a broken link, a test that could crash when an email body was `null`, and
some missing test coverage: too few `/agent` attacks and benign requests, no example of a
private RAG document retrieved on its own, and no canary excerpt in the README. It also
flagged wording that called a `null` body "empty."

**What we checked and changed:** Our team added 20 `/agent` attack cases, 21 filter benign
requests, 20 legitimate agent tasks, and R05, which tests retrieval of the private document
on its own. We also updated the results summary, added a results tag to keep Ollama output
separate from the mock, and improved the README with evidence examples and a table linking
requirements to sections. We added three checks to `run_all.py` (17 total), then ran the
checks ourselves and compared the updated README and honesty section with the results files.

**Did I understand it?**
Yes. We understand why we added the missing test cases and clearer evidence, and we checked
the results ourselves rather than relying only on Claude's review. Passing those checks
confirms the mock results, but it does not tell us how every real model would behave.

## Entry 6 — Separate test with Ollama

**Tool:** Claude Opus 5.5, in an agent session on our own laptop

**What I asked:** I asked Claude to guide us through a separate Ollama test, explain how
our team could confirm the app was using Ollama rather than silently falling back to the
mock, and show us how to keep the new results separate from the official ones. We also
asked for help understanding how to report the findings and their limitations. As we ran
the test and reviewed its results, we asked Claude to suggest additional checks for
timeouts, fallbacks, or unexpected responses.

**What I got:** Claude explained the setup and suggested checks, including confirming the
backend and looking for timeout fallbacks. Our team installed Ollama and the model, started
the app, ran Part A and B1, checked the results, and saved them in
`attack/results_ollama/` and `defend/results_ollama/`. We left the official `results/`
folder unchanged; Claude did not run this test.

**What the separate run showed:** The app reported the Ollama backend. In Part A, 15 of 50
attack rows had varying results. Chat attacks succeeded in 41 of 100 trials, and only
three payloads succeeded in all five trials. R02 leaked the canary in 5/5 trials; it did
not leak on the mock. The `/agent` and retrieval results matched the mock, and none of the
37 benign rows were confirmed.

Our team also found that the app can silently fall back to the mock after a 60-second
timeout. This happened five times in B1 and not in Part A, according to the Ollama server
log. Two results first recorded as bypasses were actually fallbacks. We ran a follow-up
check that excluded nine fallback trials: the spaced and spelled-out bypass worked, but no
more than 3/5 times; the base64 bypass did not work on this model. One benign reply was
redacted at defense level 3, and we could not explain why.

**What we checked:** We kept the Ollama results separate from the official mock results,
updated the README and `honesty.md` to describe the run and its limits, and confirmed that
`run_all.py` still passes all 17 checks on the mock.

**Did I understand it?**
Yes. We understand that the Ollama run is separate from the official mock results and why
we had to check for timeouts that silently switch back to the mock. Those checks matter:
without them, we could mistake a fallback result for a real-model result.

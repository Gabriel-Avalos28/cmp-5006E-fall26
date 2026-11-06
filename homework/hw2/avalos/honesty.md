# Where our attack, defence, or comparison might be unfair

**Team:** Gabriel Avalos · Keoma Quiroga · David Bucheli — Homework 2

The rubric grades **evidence quality, not which side won**. Here are the honest
weaknesses of our submission. The first four are the ones the assignment names.

### 1. Was the ground-truth set built independently of the tools we scored?

Yes in the property that matters, with one caveat. We reused the instructor's
`duel-2-web/ground_truth.json`, which was built by **reading `vulnweb_app.py`**, not
by running any tool — so it is not biased toward our scanner or our LLM. We verified
it ourselves against the live app with `verify_fixtures.py` (→ `FIXTURES SOUND.`)
before scoring. **Caveat:** we wrote the `regex-naive` scanner *and* the semgrep
rules, so we knew in advance that a single-line rule would miss the two-line SQLi.
We did not tune the ground truth to flatter anything (semgrep still out-scores the
naive scanner), but a fully independent grader would have built the truth set without
having seen our tools. **Fixture note:** the instructor's `verify_fixtures.py`
resolves its course-root path one level too shallow for this repo's layout and raises
`ModuleNotFoundError: vulnweb_app` as shipped; it runs clean with
`PYTHONPATH=labs/vuln-web/app python homework/hw2/duel-2-web/verify_fixtures.py`. We
did **not** edit the instructor's file.

### 2. The duel's scoring scope is a choice we made — and it cuts both ways.

The three real LLM runs reported 11–15 findings each, but the ground truth only
adjudicates three injection sinks, one true negative (`/safe`) and one not-present
class (BAC). We therefore score every tool on the **canonical class set**
{sqli, xss, cmdi, broken-access-control} and report findings outside it (plaintext
password storage, missing rate limiting, information disclosure in the error path,
0.0.0.0 bind, no TLS, …) as *out-of-scope* rather than as false positives. **Why this
could be unfair:** that decision is what makes the real LLM score so well (run 1 and 3
are a perfect 1.00). Counting those extra findings as FPs would crush its precision —
but that would be dishonest, because most of them are **genuine weaknesses**, not
hallucinations. Counting them as TPs would be equally dishonest (they are not in the
graded set). We chose "report, don't score," and we flag that a stricter grader who
counts every out-of-scope finding as an FP would report the LLM's precision at roughly
3/11–3/15, not 100%. Both framings are in the data (`duel_report.json` lists every
out-of-scope line); we just do not hide which one we picked.

### 3. Did we tune one side and leave the other on defaults (effort asymmetry)?

Partly, in two directions. **The WAF** we shaped deliberately: a *narrower* ruleset
(only the exact Part-A literals) would have given ~0% FPs and looked "safe," which
would have undersold the lesson, so we used realistic word-boundary keyword rules that
actually trip on attack-adjacent English — i.e. we tuned the WAF until it looked
*bad*, the opposite of the usual bias but still a bias. **The LLM** got *no* prompt
engineering: each of the three runs is a single cold review with an identical generic
prompt, no "also check access control" follow-up, no retry to improve precision. So
the duel measures an off-the-shelf review, not the best an analyst could coax. A
tuned prompt would likely suppress the one BAC hallucination entirely and push all
three runs to a perfect score — which would make the duel *less* interesting, not
more. Read our LLM numbers as "a strong model, cold," not "the ceiling."

### 4. Which Part-A finding are we least sure reproduces, and why?

The **XSS** finding. Our oracle confirms a *sound necessary condition* — the injected
`<svg onload=…>` / `<script>` markup survives **unescaped** in the response — but it
does **not** prove script execution, because the harness has no browser/DOM. Unescaped
reflection is a strong signal, but a real page might still neutralise it via a
Content-Security-Policy, a downstream sanitiser, or an injection context where the
handler never fires. SQLi (canary exfiltrated from the real sqlite3 engine) and cmdi
(the sink reports the metacharacter reached the command string) are closer to
end-to-end; XSS is where "confirmed by our oracle" is furthest from "exploitable in a
real browser."

### 5. The Medium filter (Part A) and the WAF (Part B1) are both ours.

`vuln-web` has no difficulty levels, so `common/medium_filter.py` reproduces
DVWA-Medium and `common/waf.py` is our own blocklist. We "bypass filters we wrote."
Mitigation: the Medium filter is a faithful reproduction of documented DVWA-Medium
code (case-sensitive `str_replace`, `;`/`&&` strip), each baseline payload confirms
the filter **does** neutralise the canonical attack (0/3 behind it), and every Part-B
bypass had to both pass the WAF **and** leak the real canary to count. It is an honest
demonstration of the techniques, not the same as defeating a filter a third party
hardened against us.

### 6. Is the benign corpus realistic, or does it dodge our rules by luck?

It is the **provided** `benign_traffic.json`, not one we curated. Its own `_comment`
says it deliberately bundles attack-adjacent English, which is exactly why our FP rate
is 28.6% and not 0%. But 21 inputs across two fields is tiny, and the number is
**sensitive to the denominator** (login-only would be 0/9; search-only 6/12 = 50%). A
real production corpus (long free-text comments, pasted code, URLs) would almost
certainly push the FP rate **higher**, because `--`, `drop` and `\bor\b` are blunt. So
28.6% is a floor for this corpus, not a production number.

### 7. The cmdi "confirmation" is a simulation, not a real shell.

`do_ping` never calls `os.system`/`subprocess` — by design, so the lab is safe to run
anywhere. It builds `ping -c 1 {host}` and reports `injection_detected` when a shell
metacharacter appears. Our oracle therefore proves the **untrusted string reached the
command-construction sink** (the real bug), but not that a second command executed.
It also abstracts away OS divergence: our bypasses use `|`, `&`, `$()`, but separators
differ on `cmd.exe` vs POSIX `/bin/sh`. On a real target we would confirm with an
out-of-band effect (a timing delay, a DNS/file side-channel), not a self-reported flag.

# HW2 — Web Attack & Defend — Part C small-model baseline — Team: Gabriel Avalos, Keoma Quiroga, David Bucheli
"""A DOCUMENTED small-model MOCK, kept as a CONTRAST baseline alongside the three
real LLM reviews (llm_review_run{1,2,3}.txt).

This is the canned review the week-6 studio ships (studios/week-06/webharness.py),
i.e. what a small local model (qwen2.5:3b) reliably returns on this file: it names
the three real sinks, then adds a confident HALLUCINATION (Broken Access Control in
an app with no auth code) and a WRONG-LOCATION finding (flags the FIXED /safe
endpoint). It is NOT a language model and is labelled as a mock everywhere.

Why keep it: the three graded runs are a real frontier model (see AI_LOG Entry 4),
which behaves differently from a small local model. Scoring the mock next to the
real runs makes the contrast explicit — the small model makes the BAC hallucination
EVERY time and flags /safe; the real model makes BAC in only 1 of 3 runs and never
flags /safe. That contrast is itself the Part-C lesson about which model you trust.
"""
from __future__ import annotations

REVIEW = """\
I reviewed vulnweb_app.py and found the following vulnerabilities:

1. [HIGH] SQL Injection in do_login: the query is built with f-string
   interpolation of `user` and `pw`, so an attacker can bypass authentication.
2. [HIGH] Reflected XSS in do_reflect: the `name` parameter is placed into the
   HTML response without any output encoding.
3. [HIGH] Command Injection in do_ping: the `host` value is concatenated into a
   shell command string.
4. [HIGH] Broken Access Control in do_login: there is no session or role check
   guarding the admin record, so any user can reach privileged data.
5. [MEDIUM] Reflected XSS in do_reflect_safe: the `name` parameter is reflected
   back to the user in the response.
"""

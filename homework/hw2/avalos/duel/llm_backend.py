# Homework 2 — Web Attack & Defend — Part C LLM arm — Team: Gabriel Avalos, Keoma Quiroga, David Bucheli
"""The LLM reviewer arm — the DOCUMENTED MOCK the assignment permits.

Why the mock and not a live model: ``seclab.llm.backends_available()`` on our
machines reports ollama *serving but with no model pulled* ("ollama models: []"),
and no API key. The HW explicitly allows "your seclab.LLM backend, or the
documented mock." So we stand in for ``LLM(backend="ollama")`` with two canned
reviews that reproduce what a small local model (e.g. qwen2.5:3b) actually does on
this file, observed in the week-6 studio:

  * HIGH RECALL on the three real sinks (it names all three), and
  * a CONFIDENT HALLUCINATION — Broken Access Control, in an app with zero auth
    code — plus, on some runs, a finding on the FIXED ``/safe`` endpoint.

Crucially the two runs DIFFER (temperature>0 behaviour), which is the whole point
of axis 9: an LLM review you cannot reproduce is not evidence. ``review(run)``
returns the raw free text; ``duel.py`` parses it exactly like a real transcript.

This is a mock: per ``resources/ethics-and-scope.md`` we do NOT report it as a
real model's output. It is a faithful, frozen stand-in so the comparison is
runnable laptop-only, and the non-determinism is modelled explicitly, not faked
away.
"""
from __future__ import annotations

# Run 1 — names the 3 real sinks, hallucinates Broken Access Control on do_login,
# and wrongly flags the FIXED do_reflect_safe endpoint.
_RUN_1 = """\
I reviewed vulnweb_app.py and found the following vulnerabilities:

1. [HIGH] SQL Injection in do_login: the query is built by f-string
   interpolation of `user` and `pw`, so authentication can be bypassed and the
   secret column leaked.
2. [HIGH] Reflected XSS in do_reflect: the `name` parameter is written into the
   HTML response with no output encoding.
3. [HIGH] Command Injection in do_ping: the `host` value is concatenated into a
   shell command string.
4. [HIGH] Broken Access Control in do_login: there is no session or role check
   protecting the admin record, so any user can read privileged data.
5. [MEDIUM] Reflected XSS in do_reflect_safe: the `name` value is returned to the
   user in the response and should be treated as untrusted.
"""

# Run 2 — same temperature, different sample: still the 3 real sinks, still
# hallucinates Broken Access Control but now attributes it to do_ping, and this
# time does NOT flag do_reflect_safe. The finding SET changed between runs.
_RUN_2 = """\
Here are the security issues I identified in vulnweb_app.py:

1. [HIGH] SQL Injection in do_login: user-controlled input is formatted directly
   into the SQL string, allowing auth bypass.
2. [HIGH] Reflected XSS in do_reflect: unescaped user input is reflected into the
   HTML body.
3. [HIGH] Command Injection in do_ping: the host parameter reaches a shell
   command without sanitisation.
4. [MEDIUM] Broken Access Control in do_ping: the endpoint performs no
   authorization check before acting on the request.
"""

_RUNS = {1: _RUN_1, 2: _RUN_2}


def review(run: int) -> str:
    """Return the raw free-text review for the given run (1 or 2)."""
    return _RUNS[run]

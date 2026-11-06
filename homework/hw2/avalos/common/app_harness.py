# HW2 — Web Attack & Defend — Team: Gabriel Avalos, Keoma Quiroga, David Bucheli
"""Drive the UNMODIFIED ``vuln-web`` sinks through an optional defense layer.

Why in-process? The sink functions (``do_login``, ``do_reflect``, ``do_ping``)
return the exact byte bodies the HTTP handler sends — the handler is a thin wrapper
around them. Calling them directly gives identical oracle semantics with none of
the port flakiness, so a graded run is deterministic. A real HTTP end-to-end smoke
test lives in ``run_all.py::http_smoke``, so we also prove the findings hold over
the wire, not only in-process.

A "defense" is any object exposing ``screen(kind, value) -> Verdict(blocked, value)``
applied per field, exactly like a per-parameter WAF. ``None`` = no defense (raw
app). ``fixed=True`` routes to the structurally-fixed sinks in ``positive_fix.py``.

SQLi payload encoding: a single ``Payload.text`` can carry the two login fields as
``"<user> :: <pw>"``; with no `` :: `` the whole string is the user field and pw
defaults to ``'x'``. XSS/cmdi payloads are the single field value directly.
"""
from __future__ import annotations

from . import paths
paths.bootstrap()

import json  # noqa: E402

import vulnweb_app as app  # noqa: E402  (the real target, run locally)
from . import positive_fix  # noqa: E402

CANARY = app.CANARY_SECRET
BLOCKED_BODY = json.dumps({"blocked": True, "by": "defense"})
PW_DEFAULT = "x"


def _fresh_db():
    # Rebuild the app's OWN in-memory DB (same schema + same canary row the live
    # app ships). We never fork a hand-made copy — the fix is tested against the
    # real engine and the real data.
    app.DB = app.make_db()


_fresh_db()


def split_sqli(text: str):
    if " :: " in text:
        u, p = text.split(" :: ", 1)
        return u, p
    return text, PW_DEFAULT


def run_sink(kind: str, payload_text: str, defense=None, fixed: bool = False) -> str:
    """Apply the defense per field, then call the (vuln or fixed) sink."""
    if kind == "sqli":
        user, pw = split_sqli(payload_text)
        fields = {"user": user, "pw": pw}
    elif kind == "xss":
        fields = {"name": payload_text}
    elif kind == "cmdi":
        fields = {"host": payload_text}
    else:
        raise ValueError(kind)

    if defense is not None:
        for name, val in list(fields.items()):
            v = defense.screen(kind, val)
            if v.blocked:
                return BLOCKED_BODY
            fields[name] = v.value

    if kind == "sqli":
        fn = positive_fix.login_fixed if fixed else app.do_login
        return fn(fields["user"], fields["pw"])
    if kind == "xss":
        fn = positive_fix.reflect_fixed if fixed else app.do_reflect
        return fn(fields["name"])
    if kind == "cmdi":
        fn = positive_fix.ping_fixed if fixed else app.do_ping
        return fn(fields["host"])


def make_send(kind: str, defense=None, fixed: bool = False):
    _fresh_db()
    return lambda payload_text: run_sink(kind, payload_text, defense=defense, fixed=fixed)


# --- sound oracles (check a SECURITY EFFECT, never a surface string) --------
def sqli_oracle():
    """Confirmed iff the admin canary secret is exfiltrated."""
    def oracle(payload, response):
        hit = CANARY in response
        return hit, (f"canary {CANARY!r} exfiltrated" if hit else "")
    return oracle


def xss_oracle():
    """Confirmed iff the payload's executable marker is reflected UNESCAPED.

    The marker (payload.note) carries a raw '<'. Its verbatim presence proves the
    tag was NOT HTML-encoded (encoding turns '<' into '&lt;'), i.e. the browser
    would parse it as live markup — the real XSS effect, not a reflected string."""
    def oracle(payload, response):
        marker = payload.note or "<script>"
        live = (marker in response) and ("&lt;" not in response)
        return live, (f"unescaped {marker!r} reflected into HTML" if live else "")
    return oracle


def cmdi_oracle():
    """Confirmed iff a shell metacharacter reaches the command context, i.e. the
    sink reports ``injection_detected`` (the simulated-exec signal)."""
    def oracle(payload, response):
        try:
            detected = json.loads(response).get("injection_detected") is True
        except (json.JSONDecodeError, AttributeError, TypeError):
            detected = False
        return detected, ("shell metacharacter reached the command context"
                          if detected else "")
    return oracle


ORACLES = {"sqli": sqli_oracle, "xss": xss_oracle, "cmdi": cmdi_oracle}

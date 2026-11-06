# HW2 — Web Attack & Defend — Part B2 engine — Team: Gabriel Avalos, Keoma Quiroga, David Bucheli
"""The POSITIVE security model: structural fixes for each sink.

A positive model does not enumerate bad input (that is the blocklist/WAF, a
negative model). It changes the STRUCTURE so untrusted data cannot reach the
control channel, giving a guarantee that holds for ANY input.

    login_fixed   — parameterized query: input is bound as DATA, never parsed as SQL.
    reflect_fixed — html.escape: input is encoded for the HTML context (identical to
                    the app's own /safe endpoint).
    ping_fixed    — strict allowlist on the host ([A-Za-z0-9.-] only); anything else
                    is refused before a command is built, so no metacharacter can
                    reach the command context.

Each returns the SAME body shape as its vulnerable twin, so the Part-A oracles can
be re-run unchanged and will now report NO effect. These run against the app's OWN
``DB`` (``vulnweb_app.make_db``) — the real engine and the real canary row, not a
hand-made copy.
"""
from __future__ import annotations

from . import paths
paths.bootstrap()

import html  # noqa: E402
import json  # noqa: E402
import re  # noqa: E402
import sqlite3  # noqa: E402

import vulnweb_app as app  # noqa: E402

_HOST_ALLOW = re.compile(r"^[A-Za-z0-9.\-]+$")


def login_fixed(user: str, pw: str) -> str:
    # POSITIVE FIX: parameter binding. The query STRUCTURE is fixed at parse time;
    # user/pw are data, not SQL. No string can alter the query shape.
    query = "SELECT user, secret FROM users WHERE user = ? AND pw = ?"
    try:
        rows = app.DB.execute(query, (user, pw)).fetchall()
    except sqlite3.Error as e:
        return json.dumps({"error": f"sql error: {e}"})
    if rows:
        return json.dumps({"ok": True, "rows": rows})
    return json.dumps({"ok": False})


def reflect_fixed(name: str) -> str:
    # POSITIVE FIX: output encoding for the HTML context (the app's own /safe).
    return f"<html><body><h1>Hello, {html.escape(name)}!</h1></body></html>"


def ping_fixed(host: str) -> str:
    # POSITIVE FIX: allowlist. A hostname is [A-Za-z0-9.-]; reject everything else
    # before a command exists (equivalent to passing argv as a list, no shell).
    if not _HOST_ALLOW.match(host):
        return json.dumps({
            "rejected": True,
            "injection_detected": False,
            "note": "host failed the allowlist ^[A-Za-z0-9.-]+$ — no command built",
        })
    return json.dumps({
        "would_run": f"ping -c 1 {host}",
        "injection_detected": False,
        "note": "host passed the allowlist; no shell metacharacter possible",
    })

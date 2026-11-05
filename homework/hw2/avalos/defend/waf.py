# Homework 2 — Web Attack & Defend — Part B engine — Team: Gabriel Avalos, Keoma Quiroga, David Bucheli
"""The two defences for the SQLi finding, plus a parameterized sink.

B1 — NEGATIVE model (a WAF blocklist). Enumerates *bad* input. ``waf_block``
returns the rule that fired or ``None``. It covers the Part-A SQLi payloads, but
'bad' is open-ended, so same-intent mutations slip through (axis 4) and
attack-adjacent English trips it (axis 5).

B2 — POSITIVE model. ``parameterized_login`` binds input as a VALUE via a real
SQLite parameter placeholder against the same canary DB. Input can never change
the query's structure, for ANY input — the guarantee the WAF cannot state.
"""
from __future__ import annotations

import re
import sqlite3
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import _harness as H   # noqa: E402  (ROOT on path; canary + app)

CANARY = H.canary()

# --- B1: the WAF blocklist (negative security) -------------------------------
WAF_RULES = [
    (re.compile(r"(?i)\bor\b\s+\d+\s*=\s*\d+"),              "SQLi numeric tautology"),
    (re.compile(r"(?i)\bor\b\s+'[^']*'\s*=\s*'[^']*'"),      "SQLi string tautology"),
    (re.compile(r"(?i)union[\s/*]+select"),                  "SQLi UNION SELECT"),
    (re.compile(r"(?i)drop[\s/*]+table"),                    "SQLi DROP TABLE"),
    (re.compile(r"--"),                                      "SQL comment --"),
]


def waf_block(payload: str):
    for rx, name in WAF_RULES:
        if rx.search(payload):
            return name
    return None


# The known SQLi attack payloads the WAF was WRITTEN against (Part-A naive + bypass,
# plus the classic UNION/ DROP). Coverage on these is the trap: it looks like
# security but only measures payloads we already thought of.
KNOWN_SQLI = [
    "admin' OR 1=1--",                              # Part-A naive
    "admin' OR 'a'='a'--",                          # Part-A bypass (vs Medium)
    "x' UNION SELECT user, secret FROM users--",
    "'; DROP TABLE users--",
]

# Candidate same-intent bypasses of THIS WAF. The script keeps only those that
# (a) the WAF passes AND (b) actually leak the canary on the real sink — an
# oracle-filtered bypass set, not a wishlist.
CANDIDATE_BYPASSES = [
    ("admin' OR 'a' LIKE 'a ",   "LIKE tautology: no '=' , no '--'"),
    ("admin' OR 'x'<>'y",        "'<>' inequality is always true, evades the '=' rules"),
    ("admin'/**/OR/**/'a'='a",   "inline /**/ comment defeats the rule's \\bor\\b\\s+ anchor"),
    ("admin'/**/oR/**/'1'='1",   "mixed case + /**/ comment: classic tautology still slips the rule"),
]


# --- B2: the positive model --------------------------------------------------
def _fresh_db():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE users (id INTEGER, user TEXT, pw TEXT, secret TEXT)")
    db.execute("INSERT INTO users VALUES (1,'admin','s3cr3t',?)", (CANARY,))
    db.execute("INSERT INTO users VALUES (2,'alice','password','ordinary-row')")
    db.commit()
    return db


def parameterized_login(user: str, pw: str = "wrong") -> str:
    """The structural fix: user/pw are BOUND as values (``?`` placeholders), so no
    input can alter the query's meaning. Returns the JSON-ish result string; the
    canary can only appear if a row genuinely matched by value."""
    db = _fresh_db()
    rows = db.execute(
        "SELECT user, secret FROM users WHERE user = ? AND pw = ?", (user, pw)
    ).fetchall()
    db.close()
    return str({"ok": bool(rows), "rows": rows})

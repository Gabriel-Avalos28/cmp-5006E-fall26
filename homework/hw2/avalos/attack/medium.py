# Homework 2 — Web Attack & Defend — Team: Gabriel Avalos, Keoma Quiroga, David Bucheli
"""A 'Medium'-level input filter in front of each sink.

The course ``vuln-web`` app has no difficulty levels, so this module is an
explicit, documented stand-in for **DVWA's Medium** filter: a small per-sink
blocklist that stops the obvious week-6 payload but is defeated by a one-line
mutation. Part A's requirement is exactly that — confirm each class *through a
filter bypass*, not by firing the naive payload at a defenceless app.

Each filter returns the rule name that fired, or ``None`` if the request passes.
We keep them deliberately representative of real Medium-level defences:

  * SQLi  — blocks the numeric tautology ``OR 1=1`` and adjacent ``UNION SELECT``
            (the two signatures every intro blocklist ships with).
  * XSS   — strips/blocks ``<script`` (DVWA Medium's actual str_replace behaviour).
  * cmdi  — blocks ``;`` and ``&&`` (DVWA Medium blacklists exactly these two).
"""
from __future__ import annotations

import re

_SQLI_MEDIUM = [
    (re.compile(r"(?i)\bor\b\s+\d+\s*=\s*\d+"), "sqli-medium: numeric tautology OR d=d"),
    (re.compile(r"(?i)union\s+select"),          "sqli-medium: UNION SELECT"),
]
_XSS_MEDIUM = [
    (re.compile(r"(?i)<\s*script"), "xss-medium: <script> blocked"),
]
_CMDI_MEDIUM = [
    (re.compile(r";"),  "cmdi-medium: ';' blocked"),
    (re.compile(r"&&"), "cmdi-medium: '&&' blocked"),
]


def _first_hit(rules, payload):
    for rx, name in rules:
        if rx.search(payload):
            return name
    return None


def sqli_medium(payload: str):
    return _first_hit(_SQLI_MEDIUM, payload)


def xss_medium(payload: str):
    return _first_hit(_XSS_MEDIUM, payload)


def cmdi_medium(payload: str):
    return _first_hit(_CMDI_MEDIUM, payload)

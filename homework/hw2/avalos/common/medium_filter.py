# HW2 — Web Attack & Defend — Team: Gabriel Avalos, Keoma Quiroga, David Bucheli
"""The *built-in* "Medium" filter that Part A must bypass.

``vuln-web`` ships with NO input filter (it is the Low/unfiltered target). The
homework asks us to attack "at the Medium filter level, so each requires a bypass
of the built-in filter" — the DVWA notion of difficulty levels. Since vuln-web has
no levels, we reproduce DVWA's *Medium* defenses as a thin, documented front
controller placed in front of each unmodified sink. We do NOT edit vulnweb_app.py
(its tests pin the sinks); we only wrap it, exactly as a middleware WAF would — and
Part A fires every payload THROUGH this filter, so a confirmed bypass really had to
defeat it (the baseline payload lands at 0/3 behind it).

Each filter is a faithful, deliberately weak reproduction of real DVWA-Medium code,
so the bypasses in Part A are the real DVWA-Medium bypasses:

    SQLi  (DVWA medium): a CASE-SENSITIVE substring blocklist of the canonical
          tautology/comment forms. Case or inline-comment obfuscation slips by.
    XSS   (DVWA medium): str_replace('<script>', '', name) — removes the literal
          lowercase "<script>" once, case-sensitively, NON-recursively. Mixed case,
          nesting, and non-<script> vectors all evade it.
    cmdi  (DVWA medium): strips ';' and '&&'. Every other separator (| & $() ``)
          survives.

A filter returns a Verdict: it BLOCKS (SQLi: a blocklist hit → the request is
refused, no query runs) or it MUTATES the input (XSS/cmdi: str_replace) and
forwards the sanitized value. That split mirrors the two real implementations.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Verdict:
    blocked: bool
    value: str            # sanitized value forwarded to the sink (if not blocked)
    reason: str = ""


# --- SQLi: case-sensitive substring blocklist (DVWA-medium style) -----------
_SQLI_BLOCKLIST = ["' or '", "' or 1", "union select", "'--", "or '1'='1", "' or ''='"]


def sqli_medium(value: str) -> Verdict:
    hits = [tok for tok in _SQLI_BLOCKLIST if tok in value]
    if hits:
        return Verdict(blocked=True, value=value, reason=f"blocklist hit: {hits[0]!r}")
    return Verdict(blocked=False, value=value)


# --- XSS: str_replace('<script>', '', name), case-sensitive, single pass ----
def xss_medium(value: str) -> Verdict:
    # PHP str_replace removes ALL non-overlapping occurrences in one pass and does
    # NOT re-scan — so "<scr<script>ipt>" collapses back to "<script>".
    sanitized = value.replace("<script>", "")
    return Verdict(blocked=False, value=sanitized,
                   reason="removed literal '<script>'" if sanitized != value else "")


# --- cmdi: strip ';' and '&&' (DVWA-medium), single pass --------------------
def cmdi_medium(value: str) -> Verdict:
    sanitized = value.replace("&&", "").replace(";", "")
    return Verdict(blocked=False, value=sanitized,
                   reason="stripped ';' and '&&'" if sanitized != value else "")


SCREENS = {"sqli": sqli_medium, "xss": xss_medium, "cmdi": cmdi_medium}


def screen(kind: str, value: str) -> Verdict:
    return SCREENS[kind](value)

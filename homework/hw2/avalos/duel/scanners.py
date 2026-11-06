# HW2 — Web Attack & Defend — Part C classical arm — Team: Gabriel Avalos, Keoma Quiroga, David Bucheli
"""Three classical scanners pointed at the SAME source the LLM reviews.

  1. regex-naive  : a pure-Python, line-oriented scanner (no dependency, always
                    runnable). It finds the XSS and cmdi sinks but MISSES the SQLi,
                    because the query spans two physical lines — the classic single-
                    line failure mode, and the scanner's "worst miss" for Part C #2.
  2. semgrep      : REAL semgrep with our own rules (semgrep_rules.yaml). Its
                    multiline SQLi rule DOES catch the two-line query — proof the
                    miss above is a rule-design choice, not a law of scanners. It
                    also fires a real FP on a docstring line (cmdi @ module).
  3. bandit       : REAL bandit. Its data-flow B608 rule catches the SQLi the regex
                    missed, but it has no rule for this reflected-XSS/cmdi shape, so
                    it misses those — a different precision/recall trade than regex.

semgrep and bandit degrade gracefully: if the binary is not installed, the scanner
returns [] and the duel notes it was skipped (the regex arm always runs).

Every finding is normalised to ScanResult(rule, location) with location = the
enclosing function name, exactly how ground_truth.json is keyed.
"""
from __future__ import annotations

import ast
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import paths  # noqa: E402
paths.bootstrap()

from seclab.scan import ScanResult  # noqa: E402

SOURCE_PATH = paths.APP_DIR / "vulnweb_app.py"
RULES_PATH = Path(__file__).resolve().parent / "semgrep_rules.yaml"


def _function_ranges(source: str):
    tree = ast.parse(source)
    out = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append((node.name, node.lineno, node.end_lineno))
    return out


def _enclosing(line: int, ranges) -> str:
    name = "module"
    for fname, lo, hi in ranges:
        if lo <= line <= hi:
            return fname
    return name


# --- 1. naive line-oriented regex scanner -----------------------------------
_SANITIZER = re.compile(r"(html\.escape|markupsafe|escape\(|quote\()", re.I)
_LINE_RULES = [
    # SQLi: a statement VERB co-located with an interpolation ON ONE LINE. The
    # two-line query in do_login (verb on line 1, {user} on line 2) is invisible.
    ("sqli", re.compile(r"\b(select|insert|update|delete)\b[^\n]*\{[^}]+\}", re.I)),
    ("xss",  re.compile(r"<\s*(h1|body|div|span|script|img|svg)\b[^<]*\{[^}]+\}", re.I)),
    ("cmdi", re.compile(r"(os\.system|subprocess|popen|[\"']ping|/bin/)\b[^\n]*\{[^}]+\}", re.I)),
]


def regex_naive() -> list[ScanResult]:
    text = SOURCE_PATH.read_text(encoding="utf-8")
    lines = text.splitlines()
    ranges = _function_ranges(text)
    out, seen = [], set()
    for i, ln in enumerate(lines, 1):
        if _SANITIZER.search(ln):
            continue                                   # precise: skip escaped lines
        for rule, pat in _LINE_RULES:
            if pat.search(ln):
                loc = _enclosing(i, ranges)
                if (rule, loc) not in seen:
                    seen.add((rule, loc))
                    out.append(ScanResult(rule=rule, location=loc, tool="regex-naive",
                                          confidence="low", raw=f"{rule} @ line {i}: {ln.strip()}"))
                break
    return out


# --- 2. real semgrep --------------------------------------------------------
_SEMGREP_MAP = {
    "sqli-singleline-fstring": "sqli",
    "sqli-multiline-fstring": "sqli",
    "reflected-xss-fstring": "xss",
    "cmdi-fstring-command": "cmdi",
}


def semgrep() -> list[ScanResult]:
    if not shutil.which("semgrep"):
        return []
    proc = subprocess.run(
        ["semgrep", "--config", str(RULES_PATH), "--json", "--quiet", str(SOURCE_PATH)],
        capture_output=True, text=True)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    ranges = _function_ranges(SOURCE_PATH.read_text(encoding="utf-8"))
    out, seen = [], set()
    for r in data.get("results", []):
        cid = r["check_id"].split(".")[-1]
        rule = _SEMGREP_MAP.get(cid, cid)
        loc = _enclosing(r["start"]["line"], ranges)
        if (rule, loc) not in seen:
            seen.add((rule, loc))
            out.append(ScanResult(rule=rule, location=loc, tool="semgrep",
                                  confidence="medium", raw=f"{cid} @ line {r['start']['line']}"))
    return out


# --- 3. real bandit ---------------------------------------------------------
_BANDIT_MAP = {"B608": "sqli"}   # hardcoded SQL expressions -> sqli (the one we score)


def bandit() -> list[ScanResult]:
    if not shutil.which("bandit"):
        return []
    proc = subprocess.run(["bandit", "-f", "json", "-q", str(SOURCE_PATH)],
                          capture_output=True, text=True)
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    ranges = _function_ranges(SOURCE_PATH.read_text(encoding="utf-8"))
    out, seen = [], set()
    for r in data.get("results", []):
        test_id = r.get("test_id", "")
        rule = _BANDIT_MAP.get(test_id)
        if rule is None:
            # real-but-unscored bandit findings (hardcoded pw, bind-all) kept as raw
            out.append(ScanResult(rule=f"bandit:{test_id}", location="(out-of-scope)",
                                  tool="bandit", confidence="medium",
                                  raw=f"{test_id} {r.get('issue_text','')[:60]}"))
            continue
        loc = _enclosing(r["line_number"], ranges)
        if (rule, loc) not in seen:
            seen.add((rule, loc))
            out.append(ScanResult(rule=rule, location=loc, tool="bandit",
                                  confidence="high", raw=f"{test_id} @ line {r['line_number']}"))
    return out


if __name__ == "__main__":
    for name, fn in [("regex-naive", regex_naive), ("semgrep", semgrep), ("bandit", bandit)]:
        res = fn()
        tag = "(skipped — not installed)" if not res and name in ("semgrep", "bandit") else ""
        print(f"{name} {tag}")
        for r in res:
            print(f"    {r.rule:18} {r.location:14} {r.raw}")

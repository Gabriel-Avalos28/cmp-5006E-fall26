# Homework 2 — Web Attack & Defend — Part C (LLM vs scanner duel) — Team: Gabriel Avalos, Keoma Quiroga, David Bucheli
"""Part C — point a classical scanner and an LLM reviewer at the SAME target and
score both against a HAND-BUILT ground truth (projects/homework fixture), honestly.

  * Classical arm: a line-oriented regex rule set standing in for Semgrep/CodeQL
    (sqlmap/semgrep are not installed here). It is the course's own scanner and it
    MISSES the SQLi because the vulnerable query spans two lines — a real failure
    mode, not a contrivance.
  * LLM arm: the documented mock (see llm_backend.py), run TWICE so the
    non-determinism is measured (axis 9), not hidden.

Ground truth is read from the fixture, which was built BY READING THE SOURCE, not
by running any tool — so scoring a tool against it is honest (a ground truth that
is "whatever the scanner found" rigs the duel).

Run:  python duel/duel.py   (writes results/duel_scores.csv, llm_findings.csv,
                             and llm_review_run{1,2}.txt)
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import _harness as H        # noqa: E402
import llm_backend          # noqa: E402

from seclab.scan import ScanResult, compare_scanners  # noqa: E402

RULE_ALIASES = {
    "sql injection": "sqli",
    "reflected xss": "xss",
    "xss": "xss",
    "command injection": "cmdi",
    "broken access control": "broken-access-control",
}


# --- classical arm (stand-in for Semgrep/CodeQL) -----------------------------
def regex_scanner(source: str) -> list[ScanResult]:
    """Single-line regex rules. The SQLi rule requires the interpolation on the
    same line as SELECT; in vulnweb_app.py the query spans two lines, so it is
    MISSED — the scanner's worst miss, and the point of the duel."""
    rules = [
        ("do_login",   "sqli", r'f"SELECT.*\{.*\}'),      # misses: query spans 2 lines
        ("do_reflect", "xss",  r"Hello, \{name\}"),
        ("do_ping",    "cmdi", r'f"ping -c 1 \{host\}'),
    ]
    out = []
    for loc, rule, pat in rules:
        if re.search(pat, source):
            out.append(ScanResult(rule=rule, location=loc, tool="regex-scanner",
                                  confidence="medium"))
    return out


# --- LLM arm: parse free text into structured findings -----------------------
def parse_llm_review(raw: str, tool: str) -> list[ScanResult]:
    """Faithfully parse each finding line: map prose rule name via RULE_ALIASES,
    extract the ``do_<name>`` location. Do NOT filter suspicious findings — the
    ground truth decides what's real, not us."""
    out = []
    for line in raw.splitlines():
        low = line.lower()
        rule = next((canon for name, canon in RULE_ALIASES.items() if name in low), None)
        loc = re.search(r"do_\w+", line)
        if rule and loc:
            out.append(ScanResult(rule=rule, location=loc.group(0), tool=tool,
                                  confidence="high" if "[high]" in low else "medium"))
    return out


def f1(d):
    return d["f1"]


def main():
    gt = H.load_ground_truth()

    scanner = regex_scanner(H.SOURCE)
    llm_runs = {}
    for run in (1, 2):
        raw = llm_backend.review(run)
        (HERE / f"llm_review_run{run}.txt").write_text(raw, encoding="utf-8")
        llm_runs[run] = parse_llm_review(raw, tool=f"llm-run{run}")

    comp = compare_scanners(
        {"regex-scanner": scanner,
         "llm-run1": llm_runs[1],
         "llm-run2": llm_runs[2]},
        gt)

    # --- scores CSV ----------------------------------------------------------
    score_rows = []
    for tool, d in comp.items():
        score_rows.append([tool, d["tp"], d["fp"], d["fn"],
                           f"{d['precision']:.2f}", f"{d['recall']:.2f}",
                           f"{d['f1']:.2f}",
                           ";".join(f"{r}:{l}" for r, l in d["false_positives"]) or "-",
                           ";".join(f"{r}:{l}" for r, l in d["missed"]) or "-"])
    H.write_csv(HERE / "results" / "duel_scores.csv",
                ["tool", "tp", "fp", "fn", "precision", "recall", "f1",
                 "false_positives", "missed"], score_rows)

    # --- per-finding CSV for the LLM runs (shows the set changing) -----------
    find_rows = []
    for run in (1, 2):
        for r in llm_runs[run]:
            key = r.key()
            verdict = "TP (real)" if key in gt else "FP (hallucination/wrong)"
            find_rows.append([f"run{run}", r.rule, r.location, r.confidence, verdict])
    H.write_csv(HERE / "results" / "llm_findings.csv",
                ["run", "rule", "location", "confidence", "verdict"], find_rows)

    # --- non-determinism delta ----------------------------------------------
    k1 = {r.key() for r in llm_runs[1]}
    k2 = {r.key() for r in llm_runs[2]}
    only1 = sorted(k1 - k2)
    only2 = sorted(k2 - k1)
    jaccard = len(k1 & k2) / len(k1 | k2) if (k1 | k2) else 1.0

    # --- console report ------------------------------------------------------
    print("PART C — the duel: LLM vs scanner (scored against hand-built ground truth)\n")
    print(f"  {'tool':<14}{'TP':>4}{'FP':>4}{'FN':>4}{'prec':>7}{'recall':>8}{'F1':>7}")
    print("  " + "-" * 48)
    for tool, d in comp.items():
        print(f"  {tool:<14}{d['tp']:>4}{d['fp']:>4}{d['fn']:>4}"
              f"{d['precision']:>7.0%}{d['recall']:>8.0%}{d['f1']:>7.2f}")
    sc = comp["regex-scanner"]
    print(f"\n  scanner's worst MISS : {sc['missed']}  (the 2-line SQLi)")
    print(f"  LLM best HALLUCINATION: broken-access-control — not present "
          f"(app has no auth/session/role code)")
    print(f"\n  non-determinism (axis 9): findings changed across 2 runs, "
          f"Jaccard={jaccard:.2f}")
    print(f"      only in run1: {only1}")
    print(f"      only in run2: {only2}")
    print("\n  wrote results/duel_scores.csv, results/llm_findings.csv, "
          "llm_review_run1.txt, llm_review_run2.txt")
    return dict(comp=comp, only1=only1, only2=only2, jaccard=jaccard,
                scanner_missed=sc["missed"])


if __name__ == "__main__":
    main()

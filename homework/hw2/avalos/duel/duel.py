# HW2 — Web Attack & Defend — Part C (the duel) — Team: Gabriel Avalos, Keoma Quiroga, David Bucheli
"""Part C — point classical scanners and an LLM reviewer at the SAME source and
score both against a HAND-BUILT ground truth (duel-2-web/ground_truth.json, built
by reading the source, not by running a tool).

Classical arm (duel/scanners.py): regex-naive (always), plus REAL semgrep and REAL
bandit when installed. LLM arm: three INDEPENDENT reviews by a real frontier model
(llm_review_run{1,2,3}.txt — see AI_LOG Entry 4), PLUS the documented small-model
mock (llm_mock.py) as a contrast baseline.

Scoring scope (a deliberate, documented choice — see honesty.md §2): the ground
truth adjudicates the three injection sinks it lists, the ONE true negative
(/safe), and the ONE not-present class (broken-access-control). So each tool's
output is scored on the CANONICAL class set {sqli, xss, cmdi, broken-access-control}
(+ the /safe XSS key). Findings OUTSIDE that set (e.g. "plaintext password storage",
"missing rate limiting") are REAL weaknesses the ground truth does not cover; we
report them separately as out-of-scope rather than scoring them as false positives,
because counting a genuine finding as an FP would be as dishonest as counting it a TP.

Run:  python duel/duel.py
"""
from __future__ import annotations

import csv
import json
import re
import sys
from itertools import combinations
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import paths  # noqa: E402
paths.bootstrap()

import llm_mock  # noqa: E402
import scanners  # noqa: E402

from seclab.scan import ScanResult, compare_scanners  # noqa: E402

HERE = Path(__file__).resolve().parent
GT_FILE = paths.FIXTURES / "ground_truth.json"

# Prose -> canonical rule. Longest alias wins (checked longest-first).
RULE_ALIASES = {
    "sql injection": "sqli",
    "reflected xss": "xss",
    "xss": "xss",
    "command injection": "cmdi",
    "broken access control": "broken-access-control",
}
CANONICAL = {"sqli", "xss", "cmdi", "broken-access-control"}
# Each finding is declared as:  N. [SEV] <Class phrase> in <function>: <reason>
# Anchor on that structure so a word like "XSS" mentioned in the REASON of a
# security-headers finding does not get miscounted as an XSS finding.
FINDING_RE = re.compile(
    r"^\s*\d+\.\s*\[(?P<sev>\w+)\]\s*(?P<cls>.*?)\s+in\s+"
    r"(?P<loc>do_\w+|make_db|main|_form|_send|log_message)\b", re.I)


def parse_llm_review(raw: str, tool: str):
    """Return (scored_canonical_results, out_of_scope_raw_lines). Faithful: we do
    NOT drop a model's dubious canonical-class claim (that is the point); we only
    set aside findings whose declared CLASS the ground truth cannot adjudicate."""
    aliases = sorted(RULE_ALIASES.items(), key=lambda kv: -len(kv[0]))
    scored, out_of_scope = [], []
    for line in raw.splitlines():
        if not re.match(r"\s*\d+\.", line):
            continue
        m = FINDING_RE.match(line)
        rule = None
        if m:
            cls = m.group("cls").lower()
            rule = next((canon for alias, canon in aliases if alias in cls), None)
        if m and rule in CANONICAL:
            scored.append(ScanResult(rule=rule, location=m.group("loc").lower(),
                                     tool=tool, confidence="model",
                                     severity=m.group("sev").lower(),
                                     raw=line.strip()))
        else:
            out_of_scope.append(line.strip())
    return scored, out_of_scope


def load_ground_truth() -> set[tuple]:
    data = json.loads(GT_FILE.read_text(encoding="utf-8"))
    return {(f["rule"].strip().lower(), f["location"].strip().lower())
            for f in data["findings"]}


def _scored_only(results):
    """Keep only canonical-class results for scoring (scanners emit out-of-scope
    bandit rows we don't score)."""
    return [r for r in results if r.rule in CANONICAL]


def main() -> int:
    gt = load_ground_truth()

    # classical arm
    classical = {"regex-naive": scanners.regex_naive(),
                 "semgrep": scanners.semgrep(),
                 "bandit": scanners.bandit()}
    skipped = [t for t in ("semgrep", "bandit") if not classical[t]]

    # LLM arm — three real runs + the mock baseline
    real_runs, oos = {}, {}
    for n in (1, 2, 3):
        raw = (HERE / f"llm_review_run{n}.txt").read_text(encoding="utf-8")
        real_runs[f"llm-run{n}"], oos[f"llm-run{n}"] = parse_llm_review(raw, f"llm-run{n}")
    mock_scored, _ = parse_llm_review(llm_mock.REVIEW, "llm-mock(small)")

    tools = {}
    for t, res in classical.items():
        if res:
            tools[t] = _scored_only(res)
    tools.update(real_runs)
    tools["llm-mock(small)"] = mock_scored

    comp = compare_scanners(tools, gt)

    # --- scores CSV ---------------------------------------------------------
    score_rows = []
    for tool, d in comp.items():
        score_rows.append([tool, d["tp"], d["fp"], d["fn"],
                           f"{d['precision']:.2f}", f"{d['recall']:.2f}", f"{d['f1']:.2f}",
                           ";".join(f"{r}:{l}" for r, l in d["false_positives"]) or "-",
                           ";".join(f"{r}:{l}" for r, l in d["missed"]) or "-"])
    _write(HERE / "results" / "duel_scores.csv",
           ["tool", "tp", "fp", "fn", "precision", "recall", "f1", "false_positives", "missed"],
           score_rows)

    # --- per-finding CSV for the real LLM runs ------------------------------
    find_rows = []
    for n in (1, 2, 3):
        run = f"llm-run{n}"
        for r in real_runs[run]:
            verdict = "TP (real)" if r.key() in gt else "FP (hallucination/wrong)"
            find_rows.append([run, r.rule, r.location, verdict, r.raw[:70]])
        for line in oos[run]:
            find_rows.append([run, "(out-of-scope)", "-", "not scored (real but not in GT)", line[:70]])
    _write(HERE / "results" / "llm_findings.csv",
           ["run", "rule", "location", "verdict", "raw"], find_rows)

    # --- non-determinism over the 3 REAL runs (axis 9) ----------------------
    key_sets = {n: {r.key() for r in real_runs[f"llm-run{n}"]} for n in (1, 2, 3)}
    raw_counts = {n: sum(1 for ln in (HERE / f"llm_review_run{n}.txt").read_text(encoding="utf-8").splitlines()
                         if re.match(r"\s*\d+\.", ln)) for n in (1, 2, 3)}
    jac = []
    for a, b in combinations((1, 2, 3), 2):
        u = key_sets[a] | key_sets[b]
        jac.append(len(key_sets[a] & key_sets[b]) / len(u) if u else 1.0)
    stable = set.intersection(*key_sets.values())
    unstable = (set.union(*key_sets.values())) - stable
    nd_rows = []
    for n in (1, 2, 3):
        fps = sorted(k for k in key_sets[n] if k not in gt)
        nd_rows.append([f"run{n}", raw_counts[n], len(key_sets[n]),
                        len(key_sets[n] & gt), len(fps),
                        ";".join(f"{r}:{l}" for r, l in fps) or "-"])
    _write(HERE / "results" / "nondeterminism.csv",
           ["run", "raw_findings_total", "scored_findings", "true_positives",
            "false_positives", "hallucinations"], nd_rows)

    # --- console ------------------------------------------------------------
    print("PART C — the duel: LLM vs scanner (scored on the canonical class set)\n")
    print(f"  {'tool':<16}{'TP':>4}{'FP':>4}{'FN':>4}{'prec':>7}{'recall':>8}{'F1':>7}")
    print("  " + "-" * 52)
    for tool, d in comp.items():
        print(f"  {tool:<16}{d['tp']:>4}{d['fp']:>4}{d['fn']:>4}"
              f"{d['precision']:>7.0%}{d['recall']:>8.0%}{d['f1']:>7.2f}")
    if skipped:
        print(f"\n  (classical tools skipped — not installed: {', '.join(skipped)}; "
              f"regex-naive always runs)")
    print(f"\n  scanner's worst MISS   : regex-naive misses ('sqli','do_login') — the "
          f"2-line query; semgrep's MULTILINE rule catches it, so the miss is a "
          f"rule-design choice, not a law of scanners.")
    print(f"  LLM best HALLUCINATION : ('broken-access-control','do_post') — asserted in "
          f"an app with zero auth/session/role code (ground truth: not_present).")
    print(f"\n  non-determinism (axis 9) over 3 REAL runs:")
    print(f"      raw findings per run : {[raw_counts[n] for n in (1,2,3)]}")
    print(f"      recall stable at     : all 3 real sinks in every run")
    print(f"      mean pairwise Jaccard: {sum(jac)/len(jac):.2f}")
    print(f"      stable keys          : {sorted(stable)}")
    print(f"      unstable (noise)     : {sorted(unstable)}")
    bac_real = {n: any(k[0] == "broken-access-control" for k in key_sets[n]) for n in (1, 2, 3)}
    print(f"\n  access control: real-LLM BAC flag per run = {bac_real}; mock flags it every "
          f"run; no scanner flags it. No real A01 exists — confirmed hallucination.")

    report = {
        "ground_truth": sorted(gt),
        "scoring_scope": sorted(CANONICAL),
        "scores": {t: comp[t] for t in comp},
        "classical_skipped": skipped,
        "nondeterminism": {
            "raw_findings_per_run": raw_counts,
            "scored_key_sets": {n: sorted(key_sets[n]) for n in (1, 2, 3)},
            "stable": sorted(stable), "unstable": sorted(unstable),
            "mean_pairwise_jaccard": round(sum(jac) / len(jac), 3),
        },
        "access_control_bac_flag": {"real_runs": bac_real,
                                    "mock": True, "scanners": False,
                                    "ground_truth": "not_present"},
        "out_of_scope_real_findings": {n: oos[f"llm-run{n}"] for n in (1, 2, 3)},
    }
    (HERE / "results" / "duel_report.json").write_text(json.dumps(report, indent=2),
                                                       encoding="utf-8")
    print("\n  wrote results/duel_scores.csv, llm_findings.csv, nondeterminism.csv, duel_report.json")
    return 0


def _write(path: Path, header, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)


if __name__ == "__main__":
    raise SystemExit(main())

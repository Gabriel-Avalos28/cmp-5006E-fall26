# HW2 — Web Attack & Defend — Part B (Defend, then bypass) — Team: Gabriel Avalos, Keoma Quiroga, David Bucheli
"""Part B — defend the SQLi finding two ways and measure BOTH blades.

We defend SQLi: the most severe Part-A finding (auth bypass + admin-canary exfil).

B1 (NEGATIVE / WAF blocklist, common/waf.py):
  * axis 3  coverage : how many Part-A SQLi payloads it blocks.
  * axis 4  BYPASS   : >=3 same-intent payloads that pass the WAF AND still leak the
                       canary on the real sink (oracle-filtered) — MANDATORY.
  * axis 5  FALSE POS: run the provided benign corpus through it; report the FP rate
                       PER FIELD (login vs search) + a named victim — MANDATORY.

B2 (POSITIVE / parameterization, common/positive_fix.py):
  * re-run every Part-A payload AND every working B1 bypass through the parameterized
    sink; show 0/N leak — a structural guarantee for ANY input (axis 2);
  * prove a LEGIT login still works, so the fix is not "reject everything."

Run:  python defend/defend.py
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import app_harness as H          # noqa: E402
from common import waf as WAFMOD              # noqa: E402
from common.paths import FIXTURES            # noqa: E402

HERE = Path(__file__).resolve().parent


def _leaks(send, text: str) -> bool:
    return H.CANARY in send(text)


def coverage():
    # axis 3: measured on >= 20 distinct payloads (control-scorecard.md requirement),
    # not just the four Part-A payloads the WAF was written against.
    rows, blocked = [], 0
    for p in WAFMOD.COVERAGE_CORPUS:
        u, pw = H.split_sqli(p)
        rule = WAFMOD.first_rule_hit(u) or WAFMOD.first_rule_hit(pw)
        is_blocked = rule is not None
        blocked += is_blocked
        rows.append({"payload": p, "blocked": is_blocked, "rule": rule or "PASSED"})
    return rows, blocked


def bypasses():
    send = H.make_send("sqli", defense=WAFMOD.WAF)   # through the WAF
    rows = []
    for payload, technique in WAFMOD.CANDIDATE_BYPASSES:
        u, pw = H.split_sqli(payload)
        waf_passed = (WAFMOD.first_rule_hit(u) is None) and (WAFMOD.first_rule_hit(pw) is None)
        leaked = _leaks(send, payload) if waf_passed else False
        rows.append({"payload": payload, "technique": technique,
                     "waf_passed": waf_passed, "leaks_canary": leaked,
                     "genuine_bypass": waf_passed and leaked})
    return rows


def false_positives():
    corpus = json.loads((FIXTURES / "benign_traffic.json").read_text(encoding="utf-8"))
    # The SQLi WAF guards the login + search boxes (string inputs). ping_host is a
    # different sink (defended by the allowlist in B2), so it is reported but not
    # counted in the SQLi-WAF denominator — see honesty.md on denominator choice.
    guarded = {"login_username": corpus["login_username"],
               "search_or_name": corpus["search_or_name"]}
    rows, per_field = [], {}
    for field, items in guarded.items():
        blocked_here = 0
        for s in items:
            rule = WAFMOD.first_rule_hit(s)
            rows.append({"field": field, "benign_input": s,
                         "blocked": rule is not None, "rule": rule or ""})
            blocked_here += rule is not None
        per_field[field] = (blocked_here, len(items))
    total = sum(n for _, n in per_field.values())
    blocked = sum(b for b, _ in per_field.values())
    return rows, blocked, total, per_field


def positive_fix():
    send_fixed = H.make_send("sqli", defense=None, fixed=True)
    send_vuln = H.make_send("sqli", defense=None, fixed=False)
    working = [p for p, _ in WAFMOD.CANDIDATE_BYPASSES]
    payloads = WAFMOD.KNOWN_SQLI + working
    rows, vuln_leaks, fix_leaks = [], 0, 0
    for p in payloads:
        on_vuln = _leaks(send_vuln, p)
        on_fix = _leaks(send_fixed, p)
        vuln_leaks += on_vuln
        fix_leaks += on_fix
        rows.append({"payload": p, "leaks_on_vulnerable": on_vuln,
                     "leaks_on_parameterized": on_fix})
    legit_ok = H.CANARY in send_fixed("admin :: s3cr3t")   # real login still works
    return rows, vuln_leaks, fix_leaks, len(payloads), legit_ok


def _write(path: Path, rows: list[dict]):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


def main() -> int:
    cov_rows, blocked = coverage()
    by_rows = bypasses()
    fp_rows, fp_blocked, fp_total, per_field = false_positives()
    b2_rows, vuln_leaks, fix_leaks, n, legit_ok = positive_fix()

    _write(HERE / "results" / "waf_coverage.csv", cov_rows)
    _write(HERE / "results" / "waf_bypasses.csv", by_rows)
    _write(HERE / "results" / "waf_false_positives.csv", fp_rows)
    _write(HERE / "results" / "positive_fix.csv", b2_rows)

    genuine = [r for r in by_rows if r["genuine_bypass"]]
    fp_rate = fp_blocked / fp_total if fp_total else 0.0

    print("PART B — defend, then bypass your own defence\n")
    print(f"  B1 axis 3  coverage  : {blocked}/{len(cov_rows)} distinct SQLi payloads blocked "
          f"({blocked/len(cov_rows):.0%})")
    print(f"  B1 axis 4  BYPASS    : {len(genuine)}/{len(by_rows)} candidates pass the WAF "
          f"AND leak the canary")
    for r in genuine:
        print(f"       BYPASS {r['payload']!r:40} ({r['technique']})")
    print(f"  B1 axis 5  FALSE POS : {fp_blocked}/{fp_total} benign blocked = {fp_rate:.1%}")
    for field, (b, n_f) in per_field.items():
        print(f"       {field:16} {b}/{n_f} blocked")
    victim = next((r for r in fp_rows if r["blocked"]), None)
    if victim:
        print(f"       e.g. blocked legit {victim['field']} {victim['benign_input']!r} "
              f"(rule: {victim['rule']})")
    print(f"\n  B2 positive fix: canary leaks  vulnerable={vuln_leaks}/{n}  "
          f"parameterized={fix_leaks}/{n}")
    print(f"  B2 legitimate admin login still works under the fix: {legit_ok}")
    print(f"  B2 guarantee: input is BOUND AS DATA; the SQL parse tree is fixed before "
          f"any input is seen, so NO input can alter the query structure.")

    summary = {
        "defended_vuln": "SQLi @ do_login (POST /login)",
        "b1_coverage": {"blocked": blocked, "total": len(cov_rows)},
        "b1_genuine_bypasses": len(genuine),
        "b1_bypass_candidates": len(by_rows),
        "b1_false_positive_count": fp_blocked,
        "b1_false_positive_total": fp_total,
        "b1_false_positive_rate": round(fp_rate, 4),
        "b1_false_positive_by_field": {k: list(v) for k, v in per_field.items()},
        "b2_leaks_on_vulnerable": vuln_leaks,
        "b2_leaks_on_parameterized": fix_leaks,
        "b2_payloads_tested": n,
        "b2_legit_login_ok": legit_ok,
        "b2_guarantee": ("For ANY string value of user/pw, the parameterized query's "
                         "structure is fixed at parse time, so no input can change which "
                         "rows are selected — PROVIDED every code path that reaches this "
                         "table uses bound parameters (one remaining string-built query "
                         "would void it). The WAF cannot claim this: it enumerates known-"
                         "bad strings, so any string it did not imagine (block-comment, "
                         "GLOB, inequality) passes."),
    }
    (HERE / "results" / "defend_summary.json").write_text(json.dumps(summary, indent=2),
                                                          encoding="utf-8")
    ok = (len(genuine) >= 3 and fix_leaks == 0 and legit_ok and fp_blocked > 0)
    print(f"\n  wrote results/*.csv + defend_summary.json — {'OK' if ok else 'CHECK'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

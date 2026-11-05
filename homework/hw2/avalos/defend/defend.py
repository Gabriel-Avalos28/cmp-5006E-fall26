# Homework 2 — Web Attack & Defend — Part B (Defend, then bypass) — Team: Gabriel Avalos, Keoma Quiroga, David Bucheli
"""Part B — defend the SQLi finding two ways and measure BOTH blades.

B1 (negative / WAF):
  * coverage on the KNOWN_SQLI payloads (axis 3),
  * >= 3 same-intent BYPASSES that evade the rules AND still leak the canary on
    the real sink, oracle-confirmed (axis 4) — mandatory,
  * false-positive rate on the provided benign corpus (axis 5) — mandatory.

B2 (positive / parameterization):
  * re-run every Part-A payload AND every B1 bypass through the parameterized
    sink; show 0/N leak the canary — a structural guarantee for ANY input (axis 2).

Run:  python defend/defend.py   (writes results/{waf_coverage,waf_bypasses,waf_false_positives,positive_fix}.csv)
"""
from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import _harness as H   # noqa: E402
import waf             # noqa: E402

CANARY = H.canary()


def leaks_canary_on_real_sink(payload: str) -> bool:
    """Sound oracle (seclab discipline): send through the REAL vulnerable /login
    and confirm the admin secret came back — not the payload echoed."""
    return CANARY in H.login_send(payload)


def main():
    H.serve()

    # --- B1.1 coverage on known attacks -------------------------------------
    cov_rows, blocked = [], 0
    for p in waf.KNOWN_SQLI:
        rule = waf.waf_block(p)
        blocked += rule is not None
        cov_rows.append([p, rule or "PASSED", rule is not None])
    H.write_csv(HERE / "results" / "waf_coverage.csv",
                ["payload", "waf_rule_fired", "blocked"], cov_rows)

    # --- B1.2 bypass it (axis 4): keep only WAF-passed AND canary-leaking ----
    by_rows, real_bypasses = [], 0
    for payload, why in waf.CANDIDATE_BYPASSES:
        passed = waf.waf_block(payload) is None
        leaks = leaks_canary_on_real_sink(payload) if passed else False
        genuine = passed and leaks
        real_bypasses += genuine
        by_rows.append([payload, why, passed, leaks, genuine])
    H.write_csv(HERE / "results" / "waf_bypasses.csv",
                ["bypass_payload", "technique", "waf_passed",
                 "leaks_canary_real_sink", "genuine_bypass"], by_rows)

    # --- B1.3 false positives on benign corpus (axis 5) ---------------------
    benign = H.load_benign()
    fp_rows = []
    for inp in benign:
        rule = waf.waf_block(inp)
        if rule is not None:
            fp_rows.append([inp, rule])
    fp_rate = len(fp_rows) / len(benign) if benign else 0.0
    H.write_csv(HERE / "results" / "waf_false_positives.csv",
                ["benign_input_blocked", "waf_rule_fired"], fp_rows)

    # --- B2 positive fix: re-run A payloads + B1 bypasses --------------------
    a_payloads = ["admin' OR 1=1--", "admin' OR 'a'='a'--"]        # Part-A SQLi
    all_payloads = a_payloads + [p for p, _ in waf.CANDIDATE_BYPASSES]
    pos_rows, vuln_leaks, param_leaks = [], 0, 0
    for p in all_payloads:
        on_vuln = leaks_canary_on_real_sink(p)          # the broken sink
        on_param = CANARY in waf.parameterized_login(p, "wrong")   # the fix
        vuln_leaks += on_vuln
        param_leaks += on_param
        pos_rows.append([p, on_vuln, on_param])
    H.write_csv(HERE / "results" / "positive_fix.csv",
                ["payload", "leaks_on_vulnerable_sink", "leaks_on_parameterized"],
                pos_rows)

    # --- console report ------------------------------------------------------
    print("PART B — defend, then bypass your own defence\n")
    print(f"  B1 coverage on known attacks : {blocked}/{len(waf.KNOWN_SQLI)} blocked")
    print(f"  B1 genuine bypasses (axis 4) : {real_bypasses}/{len(waf.CANDIDATE_BYPASSES)}"
          f"  (WAF-passed AND canary-leaking)")
    for r in by_rows:
        print(f"       {'BYPASS ' if r[4] else 'stopped'} {r[0]!r:<34} ({r[1]})")
    print(f"  B1 false positives (axis 5)  : {len(fp_rows)}/{len(benign)} "
          f"legit inputs blocked  (FP rate {fp_rate:.1%})")
    for inp, rule in fp_rows:
        print(f"       [{rule}] {inp!r}")
    print(f"\n  B2 positive fix: canary leaks  vulnerable={vuln_leaks}/{len(all_payloads)}"
          f"   parameterized={param_leaks}/{len(all_payloads)}")
    print(f"  guarantee: parameterized sink leaked the canary {param_leaks} times "
          f"for {len(all_payloads)} hostile inputs.")
    print(f"\n  wrote results/waf_coverage.csv, waf_bypasses.csv, "
          f"waf_false_positives.csv, positive_fix.csv")
    return dict(blocked=blocked, known=len(waf.KNOWN_SQLI),
                real_bypasses=real_bypasses, candidates=len(waf.CANDIDATE_BYPASSES),
                fp=len(fp_rows), benign=len(benign), fp_rate=fp_rate,
                vuln_leaks=vuln_leaks, param_leaks=param_leaks, total=len(all_payloads),
                fp_rows=fp_rows, by_rows=by_rows)


if __name__ == "__main__":
    main()

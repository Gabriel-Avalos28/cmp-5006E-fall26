"""HW3 Part A - attack T1 (vuln-llm): four attacks, each oracle-confirmed, 5 trials.

Team: Gabriel Avalos, Keoma Quiroga, David Bucheli - CMP-5006E Fall 2026, HW3.

    python attack/attack.py

Oracles (all check the CANARY - an effect - never the payload echoed back):
  1 /chat       canary token in the reply
  2 /summarize  canary token in the summary of an attacker-hosted page
  3 /rag        (a) a private-* doc was retrieved without authz   (b) canary in answer
  4 /agent      canary inside an email in the `sent` list (the exfil actually happened)

Each attack set also contains BENIGN CONTROLS that must score 0/5, otherwise the
oracle is not sound.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common.campaign import (TRIALS, run_chat, run_summarize, run_rag, run_agent,   # noqa: E402
                             write_csv, write_json)
from common.corpus import (CHAT, CHAT_BENIGN, INDIRECT, INDIRECT_BENIGN, RAG,       # noqa: E402
                           RAG_BENIGN, AGENT, AGENT_BENIGN)
from common.harness import (Client, target, oracle_rag_private_retrieved,           # noqa: E402
                            oracle_rag_poison_retrieved, SECRET)
from common.paths import ATTACK_RESULTS, TEAM                                              # noqa: E402


def main():
    with target() as t:
        c = Client(t.base_url)
        c.reset()                                   # defense 0, all tools allowed
        backend = c.backend()
        meta = {"backend": backend, "defense_level": 0, "policy": "all-tools",
                "oracle": "canary-in-reply"}
        rows = []

        rows += run_chat(c, CHAT + CHAT_BENIGN, meta=meta)
        rows += run_summarize(c, INDIRECT + INDIRECT_BENIGN, meta=meta)

        # /rag: three oracles per question - private doc retrieved, poisoned doc
        # retrieved (both are the RETRIEVAL-layer effect), and canary in the answer.
        rag_items = RAG + RAG_BENIGN
        for label, oracle in (("retrieval:private-doc", oracle_rag_private_retrieved),
                              ("retrieval:poisoned-doc", oracle_rag_poison_retrieved),
                              ("answer:canary", None)):
            kw = {"oracle": oracle} if oracle else {}
            part = run_rag(c, rag_items, meta=dict(meta, oracle=label), **kw)
            rows += part

        rows += run_agent(c, AGENT + AGENT_BENIGN, meta=dict(meta, oracle="canary-in-sent-email"))

    # ---------------- summary ----------------
    print(f"\nHW3 Part A  -  backend={backend}  trials={TRIALS}\n")
    print(f"{'id':<5}{'surface':<11}{'family':<20}{'k/5':>5}  {'oracle':<24} payload")
    print("-" * 110)
    for r in rows:
        print(f"{r['id']:<5}{r['surface']:<11}{r['family']:<20}{r['k_of_n']:>5}  "
              f"{r['oracle']:<24} {r['payload'][:48]}")

    attack_rows = [r for r in rows if r["family"] != "benign-control"]
    benign_rows = [r for r in rows if r["family"] == "benign-control"]
    nondet = [r for r in rows if not r["deterministic"]]
    print(f"\nbenign controls with a false confirmation: "
          f"{sum(r['successes'] > 0 for r in benign_rows)} of {len(benign_rows)} rows (must be 0)")
    print(f"non-deterministic rows (0 < k < 5): {len(nondet)}  "
          f"{'(mock is deterministic - cannot measure axis 9)' if backend == 'mock' else ''}")

    ATTACK_RESULTS.mkdir(parents=True, exist_ok=True)
    write_csv(ATTACK_RESULTS / "attack_findings.csv", rows)
    write_json(ATTACK_RESULTS / "attack_findings.json",
               {"team": TEAM, "backend": backend, "trials": TRIALS, "canary_prefix": "CANARY-",
                "target": "T1 vuln-llm (labs/vuln-llm/app/vulnllm_app.py)", "rows": rows})
    print(f"\nwrote {ATTACK_RESULTS / 'attack_findings.csv'} (+ .json)")


if __name__ == "__main__":
    main()

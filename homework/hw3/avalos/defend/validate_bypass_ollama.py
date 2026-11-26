"""Per-trial re-run of the B1 bypass set against a REAL model, discarding mock fallbacks.

Team: Gabriel Avalos, Keoma Quiroga, David Bucheli - CMP-5006E Fall 2026, HW3.

Why this exists: the course app falls back to the mock when an Ollama call times out
(60 s) and prefixes the reply with "[backend error: ...]". The mock implements the
spaced/spelled/base64 renderings, so a fallback trial can count as a "bypass" that the
real model never produced. `b1_bypass.csv` only stores ONE sample per row, so it cannot
tell how many of the k successes were fallbacks. This script runs the same payloads,
inspects EVERY trial, and reports k_valid / n_valid with fallback trials excluded.

    HW3_BASE_URL=http://127.0.0.1:8000 HW3_RESULTS_TAG=ollama python defend/validate_bypass_ollama.py

Writes <DEFEND_RESULTS>/b1_bypass_validated.csv. Only meaningful in external mode
against a real model (on the mock there are no fallbacks to exclude).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import corpus as K                                                  # noqa: E402
from common.campaign import TRIALS, run_chat, run_summarize, run_rag, write_csv  # noqa: E402
from common.harness import (Client, target, oracle_literal,                      # noqa: E402
                            oracle_not_literal_but_leaked)
from common.paths import DEFEND_RESULTS                                          # noqa: E402

FALLBACK = "[backend error"


def main():
    rows = []
    with target() as t:
        c = Client(t.base_url)
        backend = c.backend()
        if backend != "ollama":
            print(f"backend={backend}: nothing to validate (no fallbacks on the mock)")

        def tracked(oracle, items, text_of=lambda r: r):
            trials = {}
            id_of = {it[2]: it[0] for it in items}     # payload text -> payload id

            def wrapped(payload, response):
                text = text_of(response)
                text = text if isinstance(text, str) else json.dumps(text)
                fell_back = FALLBACK in text
                hit, ev = oracle(payload, text)
                pid = id_of[getattr(payload, "text", payload)]
                rec = trials.setdefault(pid, {"n": 0, "fallback": 0, "hit_valid": 0, "hit_fallback": 0})
                rec["n"] += 1
                if fell_back:
                    rec["fallback"] += 1
                    rec["hit_fallback"] += int(hit)
                else:
                    rec["hit_valid"] += int(hit)
                return hit, ev
            return wrapped, trials

        plan = []
        for L in (2, 3):
            plan += [(L, "/chat", [(i, e, p, "") for (i, e, p) in K.BYPASS], oracle_not_literal_but_leaked, None)]
            plan += [(L, "/summarize", K.BYPASS_INDIRECT, oracle_not_literal_but_leaked, None)]
            plan += [(L, "/rag", K.BYPASS_RAG, oracle_not_literal_but_leaked, lambda r: r["answer"])]
        plan += [(1, "/chat", K.DELIM_ESCAPE, oracle_literal, None)]
        plan += [(3, "/chat", K.DELIM_ESCAPE_ENCODED, oracle_not_literal_but_leaked, None)]

        for L, surface, items, oracle, text_of in plan:
            c.set_defense(L)
            wrapped, trials = tracked(oracle, items, text_of or (lambda r: r))
            runner = {"/chat": run_chat, "/summarize": run_summarize, "/rag": run_rag}[surface]
            out = runner(c, items, oracle=wrapped, meta={"backend": backend, "defense_level": L})
            for r in out:
                rec = trials.get(r["id"], {"n": 0, "fallback": 0, "hit_valid": 0, "hit_fallback": 0})
                n_valid = rec["n"] - rec["fallback"]
                rows.append({"defense_level": L, "surface": surface, "id": r["id"], "family": r["family"],
                             "trials": rec["n"], "fallback_trials": rec["fallback"],
                             "valid_trials": n_valid, "bypass_valid": rec["hit_valid"],
                             "k_valid_of_n_valid": f"{rec['hit_valid']}/{n_valid}",
                             "bypass_in_fallback_trials": rec["hit_fallback"], "backend": backend})
        c.set_defense(0)

    write_csv(DEFEND_RESULTS / "b1_bypass_validated.csv", rows)
    fb = sum(r["fallback_trials"] for r in rows)
    print(f"backend={backend}  trials={TRIALS}  fallback trials excluded: {fb}")
    for r in rows:
        print(f"  L{r['defense_level']} {r['surface']:<11}{r['id']:<5}{r['family']:<22}"
              f"real {r['k_valid_of_n_valid']:>5}   (fallbacks: {r['fallback_trials']})")
    print(f"wrote {DEFEND_RESULTS / 'b1_bypass_validated.csv'}")


if __name__ == "__main__":
    main()

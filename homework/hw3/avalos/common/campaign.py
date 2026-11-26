"""Run a payload set against one surface N times and return flat result rows.

Team: Gabriel Avalos, Keoma Quiroga, David Bucheli - CMP-5006E Fall 2026, HW3.

Thin layer over the course's `seclab.attack.run_payloads` (so the oracle discipline is
the course's own) that also records a sample reply per payload for the evidence files.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

from .harness import (Client, oracle_literal, oracle_rag_answer, oracle_agent_exfil,
                      oracle_rag_private_retrieved, oracle_rag_poison_retrieved, page_server)
from .paths import setup_sys_path

setup_sys_path()
from seclab.attack import Payload, run_payloads          # noqa: E402

TRIALS = 5          # homework: reliability over >= 5 trials


def _rows(surface, items, findings, samples, meta, extra=None):
    rows = []
    for (item, f) in zip(items, findings):
        pid, family, text = item[0], item[1], item[2]
        row = {
            "surface": surface, "id": pid, "family": family,
            "payload": text.replace("\n", " "),
            "trials": f.trials, "successes": f.successes,
            "k_of_n": f"{f.successes}/{f.trials}",
            "deterministic": f.deterministic,
            "confirmed": f.confirmed,
            "evidence": f.evidence,
            "sample_reply": samples.get(pid, ""),
        }
        row.update(meta)
        if extra:
            row.update(extra(pid))
        rows.append(row)
    return rows


def _run(items, send, oracle, trials, text_of=lambda it: it[2]):
    """items -> Payloads; `send` receives the payload text; remembers the last reply."""
    samples = {}
    by_text = {}
    payloads = []
    for it in items:
        p = Payload(text_of(it), intent=it[-1] if isinstance(it[-1], str) else "", family=it[1])
        by_text.setdefault(p.text, it[0])
        payloads.append(p)

    def wrapped(text):
        r = send(text)
        samples[by_text[text]] = (r if isinstance(r, str) else json.dumps(r))[:240]
        return r

    return run_payloads(payloads, send=wrapped, oracle=oracle, trials=trials), samples


# --- one function per surface ------------------------------------------------
def run_chat(c: Client, items, trials=TRIALS, oracle=oracle_literal, meta=None):
    f, s = _run(items, c.chat, oracle, trials)
    return _rows("/chat", items, f, s, meta or {})


def run_summarize(c: Client, items, trials=TRIALS, oracle=oracle_literal, meta=None):
    """items: (id, family, path, html, note). Starts the attacker's page server."""
    pages = {it[2]: it[3] for it in items}
    with page_server(pages) as base:
        f, s = _run(items, lambda path: c.summarize_url(base + path), oracle, trials,
                    text_of=lambda it: it[2])
    # the 'payload' column is the page content (that is the real payload)
    rows = _rows("/summarize", items, f, s, meta or {})
    for r, it in zip(rows, items):
        r["payload"] = f"GET {it[2]} -> {it[3]}"
    return rows


def run_rag(c: Client, items, trials=TRIALS, oracle=oracle_rag_answer, meta=None):
    f, s = _run(items, c.rag, oracle, trials)
    return _rows("/rag", items, f, s, meta or {})


def run_agent(c: Client, items, trials=TRIALS, oracle=oracle_agent_exfil, meta=None):
    f, s = _run(items, c.agent, oracle, trials)
    return _rows("/agent", items, f, s, meta or {})


# --- result writers ------------------------------------------------------------
def write_csv(path: Path, rows: list[dict]):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    keys = []
    for r in rows:
        for k in r:
            if k not in keys:
                keys.append(k)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=keys)
        w.writeheader()
        w.writerows(rows)


def write_json(path: Path, obj):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2, ensure_ascii=False)

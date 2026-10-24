# Homework 1 — Crypto & Protocols

**Team:** Gabriel Avalos · Keoma Quiroga · David Bucheli  
**Submitted by:** Gabriel Avalos (`homework/hw1/avalos/`)  
**Course:** CMP-5006E · Homework 1 — Crypto & Protocols

This is Gabriel Avalos's individual submission of the team's work. Each team
member submits the same work from their own folder (`homework/hw1/quiroga/`,
`homework/hw1/bucheli/`).

## Contents

| Part | File | What it contains |
|---|---|---|
| **A — Breaks (55 %)** | [`breaks/README.md`](breaks/README.md) | All six deployments broken, each with the named assumption, the recovered artifact, misuse vs. primitive, and reliability |
| | [`breaks/break1_reused_pad.py`](breaks/break1_reused_pad.py) … [`breaks/break6_timing.py`](breaks/break6_timing.py) | One reproducible script per break |
| | [`breaks/output/`](breaks/output/) | The exact output of our runs |
| **B — SECS design (35 %)** | [`secs-design.md`](secs-design.md) | Protocol design, message flow with trust boundaries, and an axis-2 guarantee + condition for every goal |
| **C — Honesty (10 %)** | [`honesty.md`](honesty.md) | "Where our breaks or design might be unfair" |
| AI policy | [`AI_LOG.md`](AI_LOG.md) | How AI assistants were used |

## How to run the breaks

```bash
cd breaks
python3 break1_reused_pad.py        # ...and so on for break2..break5
python3 break6_timing.py            # ~1.5 min (statistical)
```

`breaks/duel1_targets.py` is the provided target module, copied unchanged so the
scripts run from this folder.

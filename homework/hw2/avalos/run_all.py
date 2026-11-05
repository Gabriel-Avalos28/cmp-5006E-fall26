# Homework 2 — Web Attack & Defend — reproduce everything — Team: Gabriel Avalos, Keoma Quiroga, David Bucheli
"""Run Parts A, B and C end-to-end, regenerating every result CSV and transcript.

    python run_all.py

Laptop-only, 127.0.0.1 only, synthetic data only. See
``../../resources/ethics-and-scope.md``.
"""
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPTS = [HERE / "attack" / "attack.py",
           HERE / "defend" / "defend.py",
           HERE / "duel" / "duel.py"]

if __name__ == "__main__":
    for s in SCRIPTS:
        print("=" * 70)
        rc = subprocess.run([sys.executable, str(s)]).returncode
        if rc != 0:
            sys.exit(rc)
        print()
    print("All parts complete. Results under attack/results, defend/results, duel/results.")

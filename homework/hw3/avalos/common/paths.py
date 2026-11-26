"""Locate the course repo root so every script runs from anywhere (portable).

Team: Gabriel Avalos, Keoma Quiroga, David Bucheli - CMP-5006E Fall 2026, HW3.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

HW_DIR = Path(__file__).resolve().parents[1]          # homework/hw3/avalos


def _find_root() -> Path:
    for parent in HW_DIR.parents:
        if (parent / "seclab" / "attack.py").exists() and (parent / "labs" / "vuln-llm").exists():
            return parent
    raise RuntimeError("could not find the course repo root (seclab/ + labs/vuln-llm/)")


ROOT = _find_root()
APP_DIR = ROOT / "labs" / "vuln-llm" / "app"
TEAM = ["Gabriel Avalos", "Keoma Quiroga", "David Bucheli"]

# HW3_RESULTS_TAG=ollama -> results go to results_ollama/ so a real-model run never
# overwrites the committed mock results.
_TAG = re.sub(r"[^A-Za-z0-9_-]", "", os.environ.get("HW3_RESULTS_TAG", ""))
RESULTS_NAME = f"results_{_TAG}" if _TAG else "results"
ATTACK_RESULTS = HW_DIR / "attack" / RESULTS_NAME
DEFEND_RESULTS = HW_DIR / "defend" / RESULTS_NAME


def setup_sys_path() -> None:
    """Make `seclab` and the vuln-llm app importable."""
    for p in (str(ROOT), str(APP_DIR)):
        if p not in sys.path:
            sys.path.insert(0, p)

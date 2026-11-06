# HW2 — Web Attack & Defend — Team: Gabriel Avalos, Keoma Quiroga, David Bucheli
"""Locate the course repo root so every script here can import ``seclab`` and the
lab app ``vulnweb_app``, no matter where the repo is checked out.

We walk upward until we find a directory that contains BOTH the ``seclab/`` package
and ``labs/vuln-web/app/vulnweb_app.py`` — so the submission is portable and hard-
codes no absolute path.
"""
from __future__ import annotations

import sys
from pathlib import Path


def repo_root() -> Path:
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "seclab").is_dir() and \
           (parent / "labs" / "vuln-web" / "app" / "vulnweb_app.py").is_file():
            return parent
    raise RuntimeError(
        "could not locate the course repo root (needs seclab/ and "
        "labs/vuln-web/app/vulnweb_app.py above this file)")


ROOT = repo_root()
APP_DIR = ROOT / "labs" / "vuln-web" / "app"
SUBMISSION = Path(__file__).resolve().parents[1]          # .../hw2/avalos
FIXTURES = ROOT / "homework" / "hw2" / "duel-2-web"       # instructor fixtures


def bootstrap() -> None:
    """Put seclab (repo root) and the lab app dir on sys.path, once."""
    for p in (str(ROOT), str(APP_DIR)):
        if p not in sys.path:
            sys.path.insert(0, p)

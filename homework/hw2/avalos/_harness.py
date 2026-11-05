# Homework 2 — Web Attack & Defend — Team: Gabriel Avalos, Keoma Quiroga, David Bucheli
"""Shared, laptop-only harness for HW2 (no Docker, no Ollama).

Brings the course's ``vuln-web`` app up IN-PROCESS on 127.0.0.1 and exposes the
senders + fixtures the three parts need. This mirrors the GIVEN week-6/7
harnesses, kept here so the whole ``homework/hw2/avalos/`` tree runs on its own:

    python attack/attack.py
    python defend/defend.py
    python duel/duel.py
    python run_all.py           # all three, regenerating every result file

Scope: 127.0.0.1 only, synthetic data only. See
``../../resources/ethics-and-scope.md``. We attack only this app, which we run.
"""
from __future__ import annotations

import json
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

# --- locate the course root (the dir that contains ``seclab/``) --------------
ROOT = Path(__file__).resolve()
while ROOT != ROOT.parent and not (ROOT / "seclab").is_dir():
    ROOT = ROOT.parent
APP_DIR = ROOT / "labs" / "vuln-web" / "app"
FIXTURES = ROOT / "homework" / "hw2" / "duel-2-web"
GROUND_TRUTH_FILE = FIXTURES / "ground_truth.json"
BENIGN_FILE = FIXTURES / "benign_traffic.json"

for p in (str(ROOT), str(APP_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

import vulnweb_app as vulnweb  # noqa: E402  (the target under test, run locally)

# The exact source a scanner/LLM reads in Part C — the same file we attack in A.
SOURCE = (APP_DIR / "vulnweb_app.py").read_text()

_started = False
_lock = threading.Lock()
PORT = 8074
BASE = f"http://127.0.0.1:{PORT}"


def serve() -> str:
    """Start vuln-web in-process (idempotent). Fresh in-memory DB => the SQLi
    canary row is deterministic every run."""
    global _started
    with _lock:
        if not _started:
            vulnweb.DB = vulnweb.make_db()
            srv = ThreadingHTTPServer(("127.0.0.1", PORT), vulnweb.Handler)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            time.sleep(0.2)
            _started = True
    return BASE


def get(path: str) -> str:
    serve()
    with urllib.request.urlopen(BASE + path, timeout=10) as r:
        return r.read().decode()


def post(path: str, obj: dict) -> str:
    serve()
    req = urllib.request.Request(
        BASE + path, data=json.dumps(obj).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return r.read().decode()


# payload -> response string, one per sink
def login_send(user_payload: str) -> str:
    return post("/login", {"user": user_payload, "pw": "x"})


def reflect_send(name_payload: str) -> str:
    return get("/?name=" + urllib.parse.quote(name_payload))


def reflect_safe_send(name_payload: str) -> str:
    return get("/safe?name=" + urllib.parse.quote(name_payload))


def ping_send(host_payload: str) -> str:
    return post("/ping", {"host": host_payload})


def canary() -> str:
    return vulnweb.CANARY_SECRET


def load_ground_truth() -> set[tuple]:
    data = json.loads(GROUND_TRUTH_FILE.read_text())
    return {(f["rule"].strip().lower(), f["location"].strip().lower())
            for f in data["findings"]}


def load_benign() -> list[str]:
    data = json.loads(BENIGN_FILE.read_text())
    out: list[str] = []
    for field, items in data.items():
        if field.startswith("_"):
            continue
        out.extend(items)
    return out


def write_csv(path: Path, header: list[str], rows: list[list]) -> None:
    import csv
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)

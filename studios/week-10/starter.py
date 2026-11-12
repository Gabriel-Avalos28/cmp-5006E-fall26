"""Week 10 studio — starter (RAG exfil, confused-deputy exfil, containment).

Fill in the THREE functions marked TODO below. Then run
``python3 test_studio.py``. All provided tests must pass — INCLUDING the
guarantee test that watches least privilege *contain* an attack it cannot
*prevent*: WITHOUT your policy the confused-deputy chain exfiltrates the secret;
WITH your dispatcher-enforced allow-list the SAME injection still lands in the
model (coverage stays 0%) yet nothing leaves the building (100% containment).

Nothing you write stops the model from being fooled. Week 9 established that
prompt injection has no clean fix. This week's win is *architecture*: least
privilege bounds what a fooled model is able to DO, and — unlike an output
filter — that is a guarantee you can state, because it is enforced in Python the
model cannot talk past.

Everything runs on your machine. No Docker, no Ollama, no GPU: the app is
imported in-process and forced onto its deterministic mock backend (see the
GIVEN wiring below). See ../../resources/ethics-and-scope.md.
"""
from __future__ import annotations

import json
import sys
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

# ---------------------------------------------------------------------------
# GIVEN — app wiring. You do NOT edit this block.
#
# Find the course root (the dir that holds `seclab/`), put the vuln-llm app on
# the import path, import it, force the DETERMINISTIC MOCK backend by pointing
# OLLAMA at a dead port, and serve it in-process on localhost. This is the same
# laptop-only path the week-10 notebook uses when Docker is unavailable.
# ---------------------------------------------------------------------------
ROOT = Path(__file__).resolve()
while ROOT != ROOT.parent and not (ROOT / "seclab").is_dir():
    ROOT = ROOT.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "labs" / "vuln-llm" / "app"))

import vulnllm_app as vuln  # noqa: E402

vuln.OLLAMA_URL = "http://127.0.0.1:9"      # unreachable -> forces the mock
_srv = ThreadingHTTPServer(("127.0.0.1", 0), vuln.Handler)   # port 0 = pick free
_PORT = _srv.server_address[1]
threading.Thread(target=_srv.serve_forever, daemon=True).start()
time.sleep(0.2)
BASE = f"http://127.0.0.1:{_PORT}"
CANARY = "CANARY-"      # the oracle looks for this; a real leak contains it


def post(path: str, obj: dict) -> dict:
    req = urllib.request.Request(BASE + path, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)


def get(path: str) -> dict:
    with urllib.request.urlopen(BASE + path, timeout=10) as r:
        return json.load(r)


# ===========================================================================
# TODO 1 — RAG exfil: leak the private-vip document via the unscoped retriever.
# ===========================================================================
def rag_exfil_question() -> str:
    """Return a question for POST /rag that makes the UNSCOPED retriever surface
    the ``private-vip`` document and leak its canary into the answer.

    Why this works: /rag retrieves the top-k documents by keyword overlap and
    stuffs them into the model's context — with NO notion of who is asking. That
    is Broken Access Control (week 8's OWASP #1) wearing an AI costume. Ask about
    the thing only the private note mentions (its *master reconciliation code*)
    and the retriever hands it over.

    Your question must (a) put ``private-vip`` in the ``retrieved`` list, and
    (b) cause the canary (``CANARY-``) to appear in ``answer``. The provided test
    confirms the ACTUAL leak with a canary oracle — a reflected question string
    would not count.
    """
    # TODO: return a question that targets the private-vip note's content words.
    raise NotImplementedError


# ===========================================================================
# TODO 2 — Confused deputy: chain lookup_balance -> send_email to exfiltrate.
# ===========================================================================
def confused_deputy_request() -> str:
    """Return a request for POST /agent that talks the tool-calling agent into
    chaining ``lookup_balance`` -> ``send_email``, emailing the secret to an
    attacker address.

    The agent has legitimate access to those tools; YOU do not. Talking it into
    using its own authority on your behalf is the confused deputy (Hardy, 1988) /
    OWASP LLM06 Excessive Agency. With the default (all-tools) policy both calls
    EXECUTE and the secret lands in the outbox.

    Your request must make ``sent`` non-empty with the canary in the email body.
    The provided test confirms the real exfil (email sent, canary in the body),
    not a reflected string.
    """
    # TODO: return a request that triggers the send/forward exfil intent, e.g.
    #       naming an attacker recipient to receive the balance.
    raise NotImplementedError


# ===========================================================================
# TODO 3 — Least privilege: the minimal allow-list you POST to /policy.
# ===========================================================================
def least_privilege_allowlist() -> list[str]:
    """Return the smallest tool allow-list an FAQ agent needs. This is the
    week-10 defense: it is enforced in the DISPATCHER (Python), not in a prompt,
    so it is a guarantee you can state — the agent CANNOT invoke a tool outside
    this list, regardless of what the model is convinced to do.

    The three tools are ``get_faq`` (harmless), ``lookup_balance`` (returns the
    secret), and ``send_email`` (exfil-capable). An FAQ agent needs exactly one
    of them. Do NOT include a tool the task never legitimately uses — that is the
    whole point of least privilege (and axis-5 shows an over-narrow policy has a
    false-positive cost too, so pick the *minimum that still works*).
    """
    # TODO: return the minimal allow-list (a subset of the three tool names).
    raise NotImplementedError


if __name__ == "__main__":
    print(f"vuln-llm mock up at {BASE}  backend={get('/health')['backend']}\n")

    try:
        q = rag_exfil_question()
        r = post("/rag", {"question": q})
        print(f"RAG   retrieved={r['retrieved']}  leaked={CANARY in r['answer']}")
    except NotImplementedError:
        print("RAG   rag_exfil_question: not implemented yet")

    try:
        post("/policy", {"allow": get("/policy")["all_tools"]})   # default: wide open
        r = post("/agent", {"request": confused_deputy_request()})
        print(f"AGENT sent={len(r['sent'])} email(s)  "
              f"leaked={bool(r['sent']) and CANARY in r['sent'][0]['body']}")
    except NotImplementedError:
        print("AGENT confused_deputy_request: not implemented yet")

    try:
        allow = least_privilege_allowlist()
        post("/policy", {"allow": allow})
        r = post("/agent", {"request": confused_deputy_request()})
        planned = [s["tool"] for s in r["transcript"]]
        print(f"POLICY allow={allow}  planned={planned}  sent={r['sent']}")
    except NotImplementedError:
        print("POLICY least_privilege_allowlist: not implemented yet")

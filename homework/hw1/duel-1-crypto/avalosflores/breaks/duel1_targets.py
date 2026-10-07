"""Duel 1 — six deliberately flawed crypto/protocol deployments.

CMP-5006, weeks 1-5. Break at least four (>= 1 per tier), confirm each with a
recovered artifact, and name the assumption behind it. Then design the SECS system
(see ../duel-1-crypto.md).

Everything here is stdlib-only and deterministic (fixed SEED), so your break is
reproducible and the grader's key matches. Read the code: every flaw is intentional
and marked `# FLAW`. You attack these functions' OUTPUTS — you do not get the keys.

    python duel1_targets.py            # prints the public artifacts you attack
    python duel1_targets.py --check    # instructor: verify the solution key

Tier 1 (mode/cipher misuse): reused_pad, ecb_store, ctr_log
Tier 2 (integrity/key misuse): token_mac, keygen_fleet, timing_compare
"""

from __future__ import annotations

import hashlib
import sys

import random
SEED = 20250807                            # fixed so breaks are reproducible
_rng = random.Random(SEED)


def _xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# ===========================================================================
# TIER 1 — cipher & mode misuse
# ===========================================================================

# --- #1  reused_pad : a "one-time" pad reused across every message ----------
_PAD_KEY = bytes(_rng.randrange(256) for _ in range(200))

def reused_pad_ciphertexts() -> dict[str, str]:
    """FLAW: the same pad encrypts every message → it's a two-time (n-time) pad.

    Returns hex ciphertexts. Recover TARGET's plaintext by crib-dragging against
    the others (all are English). You never see _PAD_KEY.
    """
    messages = [
        b"meet me at the north gate at nine tonight and bring the documents",
        b"the quarterly revenue numbers must not leave this room under any case",
        b"remember to rotate the encryption keys every ninety days without fail",
        b"the launch authorization code will be delivered by separate courier ok",  # TARGET
    ]
    return {f"msg{i}": _xor(m, _PAD_KEY[:len(m)]).hex() for i, m in enumerate(messages)}

# --- #2  ecb_store : records encrypted with ECB, structure leaks ------------
_ECB_KEY = bytes(_rng.randrange(256) for _ in range(16))
_BS = 4     # block size for the stand-in cipher

def _block_cipher(block: bytes, key: bytes) -> bytes:
    # Deterministic keyed map on a block: identical block -> identical output.
    return hashlib.sha256(key + block).digest()[:len(block)]

def ecb_store_records() -> list[str]:
    """FLAW: ECB mode — identical plaintext blocks give identical ciphertext.

    Each record is 'name:role:dept' padded per 4-byte block. Two employees share a
    role; the repeated ciphertext block reveals it. Infer who is an 'admn'.
    """
    records = [
        b"alic:admn:engr",
        b"bob0:user:sale",
        b"carl:admn:engr",   # same role+dept blocks as alice
        b"dave:user:mktg",
    ]
    out = []
    for r in records:
        r = r + bytes((-len(r)) % _BS)
        out.append(b"".join(_block_cipher(r[i:i+_BS], _ECB_KEY)
                            for i in range(0, len(r), _BS)).hex())
    return out

# --- #3  ctr_log : AES-CTR audit log that reuses the nonce ------------------
_CTR_KEY = bytes(_rng.randrange(256) for _ in range(16))
_CTR_NONCE = bytes(_rng.randrange(256) for _ in range(8))     # FLAW: reused for every entry

def _ctr_keystream(key: bytes, nonce: bytes, n: int) -> bytes:
    ks, ctr = b"", 0
    while len(ks) < n:
        ks += hashlib.sha256(key + nonce + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    return ks[:n]

def ctr_log_entries() -> dict[str, str]:
    """FLAW: the nonce is reused across entries → C_i ⊕ C_j = P_i ⊕ P_j.

    Recover TARGET (a known-format log line) by crib-dragging the shared structure.
    """
    entries = [
        b"2025-03-01 12:00 user=alice action=login result=success from=10.0.0.5",
        b"2025-03-01 12:04 user=bob00 action=login result=failure from=10.0.0.9",
        b"2025-03-01 12:09 user=admin action=export result=success from=10.0.0.2",  # TARGET
    ]
    return {f"log{i}": _xor(e, _ctr_keystream(_CTR_KEY, _CTR_NONCE, len(e))).hex()
            for i, e in enumerate(entries)}


# ===========================================================================
# TIER 2 — integrity & key misuse
# ===========================================================================

# --- #4  token_mac : SHA256(secret || data) session token -------------------
_MAC_SECRET = bytes(_rng.randrange(256) for _ in range(9))    # you don't know this OR its length... but len is guessable

def _md_compress(state: int, block: bytes) -> int:
    s = state
    for b in block:
        s = ((s * 31) + b) & 0xFFFFFFFF
    return s

def _md_hash(msg: bytes, iv: int = 0x12345678) -> int:
    msg = msg + bytes((-len(msg)) % 4)      # simplified MD padding
    s = iv
    for i in range(0, len(msg), 4):
        s = _md_compress(s, msg[i:i+4])
    return s

def issue_token(user: bytes = b"alice", role: bytes = b"user") -> dict:
    """FLAW: tag = H(secret || data) with a Merkle-Damgard hash → length-extendable.

    Returns a valid (data, tag). Forge a tag for data extended with
    '&role=admin' WITHOUT the secret. The hash is _md_hash; secret length is 9.
    """
    data = b"user=" + user + b"&role=" + role
    return {"data": data.decode(), "tag": _md_hash(_MAC_SECRET + data)}

def verify_token(data: bytes, tag: int) -> bool:
    """The server's check — use it to confirm your forgery validates."""
    return _md_hash(_MAC_SECRET + data) == tag

# --- #5  keygen_fleet : RSA keys from a low-entropy device fleet ------------
def _egcd(a, b):
    if b == 0:
        return a, 1, 0
    g, x, y = _egcd(b, a % b)
    return g, y, x - (a // b) * y

def _inv(a, m):
    return _egcd(a, m)[1] % m

def _prime(bits, rng):
    while True:
        x = rng.getrandbits(bits) | 1 | (1 << (bits - 1))
        if pow(2, x - 1, x) == 1 and all(x % s for s in (3, 5, 7, 11, 13, 17, 19)):
            return x

def keygen_fleet() -> dict:
    """FLAW: low entropy at boot → one prime is reused across two devices.

    Returns the PUBLIC moduli/exponents for four devices. Two share a prime.
    Find the pair with gcd, factor, and recover a private key. No private data given.
    """
    frng = random.Random(1000)              # the fleet's weak PRNG
    shared = _prime(64, frng)               # reused because entropy was low
    p = [shared, _prime(64, frng), shared, _prime(64, frng)]   # devices 0 & 2 share
    q = [_prime(64, frng) for _ in range(4)]
    e = 65537
    devices = {}
    for i in range(4):
        n = p[i] * q[i]
        devices[f"device{i}"] = {"n": n, "e": e}
    return devices

# --- #6  timing_compare : early-exit secret comparison ----------------------
_TIMING_SECRET = bytes(_rng.randrange(256) for _ in range(4))

def timing_compare(guess: bytes) -> bool:
    """FLAW: returns at the first mismatched byte → duration leaks prefix length.

    Recover _TIMING_SECRET (4 bytes) by timing this function over many trials.
    The per-byte work is amplified so the signal is measurable in Python.
    """
    if len(guess) != len(_TIMING_SECRET):
        return False
    for x, y in zip(guess, _TIMING_SECRET):
        if x != y:
            return False
        for _ in range(4000):               # amplify so timing is measurable
            pass
    return True


# ===========================================================================
# Public interface — what students see
# ===========================================================================
def public_artifacts() -> dict:
    return {
        "1_reused_pad": reused_pad_ciphertexts(),
        "2_ecb_store": ecb_store_records(),
        "3_ctr_log": ctr_log_entries(),
        "4_token": issue_token(),
        "5_keygen_fleet": keygen_fleet(),
        "6_timing": "call timing_compare(guess) and measure its runtime",
    }


def _check():
    """Instructor self-test: confirm every intended break yields its artifact."""
    import math, time, statistics
    ok = []

    # #1 two-time pad: crib-drag "the " to confirm we can read the target
    cts = {k: bytes.fromhex(v) for k, v in reused_pad_ciphertexts().items()}
    # if the pad is truly reused, ct0 ^ ct3 == p0 ^ p3
    p0 = b"meet me at the north gate at nine tonight and bring the documents"
    x03 = _xor(cts["msg0"], cts["msg3"])
    target3 = _xor(x03, p0)                 # knowing p0 as a crib recovers p3
    ok.append(("#1 reused_pad", target3.startswith(b"the launch authorization")))

    # #2 ECB: alice and carl share the role+dept blocks
    recs = ecb_store_records()
    a_blocks = [recs[0][i:i+8] for i in range(0, len(recs[0]), 8)]
    c_blocks = [recs[2][i:i+8] for i in range(0, len(recs[2]), 8)]
    ok.append(("#2 ecb_store", a_blocks[1:] == c_blocks[1:]))   # role+dept blocks match

    # #3 CTR nonce reuse
    logs = {k: bytes.fromhex(v) for k, v in ctr_log_entries().items()}
    p1 = b"2025-03-01 12:04 user=bob00 action=login result=failure from=10.0.0.9"
    x12 = _xor(logs["log1"], logs["log2"])
    target_log = _xor(x12, p1)
    ok.append(("#3 ctr_log", b"user=admin action=export" in target_log))

    # #4 length extension
    t = issue_token()
    data, tag = t["data"].encode(), t["tag"]
    seclen = 9
    total = seclen + len(data)
    pad = bytes((-total) % 4)
    ext = b"&role=admin"
    forged_msg = data + pad + ext
    forged_tag = _md_hash(ext, iv=tag)
    ok.append(("#4 token_mac", verify_token(forged_msg, forged_tag) and b"role=admin" in forged_msg))

    # #5 shared factors
    dev = keygen_fleet()
    ns = {k: v["n"] for k, v in dev.items()}
    found = False
    keys = list(ns)
    for i in range(len(keys)):
        for j in range(i+1, len(keys)):
            g = math.gcd(ns[keys[i]], ns[keys[j]])
            if g > 1:
                # recover a private key for device i
                n = ns[keys[i]]; p = g; q = n // g
                phi = (p-1)*(q-1); d = _inv(65537, phi)
                # confirm d works: (m^e)^d == m
                m = 42; c = pow(m, 65537, n)
                found = pow(c, d, n) == m
    ok.append(("#5 keygen_fleet", found))

    # #6 timing (short run for the self-test)
    def med(guess, trials=41):
        ts = []
        for _ in range(trials):
            s = time.perf_counter(); timing_compare(guess); ts.append(time.perf_counter()-s)
        return statistics.median(ts)
    rec = bytearray()
    for pos in range(len(_TIMING_SECRET)):
        best_b, best_t = 0, -1.0
        for b in range(256):
            g = bytes(rec) + bytes([b]) + bytes(len(_TIMING_SECRET)-pos-1)
            tm = med(g)
            if tm > best_t:
                best_t, best_b = tm, b
        rec.append(best_b)
    ok.append(("#6 timing_compare", bytes(rec) == _TIMING_SECRET))

    print("Duel 1 solution self-check:")
    for name, passed in ok:
        print(f"  [{'OK ' if passed else 'FAIL'}] {name}")
    return all(p for _, p in ok)


if __name__ == "__main__":
    if "--check" in sys.argv:
        sys.exit(0 if _check() else 1)
    import json
    print(json.dumps(public_artifacts(), indent=2, default=str))

#!/usr/bin/env python3
"""Break #3 -- ctr_log : audit log in a CTR-style stream cipher with ONE nonce for all entries.

Assumption broken: "CTR mode is secure" -- but only if (key, nonce) is never reused.
With the nonce fixed, entry i uses the SAME keystream KS, so
        C_i xor C_j = (P_i xor KS) xor (P_j xor KS) = P_i xor P_j.

Stage A (ciphertext only): the XOR of two entries cancels the keystream; where the
         plaintexts agree the XOR is 0, and a dictionary "crib" for a field gives the
         same field in the other entries.
Stage B (known plaintext): the attacker is the low-privileged user 'bob00'. His own
         failed login is logged, and he knows what it says. That gives the keystream
         (KS = C1 xor P1) and with it every other entry, completely.

We never touch _CTR_KEY / _CTR_NONCE.   Run:  python3 break3_ctr_nonce.py
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from duel1_targets import ctr_log_entries


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


logs = [bytes.fromhex(v) for v in ctr_log_entries().values()]     # log0, log1, log2(TARGET)
print("Ciphertext lengths:", [len(c) for c in logs])

# ------------------------------------------------------------------ Stage A
x01, x02 = xor(logs[0], logs[1]), xor(logs[0], logs[2])
print("\n[A1] C0 xor C1 (= P0 xor P1) is zero over the shared header, so the keystream is reused:")
print("     ", x01.hex())
nz = [i for i, v in enumerate(x01) if v]
print("      non-zero at byte positions:", nz)
print("      -> entries 0 and 1 differ only in the minute digit, the 5-char user name,")
print("         the 7-char result field and the last IP digit; same date/action/IP prefix.")

# Crib-drag with the *log format* 'DATE HH:MM user=NAME action=ACT result=RES from=IP':
# the user name sits at bytes 22..26 in every entry. Try a list of plausible user names:
USERS = ["alice", "bob00", "admin", "carol", "dave0", "root0", "guest", "eve00", "mallo",
         "frank", "grace", "heidi", "oscar", "peggy", "trent", "user1", "test0"]
print("\n[A2] Crib-dragging the user-name field (bytes 22..26) with a name list.")
print("     A name w for entry 0 is consistent only if  w xor x01 and w xor x02  are also names:")
found = []
for w in USERS:
    n1 = bytes(a ^ b for a, b in zip(w.encode(), x01[22:27])).decode("latin1")
    n2 = bytes(a ^ b for a, b in zip(w.encode(), x02[22:27])).decode("latin1")
    if n1 in USERS and n2 in USERS:
        found.append((w, n1, n2))
        print(f"       entry0 user={w!r:8} entry1 user={n1!r:8} entry2 user={n2!r:8}")
print("     Consistent triples found:", len(found),
      "-> ciphertext-only already reveals that the TARGET entry is for user=" + found[0][2])

# result field (bytes 48..54 in entries 0 and 1; same alignment because actions have equal length)
RES = ["success", "failure"]
print("\n[A3] Same trick on the 7-char result field of entries 0/1 (bytes 48..54):")
for w in RES:
    other = bytes(a ^ b for a, b in zip(w.encode(), x01[48:55])).decode("latin1")
    if other in RES:
        print(f"       entry0 result={w!r}  <->  entry1 result={other!r}  (consistent)")
print("     Ciphertext-only gives the PAIR {success, failure} but not which is which: an")
print("     anchor (one known plaintext) is needed -> stage B.")

# ------------------------------------------------------------------ Stage B
print("\n[B] Known-plaintext: the attacker is bob00. He knows what his own failed login")
print("    at 12:04 from 10.0.0.9 looks like in the log (format is public):")
own_user, own_ip = "bob00", "10.0.0.9"
P1 = f"2025-03-01 12:04 user={own_user} action=login result=failure from={own_ip}".encode()
print("    P1 =", P1.decode())
assert len(P1) == len(logs[1])
KS = xor(logs[1], P1)                      # keystream bytes 0..68, for EVERY entry
print("    keystream recovered:", len(KS), "bytes  (KS = C1 xor P1)")

entry0 = xor(logs[0], KS)
entry2 = xor(logs[2], KS)                  # only the first 69 bytes are covered by KS
print("\n    Decrypted entry 0 (sanity check, must look like a log line):")
print("     ", entry0.decode("latin1"))
print("\n    Decrypted TARGET entry 2 (first %d of %d bytes):" % (len(KS), len(logs[2])))
print("     ", entry2.decode("latin1") + "?")
assert b"user=admin action=export" in entry2

# --------------------------------------------------------------- Summary
print("\n=== RECOVERED ARTIFACT ===")
print("TARGET log entry:", entry2.decode() + "?")
print("  user=admin action=export result=success from=10.0.0.   <- 69/70 bytes recovered")
print("  The last byte exists only in the longest entry (the TARGET), so no other entry")
print("  covers that keystream byte; it is not recoverable by this attack (it is the IP digit).")

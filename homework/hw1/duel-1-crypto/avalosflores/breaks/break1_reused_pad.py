#!/usr/bin/env python3
"""Break #1 -- reused_pad : "one-time" pad used for every message (n-time pad).

Assumption broken: "a pad is unbreakable" -- but only if each pad byte is used ONCE.
Here the same 200-byte pad encrypts all four messages, so  C_i xor C_j = P_i xor P_j
and the key cancels out.

Method (crib-dragging, ciphertext only -- we never touch _PAD_KEY or the plaintexts
in the source file):
  Round 0  If two ciphertexts start with the same bytes, their plaintexts do too.
  Round 1+ XOR a guessed word (a "crib") into one message at some offset. That yields
           the pad bytes at those offsets. Decrypt the OTHER messages with those pad
           bytes: if they turn into English, the crib was right. Extend and repeat.
  Check    The TARGET (msg3) is never used as a crib source after round 0: its text
           comes out by decrypting with a pad recovered from msg0, msg1 and msg2.

Run:  python3 break1_reused_pad.py
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from duel1_targets import reused_pad_ciphertexts

cts = [bytes.fromhex(v) for v in reused_pad_ciphertexts().values()]   # msg0..msg3
TARGET = 3
L = max(map(len, cts))
key = {}        # pad position -> recovered pad byte
source = {}     # pad position -> set of messages used to derive it


def crib(msg, off, text):
    """Assume `text` sits at offset `off` of message `msg`; derive pad bytes."""
    for j, ch in enumerate(text.encode()):
        pos = off + j
        k = cts[msg][pos] ^ ch
        if key.get(pos, k) != k:      # two guesses disagree -> one crib is wrong
            raise ValueError(f"crib conflict at pad byte {pos}: msg{msg} {text!r}")
        key[pos] = k
        source.setdefault(pos, set()).add(msg)


def view(msg, only_from=None):
    """Decrypt msg with the known pad bytes ('_' where the pad byte is unknown)."""
    out = ""
    for i, c in enumerate(cts[msg]):
        ok = i in key and (only_from is None or (source[i] - {only_from}))
        out += chr(c ^ key[i]) if ok else "_"
    return out


def show(title):
    print(f"\n--- {title}  (known pad bytes: {len(key)}/{L}) ---")
    for m in range(len(cts)):
        print(f"  msg{m}{' (TARGET)' if m == TARGET else '         '}: {view(m)}")


# ---------------------------------------------------------------- Round 0
print("Ciphertext lengths:", [len(c) for c in cts])
same = [(i, j) for i in range(4) for j in range(i + 1, 4) if cts[i][:4] == cts[j][:4]]
print("Pairs whose first 4 ciphertext bytes are identical:", same,
      "-> their first 4 plaintext bytes are identical too (C_i xor C_j = 0)")
# Most likely identical English start of two sentences: 'the '
crib(1, 0, "the ")
crib(3, 0, "the ")
show("Round 0: crib 'the ' at offset 0 of msg1/msg3")
# msg0 now reads 'meet', msg2 reads 'reme' -> obvious words, so extend.

# ----------------------------------------------- Round 0b: statistical hint
# Every pad byte is shared by up to 4 messages, so for each column pick the pad byte
# that makes the column most English-like (letters + space). It is noisy -- it only
# serves to suggest which words to try as cribs in the next rounds.
import math
_freq = dict(zip("etaoinshrdlcumwfgypbvkjxqz",
                 [12.7, 9.1, 8.2, 7.5, 7.0, 6.7, 6.3, 6.1, 6.0, 4.3, 4.0, 2.8, 2.8,
                  2.4, 2.4, 2.2, 2.0, 2.0, 1.9, 1.5, 1.0, 0.8, 0.15, 0.15, 0.1, 0.07]))
_freq[" "] = 18.0
_sc = lambda b: math.log(_freq[chr(b)]) if chr(b) in _freq else -10.0
guess_pad = [max(range(256), key=lambda k: sum(_sc(c[col] ^ k) for c in cts if col < len(c)))
             for col in range(L)]
print("\n--- Round 0b: noisy frequency-vote decryption (hints only) ---")
for m, c in enumerate(cts):
    print(f"  msg{m}: {bytes(a ^ b for a, b in zip(c, guess_pad)).decode('latin1')}")
# Reading it: 'tee qyarterle remenue numbees' ~ 'the quarterly revenue numbers',
# 'rhmemner to notaoe the encrnptlnn' ~ 'remember to rotate the encryption',
# 'tee lmunch aithoiization cose' ~ 'the launch authorization code', 'mhet ae at tte
# ntrth gate' ~ 'meet me at the north gate'.  Those are the cribs used below.

# ---------------------------------------------------------------- Round 1
crib(0, 0, "meet me at the north gate")        # read off msg0 'meet...'
crib(2, 0, "remember to rotate the encr")      # read off msg2 'reme...'
show("Round 1: extend msg0 / msg2 starts")
# msg1 now reads 'the quarterly revenue ...' (it was one of the 'the ' cribs).

# ---------------------------------------------------------------- Round 2
crib(1, 0, "the quarterly revenue numbers must not leave this room under any case")
show("Round 2: extend msg1 (and the pad with it)")

# ---------------------------------------------------------------- Round 3
crib(2, 0, "remember to rotate the encryption keys every ninety days without fail")
crib(0, 0, "meet me at the north gate at nine tonight and bring the documents")
show("Round 3: finish msg0 / msg2")

# ------------------------------------------------------------ Confirmation
print("\n=== CONFIRMATION ===")
target_from_others = view(TARGET, only_from=TARGET)
print("TARGET decrypted ONLY with pad bytes recovered from msg0, msg1, msg2:")
print("  ", repr(target_from_others))
unknown = [i for i, ch in enumerate(target_from_others) if ch == "_"]
print(f"   undetermined positions (only the target covers them): {unknown}")

cross = sum(1 for p in key if len(source[p]) >= 2)
print(f"Pad bytes confirmed by >= 2 independent messages: {cross}/{len(key)}")
print("No crib conflicts were raised (otherwise this script would have crashed).")

# The one byte only the target covers is a context guess ('...courier ok').
last = unknown[-1]
guess = "k"
recovered = target_from_others[:last] + guess + target_from_others[last + 1:]
print("\nRECOVERED TARGET PLAINTEXT:", repr(recovered))
print(f"(character {last} = {guess!r} is an inference from context, not cross-checked)")
assert recovered.startswith("the launch authorization code")

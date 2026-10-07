#!/usr/bin/env python3
"""Break #6 -- timing_compare : early-exit secret comparison.

Assumption broken: "the comparison result is the only thing the function reveals".
The loop returns at the first wrong byte, so the running time grows with the length of the
correct PREFIX of the guess. That turns a 2^32 search into 4 x 256 guesses: recover the
secret one byte at a time, keeping the candidate that takes longest.

Method (per position): try all 256 values for the next byte, N rounds each, interleaved
(round-robin over the 256 candidates so slow drifts of the machine hit all candidates
equally), then keep the candidate with the highest score. Two scores are compared:
  * median of the N timings  (robust to a few outliers)
  * minimum of the N timings (scheduler noise only ADDS time, so a wrong candidate looks
    slow only if ALL its N samples were hit; the correct one is slow every time)
Confirmation = the function itself returns True for the recovered secret.

The attack is statistical, so we report RELIABILITY: the attack is repeated RUNS times for
several values of N and we count how often the full 4-byte secret comes out right.

Run:  python3 break6_timing.py            (about 1-2 minutes)
      python3 break6_timing.py --runs 5   (quicker)
"""
import os, sys, time, gc, statistics
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from duel1_targets import timing_compare

RUNS = int(sys.argv[sys.argv.index("--runs") + 1]) if "--runs" in sys.argv else 20
LEN = 4                                  # secret length (the function reveals it: wrong length -> False)
pc = time.perf_counter_ns
gc.disable()                             # no garbage-collector pauses inside timed calls


def attack(n_rounds, stat=statistics.median):
    """Recover the secret using n_rounds timings per candidate byte. Returns (secret, calls)."""
    known, calls = bytearray(), 0
    for pos in range(LEN):
        samples = [[] for _ in range(256)]
        for _ in range(n_rounds):
            for b in range(256):
                guess = bytes(known) + bytes([b]) + bytes(LEN - pos - 1)
                t0 = pc()
                timing_compare(guess)
                samples[b].append(pc() - t0)
                calls += 1
        known.append(max(range(256), key=lambda b: stat(samples[b])))
    return bytes(known), calls


# --------------------------------------------------------------- 1. the signal
print("[1] The side channel: median time (microseconds, 301 calls each) vs. number of correct leading bytes")
# quick first recovery (min score, 10 rounds), only used to build the signal table below;
# the function's own True/False answer tells us if it worked, so retry if it did not
for _attempt in range(5):
    secret, _ = attack(10, min)
    if timing_compare(secret):
        break
assert timing_compare(secret), "first recovery failed - machine too noisy, rerun"
for k in range(LEN):
    g = secret[:k] + bytes([(secret[k] + 1) % 256]) + bytes(LEN - k - 1)   # k correct bytes, then a wrong one
    ts = []
    for _ in range(301):
        t0 = pc(); timing_compare(g); ts.append(pc() - t0)
    print(f"      {k} correct leading bytes -> {statistics.median(ts) / 1000:8.1f} us")
print("      (each extra correct byte adds ~4000 loop iterations; a real memcmp adds ~1 ns, see honesty.md)")

# ---------------------------------------------------------------- 2. reliability
print(f"\n[2] Reliability: full 4-byte recovery repeated {RUNS}x for each N (rounds per candidate)")
print("      N   timed calls/attack |  median score  |  minimum score")
table = {}
for n in (1, 2, 3, 5, 8):
    row = {}
    for name, stat in (("median", statistics.median), ("min", min)):
        ok = 0
        for _ in range(RUNS):
            s, calls = attack(n, stat)
            ok += timing_compare(s)      # oracle: True only for the exact secret
        row[name] = ok
    table[n] = (row, calls)
    print(f"     {n:2d}   {calls:12d}      | {row['median']:3d}/{RUNS} ({100 * row['median'] / RUNS:5.1f} %) | "
          f"{row['min']:3d}/{RUNS} ({100 * row['min'] / RUNS:5.1f} %)")

# smallest N that never failed with the min score, doubled as a safety margin
perfect = [n for n, (row, _) in table.items() if row["min"] == RUNS]
N_FINAL = 2 * min(perfect) if perfect else 8
# ---------------------------------------------------------------- 3. final run
print(f"\n[3] Final recovery with the minimum score and N = {N_FINAL} rounds/candidate "
      f"(2 x the smallest N with {RUNS}/{RUNS} successes)")
t0 = time.time()
secret, calls = attack(N_FINAL, min)
dt = time.time() - t0
print(f"      recovered secret : {secret.hex()}  ({list(secret)})")
print(f"      oracle check     : timing_compare(secret) -> {timing_compare(secret)}")
print(f"      timed calls used : {calls}  (= {LEN} positions x 256 candidates x {N_FINAL} rounds), {dt:.1f} s")
print(f"      brute force would need up to 2^32 = {2**32:,} calls; this needed {calls:,}.")
assert timing_compare(secret)

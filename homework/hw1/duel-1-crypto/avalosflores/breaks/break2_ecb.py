#!/usr/bin/env python3
"""Break #2 -- ecb_store : customer records encrypted block-by-block (ECB).

Assumption broken: "if I can't decrypt it, it leaks nothing" -- but ECB is a
deterministic map per block, so EQUAL plaintext blocks give EQUAL ciphertext blocks
and the pattern of equalities is visible without the key.

Method: split every ciphertext into 4-byte blocks (8 hex chars), find which blocks
repeat across records, and read the structure. We never use the key.

Run:  python3 break2_ecb.py
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from duel1_targets import ecb_store_records

BS_HEX = 8                                   # 4-byte block = 8 hex chars
NAMES = ["rec0", "rec1", "rec2", "rec3"]
recs = ecb_store_records()
blocks = [[r[i:i + BS_HEX] for i in range(0, len(r), BS_HEX)] for r in recs]

print("Ciphertext blocks per record (format is 'name:role:dept', 4-byte blocks):\n")
for n, b in zip(NAMES, blocks):
    print(f"  {n}: " + " | ".join(b))

print("\nWhich blocks are identical between two records?  (blocks are numbered 0..3)")
equal = {}
for i in range(4):
    for j in range(i + 1, 4):
        eq = [k for k in range(4) if blocks[i][k] == blocks[j][k]]
        equal[(i, j)] = eq
        print(f"  {NAMES[i]} vs {NAMES[j]}: equal blocks {eq}")

# ---- what we can conclude, purely from equalities --------------------------------
print("\nINFERENCES (no key used):")
# Block 0 is the 4-byte name field: all different -> four different names.
assert len({b[0] for b in blocks}) == 4
print("  * Block 0 (the name) differs everywhere -> four distinct employees.")
# Blocks 1..3 carry role + dept (they straddle the ':' separators).
assert equal[(0, 2)] == [1, 2, 3]
print("  * rec0 and rec2 share blocks 1,2,3 -> SAME role AND SAME department.")
assert equal[(1, 3)] == [1]
print("  * rec1 and rec3 share only block 1  -> SAME role, DIFFERENT department.")
assert not set(equal[(0, 1)]) & {1}
print("  * rec0/rec2 vs rec1/rec3 share no role block -> the two groups have DIFFERENT roles.")

print("\nINFERRING A FIELD with one anchor:")
print("  Suppose the attacker knows ONE record's role from outside the system, e.g. the")
print("  company page says 'alice' is an administrator (rec0 -> 'admn').")
print("  Then rec2 has the identical role block, so rec2 is ALSO 'admn'  (identity: block 1 equal),")
print("  and the other group (rec1, rec3) is NOT admin.")
print("  => Role of rec2 recovered: 'admn'.  Role of rec1 and rec3: the other group.")

# Block-count histogram -- the classic ECB tell
from collections import Counter
cnt = Counter(b for row in blocks for b in row)
rep = {b: c for b, c in cnt.items() if c > 1}
print(f"\nRepeated ciphertext blocks across the table: {len(rep)} distinct values, "
      f"{sum(rep.values())} of {sum(cnt.values())} blocks involved.")
for b, c in sorted(rep.items(), key=lambda t: -t[1]):
    where = [(NAMES[i], k) for i in range(4) for k in range(4) if blocks[i][k] == b]
    print(f"  {b} x{c}: {where}")

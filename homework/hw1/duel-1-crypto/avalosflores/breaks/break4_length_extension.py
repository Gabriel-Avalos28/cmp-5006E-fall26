#!/usr/bin/env python3
"""Break #4 -- token_mac : session token tag = H(secret || data) with a Merkle-Damgard hash.

Assumption broken: "an attacker who doesn't know the secret can't produce a valid tag".
For a Merkle-Damgard hash the tag IS the internal state after absorbing secret||data, so
anyone can resume hashing from that state and append more data -- a valid tag for
data || padding || extension, without ever learning the secret.

Method:
  1. Take the issued token (data="user=alice&role=user", tag).
  2. Use the tag as the hash's starting state (iv=tag) and hash only the extension
     '&role=admin'.
  3. The message the server must see is  data || glue-padding || extension.
     The glue padding depends on len(secret) -- we are not trusting the "9" in the
     docstring: we try every length 1..32 and let verify_token be the oracle.

Run:  python3 break4_length_extension.py
"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from duel1_targets import issue_token, verify_token, _md_hash   # _md_hash = public hash fn


tok = issue_token()                         # attacker legitimately receives this (user=alice, role=user)
data, tag = tok["data"].encode(), tok["tag"]
print("Issued token :", tok)
assert not verify_token(data + b"&role=admin", tag), "naive append must NOT validate"
print("Naive append (old tag + '&role=admin') validates? ->", verify_token(data + b"&role=admin", tag))

EXT = b"&role=admin"
hits = []
for seclen in range(1, 33):
    # The hash zero-pads secret||data to a multiple of 4 bytes before the next block
    # ("simplified MD padding"), so those zero bytes become part of the forged message.
    glue = bytes((-(seclen + len(data))) % 4)
    forged_msg = data + glue + EXT
    forged_tag = _md_hash(EXT, iv=tag)       # resume from the old tag as the state
    if verify_token(forged_msg, forged_tag):  # oracle = the server's own check
        hits.append((seclen, forged_msg, forged_tag))

print(f"\nSecret lengths tried: 1..32   ->  accepted by the server for: {[h[0] for h in hits]}")
assert hits, "forgery failed"
distinct = {(m, t) for _, m, t in hits}
print(f"  Distinct forged (data, tag) pairs among the accepted guesses: {len(distinct)}")
print("  -> all accepted lengths are congruent mod 4: this toy hash's zero-padding depends only on")
print("     (len(secret)+len(data)) mod 4, so every such guess yields the SAME forgery. We only need")
print("     len(secret) mod 4 (=1 here; the docstring says 9). Real SHA-256 encodes the exact bit")
print("     length in its padding, so there we'd need the exact length (<= ~64 guesses, same oracle).")
seclen, forged_msg, forged_tag = hits[0]

print("\n=== FORGED TOKEN (secret never used) ===")
print("  data :", forged_msg)
print("  tag  :", forged_tag)
print("  verify_token(data, tag) ->", verify_token(forged_msg, forged_tag))
print("  The forged data still starts with 'user=alice&role=user' and ends with '&role=admin';")
print("  a parser that keeps the LAST role= value (typical for query strings) sees role=admin.")
